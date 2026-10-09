<#
.SYNOPSIS
Opens a session: installs the session key, enables support, starts sshd (loopback only), writes the
session state and lease, points PosTunnel-Link at the relay and starts it.
.NOTES
Design: docs/design.md, section 7.2. Run through Invoke-PosTunnel, as SYSTEM. -SessionKey is the bare
base64 of an ed25519 public key: no space, so NinjaOne's parameter string needs no quoting.
#>
param(
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][int]$IdleSeconds,
    [Parameter(Mandatory)][string]$SessionKey
)

. "$PSScriptRoot\Common.ps1"

$step = 'parameters'
# 20000 + a device ID of 1..45535 (section 4); idle at most 12 hours (section 5). The key pattern is the
# exact base64 of an ed25519 public key blob, so nothing else can reach administrators_authorized_keys.
if ($Port -lt 20001 -or $Port -gt 65535 -or $IdleSeconds -lt 1 -or $IdleSeconds -gt 43200 -or
    $SessionKey -cnotmatch '^AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$') {
    Write-Result 'FAILED' $step 'port, idle seconds or session key is malformed'
    exit 1
}
foreach ($required in $RelayKey, $RelayFile, $KnownHosts, "$OpenSsh\sshd.exe") {
    if (-not (Test-Path -LiteralPath $required)) { Write-Result 'FAILED' 'setup' "missing $required; run Install-PosTunnel"; exit 1 }
}
if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
try {
    # The relay refuses a second lease for this port, so a session already here is left over (a connect
    # that timed out, say) and safe to replace. Converging to idle either way also stops a PosTunnel-Link
    # left running without one, which would otherwise keep its old arguments through the Start below.
    $step = 'previous session'
    if (Test-Path -LiteralPath $SessionFile) { Write-Result 'CHANGED' $step 'replacing' }
    Stop-Session

    $step = 'session key'
    $null = Set-FileContent $AuthorizedKeys "ssh-ed25519 $SessionKey`r`n" $SystemSid, $AdminsSid
    Write-Result 'CHANGED' $step

    $step = 'support account'
    Enable-LocalUser -Name $SupportUser
    Write-Result 'CHANGED' $step 'enabled'

    $step = 'sshd'
    $problem = Start-Sshd
    if ($problem) { throw "$problem; tearing down" }
    Write-Result 'CHANGED' $step 'started, loopback only'

    $step = 'session state'
    $session = @{ port = $Port; idle_seconds = $IdleSeconds; started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
    $null = Set-FileContent $SessionFile (($session | ConvertTo-Json -Compress) + "`r`n")
    $null = Set-FileContent $LeaseFile ''
    (Get-Item -LiteralPath $LeaseFile).LastWriteTimeUtc = [DateTime]::UtcNow
    Write-Result 'CHANGED' $step

    # 127.0.0.1, not localhost, which Windows resolves to ::1 first, where sshd isn't listening.
    # IdentitiesOnly: the relay records every key a POS offers (section 6.5), so only relay_key goes.
    # -F none: no ssh_config can add options.
    $step = 'tunnel'
    $relay = Get-Content -LiteralPath $RelayFile -Raw | ConvertFrom-Json
    $sshArgs = "-N -F none -R $Port`:127.0.0.1:22 -p $($relay.port) -i $RelayKey -o ExitOnForwardFailure=yes " +
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o StrictHostKeyChecking=yes " +
        "-o UserKnownHostsFile=$KnownHosts -o IdentitiesOnly=yes tunnel@$($relay.host)"
    $null = Set-ScheduledTask -TaskName $LinkTask -Action (New-ScheduledTaskAction -Execute "$OpenSsh\ssh.exe" -Argument $sshArgs)
    $null = Enable-ScheduledTask -TaskName $LinkTask
    Start-ScheduledTask -TaskName $LinkTask
    Write-Result 'CHANGED' $step "port $Port via $($relay.host):$($relay.port)"
} catch {
    # Whatever got this far comes down: the operator was told Open failed, and a session.json left behind
    # would have Watch keep sshd and support up until the idle timeout.
    Write-Result 'FAILED' $step $_.Exception.Message
    try { Stop-Session } catch { Write-Result 'FAILED' 'teardown' $_.Exception.Message }
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
