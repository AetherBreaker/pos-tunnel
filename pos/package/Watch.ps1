<#
.SYNOPSIS
Session lifecycle, every 2 minutes and at startup: keeps the idle state between sessions, tears down on
expiry, and during a session brings sshd, support and PosTunnel-Link back after a restart or a drop.
.NOTES
Design: docs/design.md, section 7.2. Runs as SYSTEM from PosTunnel-Watch.
#>

. "$PSScriptRoot\Common.ps1"

# Short wait: the next run is 2 minutes away, and a holder (Open, Install) may hold it for minutes.
if (-not (Enter-Lock 60)) { Write-Result 'SKIPPED' 'lock' 'held by another PosTunnel script'; exit 0 }
$step = 'session'
try {
    if (-not (Test-Path -LiteralPath $SessionFile)) { Stop-Session; exit 0 }

    # Each deadline from this machine's own clock (section 5); unreadable state counts as expired.
    $expired = $null
    try {
        $session = Get-Content -LiteralPath $SessionFile -Raw | ConvertFrom-Json
        $now = [DateTime]::UtcNow
        $leaseAge = ($now - (Get-Item -LiteralPath $LeaseFile).LastWriteTimeUtc).TotalSeconds
        $started = [DateTimeOffset]::FromUnixTimeSeconds([long]$session.started).UtcDateTime
        if ($leaseAge -gt [int]$session.idle_seconds) { $expired = 'idle timeout' }
        elseif ($now -gt $started.AddHours($MaxSessionHours)) { $expired = "$MaxSessionHours-hour maximum" }
    } catch { $expired = "unreadable session state ($($_.Exception.Message))" }
    if ($expired) {
        Write-Result 'CHANGED' $step "ended: $expired"
        Stop-Session
        exit 0
    }

    # sshd is Manual, so after a restart it is down until this starts it. Not listening (a slow boot) keeps
    # the session for the next run to retry; listening beyond loopback ends it.
    $step = 'sshd'
    $problem = Start-Sshd
    if ($problem) {
        Write-Result 'FAILED' $step "$problem; tearing down"
        Stop-Session
        exit 1
    }
    $step = 'support account'
    if (-not (Get-LocalUser -Name $SupportUser).Enabled) { Enable-LocalUser -Name $SupportUser; Write-Result 'CHANGED' $step 'enabled' }
    $step = 'tunnel'
    $link = Get-ScheduledTask -TaskName $LinkTask
    if ($link.State -ne 'Running') {
        if ($link.State -eq 'Disabled') { $null = Enable-ScheduledTask -TaskName $LinkTask }
        Start-ScheduledTask -TaskName $LinkTask
        Write-Result 'CHANGED' $step 'restarted'
    }
} catch {
    Write-Result 'FAILED' $step $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
