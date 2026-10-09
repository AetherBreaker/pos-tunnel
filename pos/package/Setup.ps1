<#
.SYNOPSIS
Device setup: sshd_config, Win32-OpenSSH, the disabled support account, the relay key pair, the relay's
address and public key, the scheduled tasks, the device fields. Every step checks before it changes.
.NOTES
Design: docs/design.md, section 7.1. Run in-process by Install-PosTunnel, as SYSTEM, only while no
session is open. Exit 0 = set up, 1 = failed, 2 = deferred (a restart must come first).
#>
param(
    [Parameter(Mandatory)][string]$RelayHost,
    [Parameter(Mandatory)][int]$RelayPort,
    [Parameter(Mandatory)][string]$RelayServerKey
)

. "$PSScriptRoot\Common.ps1"

# Raising the pin is a package release; NinjaOne's WinGet deployment patches it in between (section 7.1).
$MsiUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi'
$MsiSha256 = 'DDEC9C53864280759CF9F74791CEFD387100E3946AA849A1C138A4ED1B96B7D9'
$AuthUsersSid = 'S-1-5-11'
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Version = Split-Path $PSScriptRoot -Leaf

# administrators_authorized_keys applies to every administrator, so AllowUsers keeps the session key from
# logging in as the till account or BackupAdmin; key auth only, since BackupAdmin's password is the same
# on every POS.
$SshdConfig = @'
# Written by PosTunnel Setup on every run; edits are replaced. docs/design.md, section 7.1.
ListenAddress 127.0.0.1
AllowUsers support
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
'@ -replace "`r?`n", "`r`n"

$step = 'parameters'
if ($RelayHost -notmatch '^[A-Za-z0-9.-]+$' -or $RelayPort -lt 1 -or $RelayPort -gt 65535 -or
    $RelayServerKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
    Write-Result 'FAILED' $step 'relay host, port or public key is malformed'
    exit 1
}
if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
try {
    # 1. Before OpenSSH is installed, so the MSI's first start of sshd never sees its default config (all
    # interfaces, password login): sshd writes that default only when no file exists.
    $step = 'sshd_config'
    if (-not (Test-Path -LiteralPath $SshDir)) {
        $null = [IO.Directory]::CreateDirectory($SshDir, (New-Acl $SystemSid, $AdminsSid $AuthUsersSid -Directory))
        Write-Result 'CHANGED' 'ssh folder' 'created'
    } elseif (-not (Test-Acl $SshDir ($SystemSid, $AdminsSid) $AuthUsersSid)) {
        Set-Acl -LiteralPath $SshDir -AclObject (New-Acl $SystemSid, $AdminsSid $AuthUsersSid -Directory)
        Write-Result 'CHANGED' 'ssh folder' 'ACL reset'
    } else { Write-Result 'OK' 'ssh folder' }
    if (Set-FileContent "$SshDir\sshd_config" $SshdConfig ($SystemSid, $AdminsSid) $AuthUsersSid) { Write-Result 'CHANGED' $step }
    else { Write-Result 'OK' $step }

    # 2. Only the first install; WinGet updates it afterwards. Windows' own OpenSSH Server registers the
    # same service name, so it goes first.
    $step = 'OpenSSH'
    if (Test-Path -LiteralPath "$OpenSsh\sshd.exe") { Write-Result 'OK' $step }
    else {
        $builtin = Get-CimInstance Win32_Service -Filter "Name='sshd'" | Where-Object { $_.PathName -like '*\System32\OpenSSH\*' }
        if ($builtin) {
            $step = 'built-in OpenSSH Server'
            Stop-Service sshd -Force
            $removal = Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
            Write-Result 'CHANGED' $step 'removed'
            if ($removal.RestartNeeded -or (Get-Service sshd -ErrorAction SilentlyContinue)) {
                # The POS restarts at 3 AM and Install-PosTunnel runs at 4 AM, so the next run finishes.
                Write-Result 'DEFERRED' $step 'restart pending; the next run installs OpenSSH'
                exit 2
            }
        }
        $step = 'OpenSSH'
        $msi = "$Root\$(Split-Path $MsiUrl -Leaf)"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
        if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne $MsiSha256) {
            Remove-Item -LiteralPath $msi -Force
            throw "$(Split-Path $msi -Leaf) does not match its pinned SHA256"
        }
        $msiexec = Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$Root\openssh-msi.log`"" -Wait -PassThru
        Remove-Item -LiteralPath $msi -Force
        if ($msiexec.ExitCode -notin 0, 3010) { throw "msiexec exited $($msiexec.ExitCode); see $Root\openssh-msi.log" }
        Write-Result 'CHANGED' $step 'installed'
    }

    # 3. The MSI's first start of sshd generated the server key pair; step 8 makes the service Manual
    # and stops it.
    $step = 'sshd service'
    if (-not (Test-Path -LiteralPath "$SshDir\ssh_host_ed25519_key.pub")) {
        & "$OpenSsh\ssh-keygen.exe" -A
        if ($LASTEXITCODE) { throw "ssh-keygen -A exited $LASTEXITCODE" }
        Write-Result 'CHANGED' $step 'server key pair generated'
    }
    if ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue).DefaultShell -ne $PowerShellExe) {
        $null = New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force
        $null = New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $PowerShellExe -PropertyType String -Force
        Write-Result 'CHANGED' $step 'DefaultShell'
    }
    Write-Result 'OK' $step

    # 4. Key auth uses an S4U logon, so the password is never needed; it is random and discarded.
    $step = 'support account'
    if (-not (Get-LocalUser -Name $SupportUser -ErrorAction SilentlyContinue)) {
        $bytes = New-Object byte[] 24
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force
        $null = New-LocalUser -Name $SupportUser -Password $password -Disabled -PasswordNeverExpires -AccountNeverExpires `
            -UserMayNotChangePassword -Description 'PosTunnel support; enabled only in a session'
        Write-Result 'CHANGED' $step 'created'
    }
    # Attempted rather than checked: Get-LocalGroupMember throws on a group holding an orphaned SID.
    try {
        Add-LocalGroupMember -SID $AdminsSid -Member $SupportUser
        Write-Result 'CHANGED' $step 'added to Administrators'
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {}
    Write-Result 'OK' $step

    # 5. Install-PosTunnel has already made $Root SYSTEM-only, which ssh requires of a private key file.
    $step = 'relay key pair'
    if (-not (Test-Path -LiteralPath $RelayKey)) {
        # Windows PowerShell 5.1 drops an empty native argument; '""' reaches ssh-keygen as one.
        & "$OpenSsh\ssh-keygen.exe" -q -t ed25519 -N '""' -C "pos-tunnel $env:COMPUTERNAME" -f $RelayKey
        if ($LASTEXITCODE) { throw "ssh-keygen exited $LASTEXITCODE" }
        Write-Result 'CHANGED' $step 'generated'
    } else { Write-Result 'OK' $step }

    # 6. Open builds the tunnel command from these.
    $step = 'relay'
    $relay = (@{ host = $RelayHost; port = $RelayPort } | ConvertTo-Json -Compress) + "`r`n"
    $pin = $(if ($RelayPort -eq 22) { $RelayHost } else { "[$RelayHost]:$RelayPort" }) + " $RelayServerKey`r`n"
    $changed = Set-FileContent $RelayFile $relay
    if (Set-FileContent $KnownHosts $pin) { $changed = $true }
    Write-Result $(if ($changed) { 'CHANGED' } else { 'OK' }) $step "$RelayHost`:$RelayPort"

    # 7. Watch is always enabled, so between sessions it also undoes an MSI upgrade's restart of sshd.
    $step = 'tasks'
    $system = New-ScheduledTaskPrincipal -UserId $SystemSid -LogonType ServiceAccount -RunLevel Highest
    $watchArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\Watch.ps1`""
    $watch = Get-ScheduledTask -TaskName $WatchTask -ErrorAction SilentlyContinue
    if (-not $watch -or $watch.Actions[0].Arguments -ne $watchArgs -or $watch.State -eq 'Disabled' -or @($watch.Triggers).Count -ne 2) {
        $triggers = @(
            (New-ScheduledTaskTrigger -AtStartup),
            (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2))
        )
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $null = Register-ScheduledTask -TaskName $WatchTask -Action (New-ScheduledTaskAction -Execute $PowerShellExe -Argument $watchArgs) `
            -Trigger $triggers -Settings $settings -Principal $system -Force
        Write-Result 'CHANGED' $step $WatchTask
    }
    # Open sets the action; no time limit, since a session lasts up to 72 hours.
    $link = Get-ScheduledTask -TaskName $LinkTask -ErrorAction SilentlyContinue
    if (-not $link -or $link.Settings.ExecutionTimeLimit -ne 'PT0S') {
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $null = Register-ScheduledTask -TaskName $LinkTask -Action (New-ScheduledTaskAction -Execute "$OpenSsh\ssh.exe" -Argument '-V') `
            -Settings $settings -Principal $system -Force
        Write-Result 'CHANGED' $step $LinkTask
    }
    Write-Result 'OK' $step

    # 8. Install-PosTunnel runs Setup only with no session open, so converge to Watch's idle state: sshd
    # Manual and stopped, administrators_authorized_keys empty, support and PosTunnel-Link disabled.
    $step = 'idle state'
    Stop-Session

    # 9.
    $step = 'fields'
    Publish-DeviceFields $Version
} catch {
    Write-Result 'FAILED' $step $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
