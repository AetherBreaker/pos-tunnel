<#
.SYNOPSIS
Dot-sourced by every package script: paths, the result log, the machine-wide lock, ACLs, sshd start and
the session teardown (Stop-Session, the only teardown implementation).
.NOTES
Design: docs/design.md, section 7. Runs as SYSTEM. ASCII only: Windows PowerShell 5.1 reads a BOM-less
script as ANSI.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root = 'C:\ProgramData\PosTunnel'
$SshDir = 'C:\ProgramData\ssh'
$OpenSsh = 'C:\Program Files\OpenSSH'
$SessionFile = "$Root\session.json"
$LeaseFile = "$Root\lease"
$RelayKey = "$Root\relay_key"
$RelayFile = "$Root\relay.json"
$KnownHosts = "$Root\known_hosts"
$AuthorizedKeys = "$SshDir\administrators_authorized_keys"
$SupportUser = 'support'
$LinkTask = 'PosTunnel-Link'
$WatchTask = 'PosTunnel-Watch'
$MaxSessionHours = 72
$SystemSid = 'S-1-5-18'
$AdminsSid = 'S-1-5-32-544'
$script:failed = 0

# One line per step, "<STATUS>`t<step>`t<detail>": OK (already right), CHANGED, SKIPPED, DEFERRED, FAILED.
function Write-Result([string]$Status, [string]$Step, [string]$Detail = '') {
    if ($Status -eq 'FAILED') { $script:failed++ }
    Write-Output ("$Status`t$Step" + $(if ($Detail) { "`t$Detail" } else { '' }))
}

# Every package script and Install-PosTunnel serialize on an exclusive open of $Root\lock: Watch runs every
# 2 minutes and would otherwise tear down a session Open is halfway through building. Not a named mutex:
# any user can create and hold one, which would stop Watch ever ending a session; nobody but SYSTEM can
# open this folder. Windows closes the handle with its process, so a holder that died frees it, and every
# script converges from whatever state it finds. A script run in-process by the holder (Install -> Setup,
# Install -> Close) shares its handle through $global:PosTunnelLock and leaves releasing it to the holder.
function Enter-Lock([int]$TimeoutSeconds) {
    if ($global:PosTunnelLock) { return $true }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $global:PosTunnelLock = [IO.File]::Open("$Root\lock", 'OpenOrCreate', 'ReadWrite', 'None')
            $script:OwnsLock = $true
            return $true
        } catch [IO.IOException] { if ((Get-Date) -gt $deadline) { return $false } }
        Start-Sleep -Milliseconds 500
    }
}

function Exit-Lock {
    if ($script:OwnsLock) { $global:PosTunnelLock.Dispose(); $global:PosTunnelLock = $null; $script:OwnsLock = $false }
}

# A protected (non-inheriting) ACL granting FullControl to each SID in $FullControl and read to $ReadOnly.
function New-Acl([string[]]$FullControl, [string[]]$ReadOnly = @(), [switch]$Directory) {
    if ($Directory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        $inherit = [Security.AccessControl.InheritanceFlags]'None'
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($FullControl[0])))
    foreach ($sid in $FullControl) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inherit, 'None', 'Allow')))
    }
    foreach ($sid in $ReadOnly) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'ReadAndExecute', $inherit, 'None', 'Allow')))
    }
    return $acl
}

# True when $Path's ACL is protected, owned by the first SID and grants exactly what New-Acl would.
function Test-Acl([string]$Path, [string[]]$FullControl, [string[]]$ReadOnly = @()) {
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { return $false }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $FullControl[0]) { return $false }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $FullControl.Count + $ReadOnly.Count) { return $false }
    foreach ($rule in $rules) {
        $want = if ($FullControl -contains $rule.IdentityReference.Value) { 'FullControl' }
            elseif ($ReadOnly -contains $rule.IdentityReference.Value) { 'ReadAndExecute, Synchronize' }
            else { return $false }
        if ($rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights.ToString() -ne $want) { return $false }
    }
    return $true
}

# Writes ASCII $Content to $Path unless it already holds exactly that (and, given $FullControl, exactly
# New-Acl's ACL); returns whether it changed. Recreates the file rather than overwriting it, so an ACL
# someone else gave it doesn't survive, and creates it with its ACL, so it is never briefly open.
function Set-FileContent([string]$Path, [string]$Content, [string[]]$FullControl = @(), [string[]]$ReadOnly = @()) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($Content)
    if (Test-Path -LiteralPath $Path) {
        $same = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -eq [Convert]::ToBase64String($bytes)
        if ($same -and (-not $FullControl -or (Test-Acl $Path $FullControl $ReadOnly))) { return $false }
        Remove-Item -LiteralPath $Path -Force
    }
    $stream = if ($FullControl) { [IO.File]::Create($Path, 4096, [IO.FileOptions]::None, (New-Acl $FullControl $ReadOnly)) }
        else { [IO.File]::Create($Path) }
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Close() }
    return $true
}

# Starts sshd and checks every socket it listens on is loopback: the Windows firewall is off, so this is
# the only thing keeping sshd off the store LAN. Returns $null when it is, else where it listens. Throws
# when sshd isn't listening (a slow boot, say), after stopping it so it can't bind later unchecked: the
# caller decides whether that ends the session, where exposure always does.
function Start-Sshd {
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
    $sshdPid = (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $sshdPid -ErrorAction SilentlyContinue)
        if ($listeners) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    # sshd binds its addresses one after another, so a first look can catch only the loopback one bound.
    if ($listeners) {
        Start-Sleep -Seconds 1
        $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $sshdPid -ErrorAction SilentlyContinue)
    }
    if (-not $listeners) {
        Stop-Service sshd -Force
        throw 'not listening; stopped it'
    }
    $exposed = @($listeners | Where-Object { $_.LocalAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '::1' })
    if ($exposed) { return 'listening on ' + (($exposed | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', ') }
    return $null
}

# Converges to the idle state and ends the session if there is one: Watch's idle check and every
# teardown (expiry, Close, Open replacing a stale session, Install -Force). Tunnel first, so nothing new
# reaches sshd while it goes down; the session files last, so a failure midway leaves session.json behind
# and the next Watch run tears down again.
function Stop-Session {
    $link = Get-ScheduledTask -TaskName $LinkTask -ErrorAction SilentlyContinue
    if ($link -and $link.State -eq 'Running') { Stop-ScheduledTask -TaskName $LinkTask; Write-Result 'CHANGED' 'tunnel' 'stopped' }

    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if ($sshd) {
        if ($sshd.StartType -ne 'Manual') { Set-Service sshd -StartupType Manual; Write-Result 'CHANGED' 'sshd start type' 'Manual' }
        if ($sshd.Status -ne 'Stopped') { Stop-Service sshd -Force; Write-Result 'CHANGED' 'sshd' 'stopped' }
    }
    # Live connections outlive the service; only this install's binaries, never another OpenSSH's.
    $sessions = @(Get-Process sshd, sshd-session -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$OpenSsh\*" })
    if ($sessions) { $sessions | Stop-Process -Force; Write-Result 'CHANGED' 'ssh connections' "ended $($sessions.Count)" }

    # sshd ignores this file unless only SYSTEM and Administrators can reach it.
    if ((Test-Path -LiteralPath $SshDir) -and (Set-FileContent $AuthorizedKeys '' $SystemSid, $AdminsSid)) {
        Write-Result 'CHANGED' 'session key' 'removed'
    }

    $support = Get-LocalUser -Name $SupportUser -ErrorAction SilentlyContinue
    if ($support -and $support.Enabled) { Disable-LocalUser -Name $SupportUser; Write-Result 'CHANGED' 'support account' 'disabled' }
    $leftover = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -eq "$env:COMPUTERNAME\$SupportUser" })
    if ($leftover) { $leftover | Stop-Process -Force; Write-Result 'CHANGED' 'support processes' "ended $($leftover.Count)" }

    foreach ($file in $SessionFile, $LeaseFile) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force; Write-Result 'CHANGED' 'session state' "deleted $(Split-Path $file -Leaf)" }
    }
    if ($link -and $link.State -ne 'Disabled') { $null = Disable-ScheduledTask -TaskName $LinkTask; Write-Result 'CHANGED' 'tunnel task' 'disabled' }
}

# Writes the POS's public keys and package version to its device fields, only where they differ.
function Publish-DeviceFields([string]$Version) {
    $values = [ordered]@{
        posTunnelRelayKey = ((Get-Content -LiteralPath "$RelayKey.pub" -Raw).Trim() -split ' ')[0..1] -join ' '
        posTunnelHostKey  = ((Get-Content -LiteralPath "$SshDir\ssh_host_ed25519_key.pub" -Raw).Trim() -split ' ')[0..1] -join ' '
        posTunnelVersion  = $Version
    }
    foreach ($name in $values.Keys) {
        if ((Ninja-Property-Get $name) -eq $values[$name]) { Write-Result 'OK' "field $name"; continue }
        Ninja-Property-Set $name $values[$name]
        Write-Result 'CHANGED' "field $name" $values[$name]
    }
}
