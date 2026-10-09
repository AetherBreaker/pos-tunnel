<#
.SYNOPSIS
Dot-sourced by PosTunnel.Tests.ps1, which runs as SYSTEM (Invoke-Tests.ps1): runs the POS scripts
against a stub of NinjaOne's field cmdlets, a local release server and a stand-in relay.
.NOTES
Changes the machine (installs OpenSSH, creates accounts and tasks); refuses to run unless
POS_TUNNEL_DISPOSABLE=1, which only the CI job sets.
#>

$ErrorActionPreference = 'Stop'
if ($env:POS_TUNNEL_DISPOSABLE -ne '1') { throw 'these tests reconfigure the machine; set POS_TUNNEL_DISPOSABLE=1 only on a disposable one' }

$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
$Work = 'C:\pt-test'
$RelayDir = 'C:\pt-relay'
$Root = 'C:\ProgramData\PosTunnel'
$Keygen = "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe"
$ReleasePort = 8088
$RelayPort = 2222
$TunnelPort = 20001

# Protected, SYSTEM and Administrators only (plus $Reader read), which ssh demands of key files.
# Inheritance flags only on a folder: icacls silently drops an (OI)(CI) grant on a file.
function Protect-Path([string]$Path, [string]$Reader) {
    $flags = if (Test-Path $Path -PathType Container) { '(OI)(CI)' } else { '' }
    $grants = @('/grant:r', "*S-1-5-18:${flags}F", '/grant:r', "*S-1-5-32-544:${flags}F")
    if ($Reader) { $grants += '/grant:r', "${Reader}:R" }
    $null = icacls $Path /inheritance:r @grants
    if ($LASTEXITCODE) { throw "icacls $Path failed" }
}

# Returns the public key, "ssh-ed25519 <base64>".
function New-KeyPair([string]$Path) {
    Remove-Item $Path, "$Path.pub" -Force -ErrorAction SilentlyContinue
    & $Keygen -q -t ed25519 -N '""' -C test -f $Path
    if ($LASTEXITCODE) { throw "ssh-keygen $Path failed" }
    return ((Get-Content "$Path.pub" -Raw).Trim() -split ' ')[0..1] -join ' '
}

function Get-Field([string]$Name) { (Get-Content "$Work\fields.json" -Raw | ConvertFrom-Json).$Name }

function Set-Field([string]$Name, [string]$Value) {
    $fields = Get-Content "$Work\fields.json" -Raw | ConvertFrom-Json
    $fields | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    Set-Content "$Work\fields.json" ($fields | ConvertTo-Json) -Encoding ASCII
}

# Runs a script in its own powershell.exe -File, as NinjaOne and PosTunnel-Watch start them; returns its
# exit code and output lines. Continue: under Stop, 5.1 throws on the first stderr line 2>&1 captures.
function Invoke-Script([string]$Script, [string[]]$Arguments = @()) {
    $ErrorActionPreference = 'Continue'
    $lines = @(& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File $Script @Arguments 2>&1 | ForEach-Object { "$_" })
    $result = [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $lines; Text = $lines -join "`n" }
    Write-Host "--- $(Split-Path $Script -Leaf) $($Arguments -join ' ') -> $($result.ExitCode)"
    $lines | ForEach-Object { Write-Host "    $_" }
    return $result
}

# The library script as pasted, except that it downloads from the local release server.
function Invoke-Install([switch]$Force) {
    $script = "$Work\Install-PosTunnel.ps1"
    (Get-Content "$RepoRoot\pos\ninja\Install-PosTunnel.ps1" -Raw) -replace
        "\`$ReleaseUrl = '[^']+'", "`$ReleaseUrl = 'http://127.0.0.1:$ReleasePort'" | Set-Content $script -Encoding ASCII
    return Invoke-Script $script @(if ($Force) { '-Force' })
}

function Invoke-Action([string]$Action, [string[]]$Arguments = @()) {
    return Invoke-Script "$RepoRoot\pos\ninja\Invoke-PosTunnel.ps1" (@('-Action', $Action) + $Arguments)
}

function Invoke-Watch { return Invoke-Script "$Root\versions\$((Get-Content "$Root\current" -Raw).Trim())\Watch.ps1" }

# Builds a release of the working tree's pos\package as $Version, signed as sign_pos.py signs it.
# -SigningKey: another key. -ExtraEntry: an archive entry the manifest lacks. -Tamper: a file whose
# archive copy differs from its manifest hash.
function Publish-TestRelease([int]$Version, [string]$SigningKey = "$Work\signing_key", [switch]$ExtraEntry, [string]$Tamper) {
    $out = "$Work\release"
    $stage = "$Work\stage"
    Remove-Item $out, $stage -Recurse -Force -ErrorAction SilentlyContinue
    $null = New-Item -ItemType Directory $out, $stage
    Copy-Item "$RepoRoot\pos\package\*" $stage
    $files = [ordered]@{}
    foreach ($file in Get-ChildItem $stage -File | Sort-Object Name) {
        $files[$file.Name] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
    }
    [IO.File]::WriteAllText("$out\pos-manifest.json", (([ordered]@{ version = $Version; files = $files }) | ConvertTo-Json) + "`n")
    & $Keygen -q -Y sign -f $SigningKey -n pos-tunnel-release "$out\pos-manifest.json"
    if ($LASTEXITCODE) { throw 'signing failed' }
    if ($ExtraEntry) { Set-Content "$stage\Extra.ps1" 'Write-Output extra' }
    if ($Tamper) { Add-Content "$stage\$Tamper" '# tampered' }
    Compress-Archive -Path "$stage\*" -DestinationPath "$out\pos-package.zip"
}

# What tunnelctl open does for the real relay: one key line for the POS's port.
function Grant-RelayLease([string]$RelayPublicKey) {
    Set-Content "$RelayDir\authorized_keys" -Encoding ASCII `
        -Value "restrict,port-forwarding,permitlisten=`"localhost:$TunnelPort`" $RelayPublicKey"
}

function Wait-Port([int]$Port, [switch]$Closed, [int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ([bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) -eq [bool]$Closed) {
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 500
    }
    return $true
}

# An operator's ssh through the tunnel: the stand-in relay's forwarded port, the session key, and the
# POS's published SSH server public key pinned.
function Get-TunnelSshArgs([string]$Command) {
    Set-Content "$Work\pos_known_hosts" "[127.0.0.1]:$TunnelPort $(Get-Field posTunnelHostKey)" -Encoding ASCII
    return @('-F', 'none', '-p', "$TunnelPort", '-i', "$Work\session_key", '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$Work\pos_known_hosts", '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=15', 'support@127.0.0.1', $Command)
}

function Invoke-ThroughTunnel([string]$Command) {
    $ErrorActionPreference = 'Continue'
    $output = & "$env:ProgramFiles\OpenSSH\ssh.exe" @(Get-TunnelSshArgs $Command) 2>&1
    $result = [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output | Out-String).Trim() }
    Write-Host "--- ssh support@ $Command -> $($result.ExitCode)`n$($result.Output)"
    return $result
}

# A connection left running, to check a teardown ends it.
function Start-TunnelSsh([string]$Command) {
    $process = Start-Process "$env:ProgramFiles\OpenSSH\ssh.exe" -ArgumentList (Get-TunnelSshArgs $Command) -PassThru -NoNewWindow `
        -RedirectStandardOutput "$Work\live.out" -RedirectStandardError "$Work\live.err"
    Start-Sleep -Seconds 5
    if ($process.HasExited) { throw "the live connection exited at once: $(Get-Content "$Work\live.err" -Raw)" }
    return $process
}

function Open-TestSession([int]$IdleSeconds = 3600) {
    Grant-RelayLease (Get-Field posTunnelRelayKey)
    $sessionKey = ((Get-Content "$Work\session_key.pub" -Raw).Trim() -split ' ')[1]
    return Invoke-Action Open @('-Port', "$TunnelPort", '-IdleSeconds', "$IdleSeconds", '-SessionKey', $sessionKey)
}

# Lines of Stop-Session's idle state that a check can compare.
function Get-IdleState {
    return [pscustomobject]@{
        SshdStatus     = (Get-Service sshd).Status.ToString()
        SshdStartType  = (Get-Service sshd).StartType.ToString()
        SupportEnabled = (Get-LocalUser support).Enabled
        AuthorizedKeys = (Get-Item "$env:ProgramData\ssh\administrators_authorized_keys").Length
        LinkState      = (Get-ScheduledTask PosTunnel-Link).State.ToString()
        Session        = Test-Path "$Root\session.json"
    }
}

function Initialize-Harness {
    Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
    $null = New-Item -ItemType Directory $Work
    Protect-Path $Work
    Set-Content "$Work\fields.json" '{}' -Encoding ASCII

    # NinjaOne's agent gives the scripts it runs Ninja-Property-Get/-Set; this module stands in for them,
    # backed by fields.json, and autoloads from the machine-wide module path.
    $module = "$env:ProgramFiles\WindowsPowerShell\Modules\NinjaStub"
    $null = New-Item -ItemType Directory -Path $module -Force
    Set-Content -Path "$module\NinjaStub.psm1" -Encoding ASCII -Value @"
function Ninja-Property-Get([string]`$Name) { (Get-Content '$Work\fields.json' -Raw | ConvertFrom-Json).`$Name }
function Ninja-Property-Set([string]`$Name, [string]`$Value) {
    `$fields = Get-Content '$Work\fields.json' -Raw | ConvertFrom-Json
    `$fields | Add-Member -NotePropertyName `$Name -NotePropertyValue `$Value -Force
    Set-Content '$Work\fields.json' (`$fields | ConvertTo-Json) -Encoding ASCII
}
Export-ModuleMember -Function Ninja-Property-Get, Ninja-Property-Set
"@

    Set-Field posTunnelSigner (New-KeyPair "$Work\signing_key")
    $null = New-KeyPair "$Work\other_signing_key"
    $null = New-KeyPair "$Work\session_key"

    # The stand-in relay: a second sshd, from a copy of Windows' own OpenSSH taken before Setup removes it,
    # with user tunnel allowed only remote forwarding of the POS's port, as section 6.2 configures the
    # real one.
    $null = New-Item -ItemType Directory $RelayDir -Force
    Protect-Path $RelayDir
    Copy-Item "$env:SystemRoot\System32\OpenSSH" "$RelayDir\OpenSSH" -Recurse
    Set-Field posTunnelRelayServerKey (New-KeyPair "$RelayDir\ssh_host_ed25519_key")
    Set-Field posTunnelRelay "127.0.0.1:$RelayPort"
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $null = New-LocalUser -Name tunnel -Password (ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force) -PasswordNeverExpires
    Set-Content "$RelayDir\authorized_keys" '' -Encoding ASCII
    Protect-Path "$RelayDir\authorized_keys" 'tunnel'
    Set-Content "$RelayDir\sshd_config" -Encoding ASCII -Value @"
Port $RelayPort
ListenAddress 127.0.0.1
HostKey $($RelayDir -replace '\\', '/')/ssh_host_ed25519_key
AllowUsers tunnel
AuthorizedKeysFile $($RelayDir -replace '\\', '/')/authorized_keys
PasswordAuthentication no
AllowTcpForwarding remote
PermitTTY no
"@
    $null = New-Service -Name 'pt-relay' -BinaryPathName "`"$RelayDir\OpenSSH\sshd.exe`" -f `"$RelayDir\sshd_config`"" -StartupType Manual
    Start-Service 'pt-relay'

    # Serves $Work\release for Install-PosTunnel's downloads.
    $null = Start-Job -Name 'pt-release' -ArgumentList "$Work\release", $ReleasePort -ScriptBlock {
        param($dir, $port)
        $listener = New-Object Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()
        while ($true) {
            $context = $listener.GetContext()
            $path = Join-Path $dir $context.Request.Url.AbsolutePath.TrimStart('/')
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $bytes = [IO.File]::ReadAllBytes($path)
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            } else { $context.Response.StatusCode = 404 }
            $context.Response.Close()
        }
    }
    if (-not (Wait-Port $ReleasePort -TimeoutSeconds 30)) { throw 'release server did not start' }
}
