<#
.SYNOPSIS
NinjaOne library script, pasted once. Installs or upgrades the signed POS package from the latest GitHub
release, then runs its Setup. Idempotent; scheduled daily by the POS policy.
.NOTES
Design: docs/design.md, section 7.1. Runs as SYSTEM. The relay's address and public key and the release
signing public key come from the fleet fields, so nothing here changes when they do. ASCII only.
#>
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# A 32-bit PowerShell on 64-bit Windows sees a redirected System32 (no OpenSSH) and lacks the
# LocalAccounts cmdlets, so rerun in the 64-bit one.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    & "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PSCommandPath @(if ($Force) { '-Force' })
    exit $LASTEXITCODE
}

$ReleaseUrl = 'https://github.com/AetherBreaker/pos-tunnel/releases/latest/download'
$Root = 'C:\ProgramData\PosTunnel'
$Namespace = 'pos-tunnel-release'
$SystemSid = 'S-1-5-18'
$KeyPattern = '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'
# What this script and Invoke-PosTunnel run; Common.ps1 is what they dot-source.
$Required = 'Common.ps1', 'Setup.ps1', 'Watch.ps1', 'Open.ps1', 'Close.ps1', 'Touch.ps1', 'Rekey.ps1'
$script:failed = 0

function Write-Result([string]$Status, [string]$Step, [string]$Detail = '') {
    if ($Status -eq 'FAILED') { $script:failed++ }
    Write-Output ("$Status`t$Step" + $(if ($Detail) { "`t$Detail" } else { '' }))
}

# Recursive delete that never follows a link: rmdir /s removes a junction inside without entering it,
# and a link in $Path's place is deleted as the link (both probed on Windows 11).
function Remove-Tree([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if ($item.PSIsContainer) { [IO.Directory]::Delete($Path, $false) } else { [IO.File]::Delete($Path) }
    } elseif ($item.PSIsContainer) { cmd /c rmdir /s /q "$Path" } else { Remove-Item -LiteralPath $Path -Force }
    if (Test-Path -LiteralPath $Path) { throw "could not delete $Path" }
}

# Same mutex as the package's Common.ps1; the in-process Setup and Close re-enter it on this thread.
$lock = New-Object Threading.Mutex($false, 'Global\PosTunnel')
try { $held = $lock.WaitOne(600000) } catch [Threading.AbandonedMutexException] { $held = $true }
if (-not $held) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }

$step = 'folder'
try {
    # 1. Any user can create a folder in C:\ProgramData and own it, and SYSTEM runs Watch.ps1 from this
    # one every 2 minutes, so it is used only as SYSTEM's own: owner SYSTEM, SYSTEM-only, not inherited.
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    $secure = $false
    if ($item -and $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $acl = Get-Acl -LiteralPath $Root
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $secure = $acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $SystemSid -and
            $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $SystemSid -and
            $rules[0].AccessControlType -eq 'Allow' -and $rules[0].FileSystemRights -eq 'FullControl'
    }
    if ($secure) { Write-Result 'OK' $step }
    else {
        if ($item) { Remove-Tree $Root; Write-Result 'CHANGED' $step 'not SYSTEM-only: deleted, installing from scratch' }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($SystemSid)))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($SystemSid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        # Created with its ACL, so it is never briefly open to other users.
        $null = [IO.Directory]::CreateDirectory($Root, $acl)
        Write-Result 'CHANGED' $step 'created'
    }
    $installed = 0
    if (Test-Path -LiteralPath "$Root\current") { $installed = [int](Get-Content -LiteralPath "$Root\current" -Raw).Trim() }

    # 2. Neither an upgrade nor a repair should change sshd or the tasks under a live session.
    $step = 'session'
    if (Test-Path -LiteralPath "$Root\session.json") {
        if (-not $Force) { Write-Result 'DEFERRED' $step 'a session is open; the next run installs'; exit 0 }
        & "$Root\versions\$installed\Close.ps1"
        if ($LASTEXITCODE) { throw 'Close failed' }
    }

    # 3. Into the SYSTEM-only folder, never %TEMP%, which standard users can write to.
    $step = 'signature'
    $signer = Ninja-Property-Get posTunnelSigner
    if ($signer -cnotmatch $KeyPattern) { throw 'fleet field posTunnelSigner is empty or malformed' }
    [IO.File]::WriteAllText("$Root\allowed_signers", "$Namespace namespaces=`"$Namespace`" $signer`r`n")
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    foreach ($name in 'pos-manifest.json', 'pos-manifest.json.sig') {
        Invoke-WebRequest -Uri "$ReleaseUrl/$name" -OutFile "$Root\$name" -UseBasicParsing
    }
    # On a fresh POS only Windows' own ssh-keygen exists; it needs OpenSSH 8.1 or later for -Y.
    $keygen = @('C:\Program Files\OpenSSH\ssh-keygen.exe', "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe") |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $keygen) { throw 'no ssh-keygen to verify the release with' }
    # Start-Process, because Windows PowerShell 5.1 pipes text, not bytes, into a native command.
    $verify = Start-Process -FilePath $keygen -NoNewWindow -Wait -PassThru `
        -ArgumentList '-Y', 'verify', '-f', "$Root\allowed_signers", '-I', $Namespace, '-n', $Namespace, '-s', "$Root\pos-manifest.json.sig" `
        -RedirectStandardInput "$Root\pos-manifest.json" -RedirectStandardOutput "$Root\verify.out" -RedirectStandardError "$Root\verify.err"
    if ($verify.ExitCode) {
        throw "bad signature: $((Get-Content -LiteralPath "$Root\verify.out", "$Root\verify.err" | Where-Object { $_.Trim() }) -join ' ')"
    }
    Write-Result 'OK' $step

    $step = 'manifest'
    $manifest = Get-Content -LiteralPath "$Root\pos-manifest.json" -Raw | ConvertFrom-Json
    if ("$($manifest.version)" -notmatch '^\d+$') { throw 'version is not a number' }
    $version = [int]$manifest.version
    $files = @{}
    foreach ($entry in $manifest.files.PSObject.Properties) {
        if ($entry.Name -notmatch '^[A-Za-z0-9-]+\.ps1$' -or $entry.Value -notmatch '^[0-9a-f]{64}$') { throw "bad entry '$($entry.Name)'" }
        $files[$entry.Name] = $entry.Value
    }
    foreach ($name in $Required) { if (-not $files.ContainsKey($name)) { throw "lacks $name" } }

    # 4. Rollback protection: whoever can serve files could otherwise serve an old, validly signed release.
    $step = 'package'
    if ($version -lt $installed) { throw "release $version is older than installed $installed" }
    $dir = "$Root\versions\$version"
    $intact = Test-Path -LiteralPath $dir
    if ($intact) {
        $present = @(Get-ChildItem -LiteralPath $dir -Force)
        $intact = $present.Count -eq $files.Count -and -not @($present | Where-Object {
            -not $files.ContainsKey($_.Name) -or (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower() -ne $files[$_.Name]
        })
    }
    if ($intact) { Write-Result 'OK' $step "version $version" }
    else {
        Invoke-WebRequest -Uri "$ReleaseUrl/pos-package.zip" -OutFile "$Root\pos-package.zip" -UseBasicParsing
        # Read in memory: nothing from the archive reaches disk before its name and hash match the
        # manifest, so no entry can place a file anywhere (a ..\ name, say).
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Remove-Tree "$Root\staging"
        $null = New-Item -ItemType Directory -Path "$Root\staging"
        $sha = [Security.Cryptography.SHA256]::Create()
        $seen = @{}
        $zip = [IO.Compression.ZipFile]::OpenRead("$Root\pos-package.zip")
        try {
            foreach ($entry in $zip.Entries) {
                $name = $entry.FullName
                if (-not $files.ContainsKey($name) -or $seen.ContainsKey($name)) { throw "unexpected archive entry '$name'" }
                $buffer = New-Object IO.MemoryStream
                $stream = $entry.Open()
                try { $stream.CopyTo($buffer) } finally { $stream.Close() }
                $bytes = $buffer.ToArray()
                if ([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLower() -ne $files[$name]) { throw "$name does not match the manifest" }
                [IO.File]::WriteAllBytes("$Root\staging\$name", $bytes)
                $seen[$name] = $true
            }
        } finally { $zip.Dispose() }
        $missing = @($files.Keys | Where-Object { -not $seen.ContainsKey($_) })
        if ($missing) { throw "archive lacks $($missing -join ', ')" }
        Remove-Tree $dir
        $null = New-Item -ItemType Directory -Path "$Root\versions" -Force
        Move-Item -LiteralPath "$Root\staging" -Destination $dir
        Remove-Item -LiteralPath "$Root\pos-package.zip" -Force
        Write-Result 'CHANGED' $step $(if ($version -eq $installed) { "version $version repaired" } else { "version $version installed" })
    }

    # 5. current moves only after Setup succeeds, so a failed upgrade leaves the previous version active.
    $step = 'setup'
    $relay = Ninja-Property-Get posTunnelRelay
    if ($relay -notmatch '^([A-Za-z0-9.-]+):(\d{1,5})$') { throw 'fleet field posTunnelRelay is empty or malformed' }
    $relayHost, $relayPort = $Matches[1], [int]$Matches[2]
    $serverKey = Ninja-Property-Get posTunnelRelayServerKey
    if ($serverKey -cnotmatch $KeyPattern) { throw 'fleet field posTunnelRelayServerKey is empty or malformed' }
    & "$dir\Setup.ps1" -RelayHost $relayHost -RelayPort $relayPort -RelayServerKey $serverKey
    if ($LASTEXITCODE -eq 2) { Write-Result 'DEFERRED' $step "version $version stays inactive until Setup finishes"; exit 0 }
    if ($LASTEXITCODE) { throw "Setup failed; version $installed stays active" }

    $step = 'current'
    if ($version -ne $installed) {
        [IO.File]::WriteAllText("$Root\current", "$version")
        Write-Result 'CHANGED' $step "version $version"
    } else { Write-Result 'OK' $step "version $version" }
    # Keep the previous version, delete older ones.
    foreach ($old in @(Get-ChildItem -LiteralPath "$Root\versions" -Directory | Where-Object { $_.Name -notin "$version", "$installed" })) {
        Remove-Tree $old.FullName
        Write-Result 'CHANGED' 'old versions' "deleted $($old.Name)"
    }
} catch {
    Write-Result 'FAILED' $step $_.Exception.Message
} finally { $lock.ReleaseMutex() }
exit [int]($script:failed -gt 0)
