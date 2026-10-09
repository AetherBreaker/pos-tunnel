# POS Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the POS side of pos-tunnel: the two NinjaOne library scripts (`Install-PosTunnel`, `Invoke-PosTunnel`) and the signed package they install and run (`Common`, `Setup`, `Open`, `Close`, `Touch`, `Watch`, `Rekey`), with integration tests that run every script as SYSTEM on a disposable Windows runner.

**Architecture:** Windows PowerShell 5.1 scripts, run as SYSTEM by NinjaOne or by the `PosTunnel-Watch` scheduled task. `Install-PosTunnel` secures `C:\ProgramData\PosTunnel`, verifies the release manifest's signature with `ssh-keygen -Y verify` against the `posTunnelSigner` fleet field, unpacks only manifest-listed, hash-matching files, and runs that version's `Setup`. Every package script dot-sources `Common.ps1`: paths, the one-line-per-step result log, the machine-wide `Global\PosTunnel` mutex, ACL helpers, `Start-Sshd`, and `Stop-Session`, the only teardown. The tests run under Pester 5 as SYSTEM on `windows-latest`, against a JSON-backed stub of NinjaOne's field cmdlets, a local HTTP release server, and a second `sshd` standing in for the relay.

**Tech Stack:** Windows PowerShell 5.1, Win32-OpenSSH 10.0.0.0p2 (MSI, pinned by SHA256), Task Scheduler, `Microsoft.PowerShell.LocalAccounts`, Pester 5.9 (preinstalled on `windows-latest`), GitHub Actions.

**Spec:** `docs/design.md`, sections 7.1-7.6, plus 7.8 for `Rekey.ps1` (the package's fifth action) and sections 2, 3, 5 and 11 where they touch the POS. Read 7.1 and 7.2 in full before starting. Where this plan and the design differ, this plan is newer and Task 6 brings the design up to date; the differences are listed under "Decisions this plan makes".

**Provenance:** every script and test below ran green on `windows-latest` before this plan was written (throwaway branch `probe/pos-package`, 25 of 25 tests, and the end-of-Task-1 state alone, 3 of 3). The code blocks are those files verbatim.

## Global Constraints

- **Windows PowerShell 5.1 only.** No PowerShell 7 syntax: no `? :`, `??`, `?.`, `&&`/`||` pipeline chains, `-Parallel`, or `ForEach-Object -Parallel`.
- **ASCII only** in every `.ps1`: 5.1 reads a BOM-less script as ANSI, so one em dash corrupts a string. `.gitattributes` makes `.ps1` CRLF in every checkout; `scripts/sign_pos.py` refuses LF.
- 4-space indent, `$ErrorActionPreference = 'Stop'`, full cmdlet names, `-LiteralPath` for paths. Native commands by full path (`C:\Program Files\OpenSSH\...`), never the copies in `System32`, except `Install-PosTunnel`'s fallback `ssh-keygen` on a fresh POS.
- Output is one line per step, `<STATUS>`, `<step>` and `<detail>` separated by tabs, with status `OK` (already right), `CHANGED`, `SKIPPED`, `DEFERRED` or `FAILED`. Exit 0 = success or deferred, 1 = failed; `Setup.ps1` also exits 2 = deferred, which `Install-PosTunnel` turns into its own exit 0.
- Fixed values: state folder `C:\ProgramData\PosTunnel`; tunnel port 20001-65535 (20000 + device ID); idle seconds 1-43200; 72-hour maximum; `PosTunnel-Watch` every 2 minutes plus at startup; lock `Global\PosTunnel`, waited for 600 s (`Watch`: 60 s, then `SKIPPED`); session key = the bare base64 of an ed25519 public key, `^AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$` (fleet-field keys: the same with an `ssh-ed25519 ` prefix); Win32-OpenSSH MSI `https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi`, SHA256 `DDEC9C53864280759CF9F74791CEFD387100E3946AA849A1C138A4ED1B96B7D9`.
- **Leave the till alone.** The POS runs payment and database services, some listening on the store LAN. Nothing here restarts the machine, touches the firewall, or stops a service other than `sshd`; the loopback check (`Start-Sshd`) looks only at `sshd`'s own listeners, never at the machine's.
- Comments and docstrings carry reasoning, densely (`AGENTS.md`, "Comment Density"). No single-use helpers of 4 lines or fewer.
- In prose, say "private key"/"public key", never "host key" (the field name `posTunnelHostKey` and sshd's `HostKey` keyword are names, not prose).
- **Tests run only on CI.** They install OpenSSH, create accounts and tasks, and remove Windows' own OpenSSH Server, so they refuse to run unless `POS_TUNNEL_DISPOSABLE=1`, which only the CI job sets. Never set it on a workstation. The user chose GitHub Actions as the test machine (2026-10-08), so each task ends by pushing the feature branch and reading the `pos-integration` job. The other CI jobs: `pos-package` fails on this branch until Task 6 re-signs, which is expected; `cli` is unaffected.
- Conventional Commits, scope `pos` (or `ci`, `docs`, `test`), every message ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Never print `.env`. Never sign with the release signing private key yourself: Task 6 asks the user to.

**Local check** (any Windows machine, changes nothing; run it from the repo root before every push). Expected: no output.

```powershell
foreach ($f in Get-ChildItem pos, tests\pos -Recurse -Filter *.ps1) {
    if ([IO.File]::ReadAllBytes($f.FullName) | Where-Object { $_ -gt 127 }) { "$($f.Name): not ASCII" }
    $e = $null; $null = [Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e)
    $e | ForEach-Object { "$($f.Name):$($_.Extent.StartLineNumber): $($_.Message)" }
}
```

**CI check** (Git Bash, after `git push`): waits for this commit's CI run and prints the `pos-integration` job's verdict and its test lines. The suite takes about 5 minutes; the whole job about 8.

```bash
sha=$(git rev-parse HEAD)
until run=$(gh run list --commit "$sha" --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId') && [ -n "$run" ]; do sleep 5; done
gh run watch "$run" > /dev/null 2>&1
job=$(gh run view "$run" --json jobs --jq '.jobs[] | select(.name | startswith("POS package: integration")) | .databaseId')
gh run view "$run" --json jobs --jq '.jobs[] | select(.name | startswith("POS package: integration")) | "pos-integration: \(.conclusion)"'
gh run view --job "$job" --log | sed 's/\x1b\[[0-9;]*m//g' | grep -E '\[[+-]\]|Tests Passed|Expected|Exception|^\s+(OK|CHANGED|FAILED|DEFERRED|SKIPPED)\s'
```

## Decisions this plan makes

Each was settled by a probe or a CI run; Task 6 records them in the design.

1. **`Invoke-PosTunnel` re-splats `-Name value` pairs by name.** The design's "runs `<Action>.ps1` with the remaining arguments", done the obvious way (`ValueFromRemainingArguments` then `@Arguments`), hands `-Port` to `Open` as a value: `Cannot convert value "-Port" to type "System.Int32"`. Probed in 5.1 three ways (`-File`, `-Command`, in-process), with typed and untyped collectors.
2. **The session key travels as bare base64** (`-SessionKey AAAAC3...`), so NinjaOne's parameter string needs no quoting and one regex validates all of it. `posctl`'s plan inherits this.
3. **The tunnel forwards to `127.0.0.1:22`, not `localhost:22`.** Windows resolves `localhost` to `::1` first, where `sshd` isn't listening, so every forwarded connection was refused before reaching `sshd` (CI: `kex_exchange_identification: Connection closed by remote host`). The relay's `permitlisten="localhost:<port>"` concerns its own listening side and stays.
4. **A machine-wide lock.** `Watch` runs every 2 minutes, and between `Open` writing the session key and writing `session.json` it would see no session and tear down. Every script holds `Global\PosTunnel`.
5. **`Stop-Session` in `Common.ps1` is the one teardown,** called by `Watch` (idle state and expiry), `Close` (at once, no longer backdating the lease and starting `Watch`), `Open` (replacing a leftover session from a `connect` that timed out), `Setup` (its final idle state) and `Install-PosTunnel -Force` (through `Close`).
6. **During a session `Watch` also starts `sshd` and enables `support`.** `sshd` is Manual, so after the nightly 3 AM restart the tunnel came back but `sshd` didn't.
7. **`Setup` defers when removing Windows' own OpenSSH Server needs a restart,** leaving `current` unchanged; the 3 AM restart precedes the next 4 AM run. On Server 2025 the removal needed none.
8. **The MSI is pinned by URL and SHA256 in `Setup.ps1`.** The signature covers `Setup`, so the pin is as trusted as the package.
9. **Both library scripts rerun themselves in 64-bit PowerShell** if NinjaOne starts a 32-bit one, where `System32` redirects (no OpenSSH) and the LocalAccounts cmdlets are missing.
10. **`Invoke-PosTunnel` checks the state folder is SYSTEM-only** before running anything from it, since SYSTEM runs whatever it holds.
11. **`Install-PosTunnel` repairs a same-version install** whose files no longer match the manifest.

## Review Focus

1. **The nightly 3 AM restart during a session.** `sshd` is Manual, so the tunnel comes back with nothing behind it. Expected: `Watch` starts `sshd` (loopback-checked) and the tunnel. Test: `Watch` / `brings sshd and the tunnel back after a restart` (Task 4).
2. **`Watch` firing while `Open` is halfway through.** Expected: `Watch` waits for the lock or skips; it never tears down a session being built. Test: `Watch` / `skips its run while another PosTunnel script holds the lock` (Task 4).
3. **`localhost` resolving to `::1`.** Expected: the operator's login reaches `sshd` through the relay. Test: `Sessions` / `opens a session the operator reaches through the relay, with sshd on loopback only` (Task 3).
4. **An edited `sshd_config` that listens on the store LAN.** Expected: `Open` refuses and tears down, and the next install restores the file. Test: `Sessions` / `refuses to open, and tears down, when sshd would listen beyond loopback` (Task 3).
5. **A state folder a user created first, with a junction inside.** Expected: deleted without following the junction, then recreated SYSTEM-only. Test: `Install-PosTunnel` / `installs from scratch, replacing a folder it does not own without following a junction in it` (Task 1).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `pos/ninja/Install-PosTunnel.ps1` | Library script: secure the folder, verify and unpack the release, run `Setup`, move `current` |
| `pos/ninja/Invoke-PosTunnel.ps1` | Library script: check the folder, run `versions\<current>\<Action>.ps1` with re-splatted arguments |
| `pos/package/Common.ps1` | Dot-sourced: paths, `Write-Result`, the lock, `New-Acl`/`Test-Acl`/`Set-FileContent`, `Start-Sshd`, `Stop-Session`, `Publish-DeviceFields` |
| `pos/package/Setup.ps1` | `sshd_config`, OpenSSH, `support`, relay key pair, relay pin, tasks, idle state, device fields |
| `pos/package/Open.ps1` | Start a session |
| `pos/package/Close.ps1` | End it at once |
| `pos/package/Touch.ps1` | Renew the lease |
| `pos/package/Watch.ps1` | Idle state, expiry, recovery after a restart or a drop |
| `pos/package/Rekey.ps1` | New relay and SSH server key pairs |
| `tests/pos/Harness.ps1` | Field stub, release builder and server, stand-in relay, script runner, tunnel ssh |
| `tests/pos/Invoke-Tests.ps1` | Runs the suite as SYSTEM through a scheduled task, prints its log |
| `tests/pos/PosTunnel.Tests.ps1` | One `Describe` per task, in order |
| `.github/workflows/ci.yml` | Gains the `pos-integration` job |
| `pos/manifest.json`, `pos/manifest.json.sig` | Re-signed by the user in Task 6 |
| `docs/design.md`, `README.md` | Task 6 |

---

### Task 1: The install path, the test harness and the CI job

**Files:**
- Create: `pos/package/Common.ps1`, `tests/pos/Harness.ps1`, `tests/pos/Invoke-Tests.ps1`, `tests/pos/PosTunnel.Tests.ps1`
- Replace: `pos/package/Setup.ps1`, `pos/ninja/Install-PosTunnel.ps1` (the current files are placeholders)
- Create placeholder: `pos/package/Rekey.ps1` (Task 5 fills it in; `Install-PosTunnel` requires every package file to exist)
- Modify: `.github/workflows/ci.yml` (add a job)
- Leave alone until their tasks: `pos/package/{Open,Close,Touch,Watch}.ps1`, `pos/ninja/Invoke-PosTunnel.ps1`. `Setup` registers `PosTunnel-Watch` pointing at the placeholder `Watch.ps1`, which throws harmlessly every 2 minutes until Task 4.

**Interfaces:**
- Produces (`Common.ps1`, dot-sourced as `. "$PSScriptRoot\Common.ps1"`): variables `$Root`, `$SshDir`, `$OpenSsh`, `$SessionFile`, `$LeaseFile`, `$RelayKey`, `$RelayFile`, `$KnownHosts`, `$AuthorizedKeys`, `$SupportUser`, `$LinkTask`, `$WatchTask`, `$MaxSessionHours`, `$SystemSid`, `$AdminsSid`; functions `Write-Result([string]$Status, [string]$Step, [string]$Detail = '')` (counts `FAILED` in `$script:failed`), `Enter-Lock([int]$TimeoutSeconds)` -> `[bool]`, `Exit-Lock`, `New-Acl([string[]]$FullControl, [string[]]$ReadOnly = @(), [switch]$Directory)`, `Test-Acl([string]$Path, [string[]]$FullControl, [string[]]$ReadOnly = @())` -> `[bool]`, `Set-FileContent([string]$Path, [string]$Content, [string[]]$FullControl = @(), [string[]]$ReadOnly = @())` -> `[bool]` changed, `Start-Sshd` -> `$null` or a problem string, `Stop-Session`, `Publish-DeviceFields([string]$Version)`.
- Produces (`Setup.ps1`): `-RelayHost <string> -RelayPort <int> -RelayServerKey 'ssh-ed25519 <base64>'`; exit 0/1/2.
- Produces (`Install-PosTunnel.ps1`): `[-Force]`; reads fleet fields `posTunnelSigner`, `posTunnelRelay` (`<host>:<port>`), `posTunnelRelayServerKey`; downloads `pos-manifest.json`, `pos-manifest.json.sig`, `pos-package.zip` from `$ReleaseUrl`; writes `$Root\current`.
- Produces (harness, for every later task): `Invoke-Install [-Force]`, `Invoke-Action <Action> [string[]]`, `Invoke-Watch`, `Open-TestSession [-IdleSeconds 3600]`, `Invoke-ThroughTunnel <command>` -> `{ExitCode, Output}`, `Start-TunnelSsh <command>` -> `Process`, `Wait-Port <port> [-Closed]` -> `[bool]`, `Get-IdleState` -> `{SshdStatus, SshdStartType, SupportEnabled, AuthorizedKeys, LinkState, Session}`, `Get-Field`/`Set-Field`, `Publish-TestRelease <version> [-SigningKey] [-ExtraEntry] [-Tamper <file>]`; every script runner returns `{ExitCode, Output, Text}`; variables `$Root`, `$Work`, `$RelayPort` (2222), `$TunnelPort` (20001).

- [x] **Step 1: Write the harness**

`tests/pos/Harness.ps1`:

```powershell
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
```

- [x] **Step 2: Write the SYSTEM runner**

`tests/pos/Invoke-Tests.ps1`:

```powershell
<#
.SYNOPSIS
Runs PosTunnel.Tests.ps1 as SYSTEM, the identity NinjaOne gives the scripts: once C:\ProgramData\PosTunnel
is SYSTEM-only, nothing else can even read it. Disposable machines only (POS_TUNNEL_DISPOSABLE=1).
#>
param([switch]$AsSystem)

$ErrorActionPreference = 'Stop'
$Log = 'C:\pt-tests.log'

if ($AsSystem) {
    Import-Module Pester -MinimumVersion 5.5
    $config = New-PesterConfiguration
    $config.Run.Path = "$PSScriptRoot\PosTunnel.Tests.ps1"
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $result = Invoke-Pester -Configuration $config
    exit [int]($result.Result -ne 'Passed')
}

if ($env:POS_TUNNEL_DISPOSABLE -ne '1') { throw 'these tests reconfigure the machine; set POS_TUNNEL_DISPOSABLE=1 only on a disposable one' }
Remove-Item $Log, "$Log.exit" -Force -ErrorAction SilentlyContinue
$command = "`$env:POS_TUNNEL_DISPOSABLE = '1'; & '$PSCommandPath' -AsSystem *> '$Log'; Set-Content '$Log.exit' `$LASTEXITCODE"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40)
$null = Register-ScheduledTask -TaskName 'pt-tests' -Action $action -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName 'pt-tests'
$deadline = (Get-Date).AddMinutes(40)
while (-not (Test-Path "$Log.exit")) {
    if ((Get-Date) -gt $deadline) { break }
    Start-Sleep -Seconds 2
}
Get-Content $Log -ErrorAction SilentlyContinue
if (-not (Test-Path "$Log.exit")) { throw 'the tests did not finish within 40 minutes' }
exit [int](Get-Content "$Log.exit" -Raw).Trim()
```

- [x] **Step 3: Write the install tests**

`tests/pos/PosTunnel.Tests.ps1` (later tasks append one `Describe` each):

```powershell
BeforeAll {
    . "$PSScriptRoot\Harness.ps1"
    Initialize-Harness
}

# In file order, each test starting from the state the one before left, as a device's life runs. The
# real PosTunnel-Watch also fires every 2 minutes throughout, so a test of what Watch does checks the
# state it leaves, not which run produced it.
Describe 'Install-PosTunnel' {
    It 'installs from scratch, replacing a folder it does not own without following a junction in it' {
        $null = New-Item -ItemType Directory 'C:\pt-victim' -Force
        Set-Content 'C:\pt-victim\keep.txt' 'keep'
        $null = New-Item -ItemType Directory $Root -Force
        $null = cmd /c mklink /J "$Root\versions" 'C:\pt-victim'
        Publish-TestRelease 1

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "CHANGED`tfolder`tnot SYSTEM-only"
        'C:\pt-victim\keep.txt' | Should -Exist
        $acl = Get-Acl $Root
        $acl.AreAccessRulesProtected | Should -BeTrue
        @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) |
            Should -Be @('S-1-5-18')
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
    }

    It 'leaves the device set up and idle' {
        (Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName | Should -BeLike '*Program Files\OpenSSH\sshd.exe*'
        Test-Path "$env:SystemRoot\System32\OpenSSH\sshd.exe" | Should -BeFalse
        $state = Get-IdleState
        $state.SshdStatus | Should -Be 'Stopped'
        $state.SshdStartType | Should -Be 'Manual'
        $state.SupportEnabled | Should -BeFalse
        $state.AuthorizedKeys | Should -Be 0
        $state.LinkState | Should -Be 'Disabled'
        $state.Session | Should -BeFalse
        (Get-LocalGroupMember -SID 'S-1-5-32-544').Name | Should -Contain "$env:COMPUTERNAME\support"
        Get-Content "$env:ProgramData\ssh\sshd_config" | Should -Contain 'ListenAddress 127.0.0.1'
        (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH').DefaultShell | Should -BeLike '*\WindowsPowerShell\v1.0\powershell.exe'
        Get-Field posTunnelRelayKey | Should -Match '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'
        Get-Field posTunnelHostKey | Should -Match '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'
        Get-Field posTunnelVersion | Should -Be '1'
        (Get-Content "$Root\known_hosts" -Raw).Trim() | Should -Be "[127.0.0.1]:$RelayPort $(Get-Field posTunnelRelayServerKey)"
        $watch = Get-ScheduledTask PosTunnel-Watch
        $watch.Actions[0].Arguments | Should -BeLike "*$Root\versions\1\Watch.ps1*"
        $watch.Triggers[1].Repetition.Interval | Should -Be 'PT2M'
        $watch.Triggers[1].Repetition.Duration | Should -BeNullOrEmpty
        (Get-ScheduledTask PosTunnel-Link).Settings.ExecutionTimeLimit | Should -Be 'PT0S'
    }

    It 'changes nothing on a second run' {
        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Not -Match 'CHANGED'
    }
}
```

- [x] **Step 4: Add the CI job**

In `.github/workflows/ci.yml`, add under `jobs:`, after the `cli` job:

```yaml
  pos-integration:
    name: "POS package: integration tests as SYSTEM (windows-latest)"
    runs-on: windows-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Every POS script is ASCII and parses in Windows PowerShell 5.1
        shell: powershell
        run: |
          $bad = 0
          foreach ($file in Get-ChildItem pos, tests\pos -Recurse -Filter *.ps1) {
            if ([IO.File]::ReadAllBytes($file.FullName) | Where-Object { $_ -gt 127 }) { "$($file.FullName): not ASCII"; $bad++ }
            $errors = $null
            $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
            foreach ($e in $errors) { "$($file.FullName):$($e.Extent.StartLineNumber): $($e.Message)"; $bad++ }
          }
          exit [int]($bad -gt 0)

      - name: tests\pos\Invoke-Tests.ps1
        shell: powershell
        env:
          POS_TUNNEL_DISPOSABLE: "1"
        run: .\tests\pos\Invoke-Tests.ps1

      - name: Get-WinEvent OpenSSH/Operational (on failure)
        if: failure()
        shell: powershell
        run: Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 300 -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { "$($_.TimeCreated.ToString('HH:mm:ss')) $($_.Message)" }
```

- [x] **Step 5: Commit, push, and watch the tests fail**

Run the local check (expected: no output), then:

```bash
git add tests/pos .github/workflows/ci.yml
git commit -m "test(pos): integration harness and install tests, run as SYSTEM in CI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin HEAD
```

Run the CI check. Expected: `pos-integration: failure`, all three tests `[-]`, the first with `Expected 0, but got 1.` (the placeholder `Install-PosTunnel` throws `not implemented yet`).

- [x] **Step 6: Write `Common.ps1`**

`pos/package/Common.ps1`:

```powershell
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

# Every package script and Install-PosTunnel serialize on this mutex: Watch runs every 2 minutes and would
# otherwise tear down a session Open is halfway through building. Mutex ownership is per thread and
# recursive, so a script run in-process by a holder (Install -> Setup, Install -> Close) gets it at once.
# A holder that died leaves it abandoned, which hands it to the next waiter; every script converges from
# whatever state it finds, so that is safe.
function Enter-Lock([int]$TimeoutSeconds) {
    $script:Lock = New-Object Threading.Mutex($false, 'Global\PosTunnel')
    try { return $script:Lock.WaitOne($TimeoutSeconds * 1000) } catch [Threading.AbandonedMutexException] { return $true }
}

function Exit-Lock {
    if ($script:Lock) { $script:Lock.ReleaseMutex(); $script:Lock.Dispose(); $script:Lock = $null }
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
# the only thing keeping sshd off the store LAN. Returns $null when it is, else what it found.
function Start-Sshd {
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
    $sshdPid = (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $sshdPid -ErrorAction SilentlyContinue)
        if ($listeners) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    if (-not $listeners) { return 'no listener' }
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
```

- [x] **Step 7: Write `Setup.ps1`**

`pos/package/Setup.ps1` (replacing the placeholder):

```powershell
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
```

- [x] **Step 8: Write the `Rekey.ps1` placeholder**

`pos/package/Rekey.ps1`:

```powershell
<#
.SYNOPSIS
Regenerates the POS relay key pair and the POS SSH server key pair, then republishes both public keys.
Refused while a session is open.
.NOTES
Design: docs/design.md, section 7.8. Run through Invoke-PosTunnel, as SYSTEM.
#>

$ErrorActionPreference = 'Stop'
throw 'not implemented yet'
```

- [x] **Step 9: Write `Install-PosTunnel.ps1`**

`pos/ninja/Install-PosTunnel.ps1` (replacing the placeholder):

```powershell
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
```

- [x] **Step 10: Commit, push, and watch the tests pass**

Run the local check (expected: no output), then:

```bash
git add pos/package/Common.ps1 pos/package/Setup.ps1 pos/package/Rekey.ps1 pos/ninja/Install-PosTunnel.ps1
git commit -m "feat(pos): Install-PosTunnel, Setup and the shared Common

Install-PosTunnel secures the state folder, verifies the release manifest's
signature against the posTunnelSigner fleet field, unpacks only manifest-listed,
hash-matching files and runs that version's Setup (design 7.1). Common holds the
machine-wide lock and Stop-Session, the one teardown.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: success`, `Tests Passed: 3`. The first install's lines include `CHANGED <tab> built-in OpenSSH Server <tab> removed` and `CHANGED <tab> OpenSSH <tab> installed`: the runner image ships Windows' own OpenSSH Server, so every run exercises its removal.

---

### Task 2: Install refusals, upgrades and repair

**Files:**
- Modify: `tests/pos/PosTunnel.Tests.ps1` (append a `Describe`)
- Modify only if a test fails: `pos/ninja/Install-PosTunnel.ps1`

**Interfaces:**
- Consumes: Task 1's harness (`Publish-TestRelease`, `Invoke-Install`, `Get-Field`, `$Root`, `$Work`) and `Install-PosTunnel.ps1`.

These tests pin behaviour Task 1's `Install-PosTunnel` already has, so they are expected to pass at once. A reviewer can still reject them separately: they are the rollback protection and the archive vetting (design 7.1 steps 3-4). If one fails, the fix goes in `Install-PosTunnel.ps1`, never in the test's expectation.

- [x] **Step 1: Append the tests**

Append to `tests/pos/PosTunnel.Tests.ps1`:

```powershell
Describe 'Install-PosTunnel refusals and upgrades' {
    It 'refuses a release signed by another key, keeping the installed version' {
        Publish-TestRelease 2 -SigningKey "$Work\other_signing_key"

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tsignature`tbad signature: .*verif"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
        "$Root\versions\2" | Should -Not -Exist
    }

    It 'refuses an archive entry the manifest lacks, writing nothing from the archive' {
        Publish-TestRelease 2 -ExtraEntry

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`tunexpected archive entry 'Extra.ps1'"
        Get-ChildItem $Root -Recurse -Filter 'Extra.ps1' | Should -BeNullOrEmpty
        "$Root\versions\2" | Should -Not -Exist
    }

    It 'refuses an archive file whose hash does not match the manifest' {
        Publish-TestRelease 2 -Tamper 'Open.ps1'

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`tOpen.ps1 does not match the manifest"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '1'
    }

    It 'upgrades, keeping the previous version and pointing Watch at the new one' {
        Publish-TestRelease 2

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '2'
        "$Root\versions\1" | Should -Exist
        (Get-ScheduledTask PosTunnel-Watch).Actions[0].Arguments | Should -BeLike "*$Root\versions\2\Watch.ps1*"
        Get-Field posTunnelVersion | Should -Be '2'

        Publish-TestRelease 3
        (Invoke-Install).ExitCode | Should -Be 0
        "$Root\versions\1" | Should -Not -Exist
        "$Root\versions\2" | Should -Exist
    }

    It 'refuses an older release than the installed one' {
        Publish-TestRelease 2

        $r = Invoke-Install

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tpackage`trelease 2 is older than installed 3"
        (Get-Content "$Root\current" -Raw).Trim() | Should -Be '3'
    }

    It 'repairs an installed file that no longer matches the manifest' {
        Add-Content "$Root\versions\3\Touch.ps1" '# drift'
        Publish-TestRelease 3

        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "CHANGED`tpackage`tversion 3 repaired"
        Get-Content "$Root\versions\3\Touch.ps1" | Should -Not -Contain '# drift'
    }
}
```

- [x] **Step 2: Commit, push, and check**

Run the local check (expected: no output), then:

```bash
git add tests/pos/PosTunnel.Tests.ps1
git commit -m "test(pos): Install-PosTunnel refuses bad releases, upgrades and repairs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: success`, `Tests Passed: 9`, including `FAILED <tab> signature <tab> bad signature: Could not verify signature.` and `FAILED <tab> package <tab> release 2 is older than installed 3` as expected output lines.

---

### Task 3: Sessions: `Invoke-PosTunnel`, `Open`, `Touch`, `Close`

**Files:**
- Modify: `tests/pos/PosTunnel.Tests.ps1` (append a `Describe`)
- Replace: `pos/ninja/Invoke-PosTunnel.ps1`, `pos/package/Open.ps1`, `pos/package/Touch.ps1`, `pos/package/Close.ps1`

**Interfaces:**
- Consumes: `Common.ps1` (`Enter-Lock`, `Exit-Lock`, `Write-Result`, `Set-FileContent`, `Start-Sshd`, `Stop-Session`, the path variables); Task 1's harness (`Open-TestSession`, `Invoke-ThroughTunnel`, `Start-TunnelSsh`, `Wait-Port`, `Get-IdleState`, `Invoke-Action`, `Invoke-Install`).
- Produces: `Invoke-PosTunnel -Action <Open|Close|Touch|Rekey> [-Name value ...]`; `Open -Port <int> -IdleSeconds <int> -SessionKey <bare base64>`; `Close` and `Touch` with no parameters. `session.json` = `{"port":..,"idle_seconds":..,"started":<Unix seconds>}`; `lease`'s `LastWriteTimeUtc` is the last renewal. `posctl` (its own plan) calls these through NinjaOne.

- [x] **Step 1: Append the tests**

Append to `tests/pos/PosTunnel.Tests.ps1`:

```powershell
Describe 'Sessions: Invoke-PosTunnel, Open, Touch, Close' {
    It 'refuses arguments that are not -Name value pairs' {
        $r = Invoke-Action Open @('20001', '3600')

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tinvoke`texpected -Name value pairs"
        (Get-IdleState).Session | Should -BeFalse
    }

    It 'refuses a session key that is not the bare base64 of an ed25519 public key' {
        $r = Invoke-Action Open @('-Port', "$TunnelPort", '-IdleSeconds', '3600', '-SessionKey', 'AAAAB3NzaC1yc2EAAAADAQABAAABAQ')

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tparameters"
        (Get-IdleState).Session | Should -BeFalse
    }

    It 'opens a session the operator reaches through the relay, with sshd on loopback only' {
        $r = Open-TestSession

        $r.ExitCode | Should -Be 0
        Wait-Port $TunnelPort | Should -BeTrue
        $ssh = Invoke-ThroughTunnel 'whoami'
        $ssh.ExitCode | Should -Be 0
        $ssh.Output | Should -BeLike '*\support'
        $sshdPid = (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId
        @(Get-NetTCPConnection -State Listen -OwningProcess $sshdPid | ForEach-Object LocalAddress) | Should -Be @('127.0.0.1')
    }

    It 'defers an install while the session is open, leaving it working' {
        $r = Invoke-Install

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "DEFERRED`tsession"
        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
    }

    It 'renews the lease on Touch' {
        (Get-Item "$Root\lease").LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-30)

        $r = Invoke-Action Touch

        $r.ExitCode | Should -Be 0
        ([DateTime]::UtcNow - (Get-Item "$Root\lease").LastWriteTimeUtc).TotalSeconds | Should -BeLessThan 60
    }

    It 'replaces a leftover session on Open' {
        $r = Open-TestSession

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "CHANGED`tprevious session`treplacing"
        Wait-Port $TunnelPort | Should -BeTrue
        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
    }

    It 'closes at once, ending the live connection' {
        $live = Start-TunnelSsh 'Start-Sleep 600'

        $r = Invoke-Action Close

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "OK`tclose`tsession ended"
        $live.WaitForExit(30000) | Should -BeTrue
        $state = Get-IdleState
        $state.SshdStatus | Should -Be 'Stopped'
        $state.SupportEnabled | Should -BeFalse
        $state.AuthorizedKeys | Should -Be 0
        $state.LinkState | Should -Be 'Disabled'
        $state.Session | Should -BeFalse
        Wait-Port $TunnelPort -Closed | Should -BeTrue
    }

    It 'refuses to open, and tears down, when sshd would listen beyond loopback' {
        (Get-Content "$env:ProgramData\ssh\sshd_config" -Raw) -replace 'ListenAddress 127.0.0.1', 'ListenAddress 0.0.0.0' |
            Set-Content "$env:ProgramData\ssh\sshd_config" -Encoding ASCII -NoNewline

        $r = Open-TestSession

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tsshd`tlistening on 0.0.0.0:22"
        $state = Get-IdleState
        $state.SshdStatus | Should -Be 'Stopped'
        $state.SupportEnabled | Should -BeFalse
        $state.Session | Should -BeFalse
        $repair = Invoke-Install
        $repair.ExitCode | Should -Be 0
        $repair.Text | Should -Match "CHANGED`tsshd_config"
    }

    It 'ends an open session and reinstalls with -Force' {
        (Open-TestSession).ExitCode | Should -Be 0

        $r = Invoke-Install -Force

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "OK`tclose`tsession ended"
        (Get-IdleState).Session | Should -BeFalse
        (Get-IdleState).SshdStatus | Should -Be 'Stopped'
    }
}
```

- [x] **Step 2: Commit, push, and watch them fail**

Run the local check (expected: no output), then:

```bash
git add tests/pos/PosTunnel.Tests.ps1
git commit -m "test(pos): session tests for Invoke-PosTunnel, Open, Touch and Close

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: failure`, Tasks 1-2's 9 tests `[+]`, this task's 9 `[-]` (the placeholder `Invoke-PosTunnel` throws `not implemented yet`).

- [x] **Step 3: Write `Invoke-PosTunnel.ps1`**

`pos/ninja/Invoke-PosTunnel.ps1` (replacing the placeholder):

```powershell
<#
.SYNOPSIS
NinjaOne library script, pasted once. Runs an action (Open, Close, Touch, Rekey) from the installed POS
package with the remaining -Name value arguments.
.NOTES
Design: docs/design.md, section 7.1. Runs as SYSTEM. ASCII only.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Touch', 'Rekey')][string]$Action,
    [Parameter(ValueFromRemainingArguments)][string[]]$Arguments
)

$ErrorActionPreference = 'Stop'

# A 32-bit PowerShell on 64-bit Windows sees a redirected System32 (no OpenSSH) and lacks the
# LocalAccounts cmdlets, so rerun in the 64-bit one.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    & "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PSCommandPath -Action $Action @Arguments
    exit $LASTEXITCODE
}

$Root = 'C:\ProgramData\PosTunnel'
$SystemSid = 'S-1-5-18'
try {
    # Install-PosTunnel's folder check, without its repair: SYSTEM runs whatever this folder holds.
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    $acl = if ($item -and $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Get-Acl -LiteralPath $Root }
    $rules = if ($acl) { @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) } else { @() }
    if (-not ($acl -and $acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $SystemSid -and
        $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $SystemSid -and $rules[0].FileSystemRights -eq 'FullControl')) {
        throw "$Root is missing or not SYSTEM-only; run Install-PosTunnel"
    }
    $version = ''
    if (Test-Path -LiteralPath "$Root\current") { $version = "$(Get-Content -LiteralPath "$Root\current" -Raw)".Trim() }
    if ($version -notmatch '^\d+$') { throw 'no package version is installed; run Install-PosTunnel' }

    # Re-splatted by name: splatting the raw list would hand "-Port" to Open as a value.
    $named = @{}
    for ($i = 0; $i -lt $Arguments.Count; $i += 2) {
        if ($Arguments[$i] -notmatch '^-([A-Za-z]+)$' -or $i + 1 -ge $Arguments.Count) { throw "expected -Name value pairs, got '$($Arguments[$i])'" }
        $named[$Matches[1]] = $Arguments[$i + 1]
    }
    & "$Root\versions\$version\$Action.ps1" @named
    exit $LASTEXITCODE
} catch {
    Write-Output "FAILED`tinvoke`t$($_.Exception.Message)"
    exit 1
}
```

- [x] **Step 4: Write `Open.ps1`**

`pos/package/Open.ps1` (replacing the placeholder):

```powershell
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
    # that timed out, say) and safe to replace.
    $step = 'previous session'
    if (Test-Path -LiteralPath $SessionFile) { Write-Result 'CHANGED' $step 'replacing'; Stop-Session }

    $step = 'session key'
    $null = Set-FileContent $AuthorizedKeys "ssh-ed25519 $SessionKey`r`n" $SystemSid, $AdminsSid
    Write-Result 'CHANGED' $step

    $step = 'support account'
    Enable-LocalUser -Name $SupportUser
    Write-Result 'CHANGED' $step 'enabled'

    $step = 'sshd'
    $problem = Start-Sshd
    if ($problem) {
        Write-Result 'FAILED' $step "$problem; tearing down"
        Stop-Session
        exit 1
    }
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
    Write-Result 'FAILED' $step $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
```

- [x] **Step 5: Write `Touch.ps1`**

`pos/package/Touch.ps1` (replacing the placeholder):

```powershell
<#
.SYNOPSIS
Renews the POS lease. keepalive's fallback when the tunnel is down.
.NOTES
Design: docs/design.md, section 7.3. Run through Invoke-PosTunnel, as SYSTEM.
#>

. "$PSScriptRoot\Common.ps1"

if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
try {
    if (Test-Path -LiteralPath $SessionFile) {
        (Get-Item -LiteralPath $LeaseFile).LastWriteTimeUtc = [DateTime]::UtcNow
        Write-Result 'CHANGED' 'lease' 'renewed'
    } else { Write-Result 'FAILED' 'lease' 'no session is open' }
} catch {
    Write-Result 'FAILED' 'lease' $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
```

- [x] **Step 6: Write `Close.ps1`**

`pos/package/Close.ps1` (replacing the placeholder):

```powershell
<#
.SYNOPSIS
Closes the session at once: the same teardown Watch runs on expiry. Converges to idle if none is open.
.NOTES
Design: docs/design.md, section 7.5. Run through Invoke-PosTunnel, and in-process by
Install-PosTunnel -Force, as SYSTEM.
#>

. "$PSScriptRoot\Common.ps1"

if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
try {
    $open = Test-Path -LiteralPath $SessionFile
    Stop-Session
    Write-Result 'OK' 'close' $(if ($open) { 'session ended' } else { 'no session was open' })
} catch {
    Write-Result 'FAILED' 'close' $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
```

- [x] **Step 7: Commit, push, and watch them pass**

Run the local check (expected: no output), then:

```bash
git add pos/ninja/Invoke-PosTunnel.ps1 pos/package/Open.ps1 pos/package/Touch.ps1 pos/package/Close.ps1
git commit -m "feat(pos): Invoke-PosTunnel, Open, Touch and Close

Invoke-PosTunnel re-splats -Name value pairs by name: splatting the raw list
hands -Port to Open as a value. Open takes the session key as bare base64, so
NinjaOne's parameter string needs no quoting, and forwards to 127.0.0.1:22,
since Windows resolves localhost to ::1 first, where sshd isn't listening.
Close tears down at once through Stop-Session.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: success`, `Tests Passed: 18`.

---

### Task 4: `Watch`

**Files:**
- Modify: `tests/pos/PosTunnel.Tests.ps1` (append a `Describe`)
- Replace: `pos/package/Watch.ps1`

**Interfaces:**
- Consumes: `Common.ps1` (`Enter-Lock`, `Exit-Lock`, `Write-Result`, `Start-Sshd`, `Stop-Session`, `$SessionFile`, `$LeaseFile`, `$MaxSessionHours`, `$SupportUser`, `$LinkTask`); `session.json` and `lease` as Task 3 writes them; the harness's `Invoke-Watch`.
- Produces: the `PosTunnel-Watch` task's behaviour. From here on it fires for real every 2 minutes during the suite, so a test of what `Watch` does checks the state left behind, not the output of its own run.

- [x] **Step 1: Append the tests**

Append to `tests/pos/PosTunnel.Tests.ps1`:

```powershell
Describe 'Watch' {
    It 'brings sshd and the tunnel back after a restart' {
        (Open-TestSession).ExitCode | Should -Be 0
        Wait-Port $TunnelPort | Should -BeTrue
        Stop-ScheduledTask PosTunnel-Link
        Stop-Service sshd -Force
        Wait-Port $TunnelPort -Closed | Should -BeTrue

        $r = Invoke-Watch

        $r.ExitCode | Should -Be 0
        Wait-Port $TunnelPort | Should -BeTrue
        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
    }

    It 'skips its run while another PosTunnel script holds the lock' {
        $mutex = New-Object Threading.Mutex($false, 'Global\PosTunnel')
        $null = $mutex.WaitOne()
        try { $r = Invoke-Watch } finally { $mutex.ReleaseMutex() }

        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match "SKIPPED`tlock"
        (Get-IdleState).Session | Should -BeTrue
    }

    It 'tears down when the lease expires, ending the live connection' {
        $live = Start-TunnelSsh 'Start-Sleep 600'
        (Get-Item "$Root\lease").LastWriteTimeUtc = [DateTime]::UtcNow.AddHours(-2)

        $r = Invoke-Watch

        $r.ExitCode | Should -Be 0
        $live.WaitForExit(30000) | Should -BeTrue
        $state = Get-IdleState
        $state.SshdStatus | Should -Be 'Stopped'
        $state.SupportEnabled | Should -BeFalse
        $state.AuthorizedKeys | Should -Be 0
        $state.LinkState | Should -Be 'Disabled'
        $state.Session | Should -BeFalse
        Wait-Port $TunnelPort -Closed | Should -BeTrue
    }

    It 'tears down at the 72-hour maximum however fresh the lease' {
        (Open-TestSession).ExitCode | Should -Be 0
        $session = Get-Content "$Root\session.json" -Raw | ConvertFrom-Json
        $session.started = [DateTimeOffset]::UtcNow.AddHours(-73).ToUnixTimeSeconds()
        Set-Content "$Root\session.json" ($session | ConvertTo-Json -Compress) -Encoding ASCII

        $r = Invoke-Watch

        $r.ExitCode | Should -Be 0
        (Get-IdleState).Session | Should -BeFalse
        (Get-IdleState).SshdStatus | Should -Be 'Stopped'
    }

    It 'stops sshd again when an OpenSSH upgrade restarts it between sessions' {
        Set-Service sshd -StartupType Automatic
        Start-Service sshd

        $r = Invoke-Watch

        $r.ExitCode | Should -Be 0
        (Get-IdleState).SshdStatus | Should -Be 'Stopped'
        (Get-IdleState).SshdStartType | Should -Be 'Manual'
        (Invoke-Watch).Text | Should -BeNullOrEmpty
    }
}
```

- [x] **Step 2: Commit, push, and watch them fail**

Run the local check (expected: no output), then:

```bash
git add tests/pos/PosTunnel.Tests.ps1
git commit -m "test(pos): Watch recovers, expires, and respects the lock

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: failure`, the first 18 tests `[+]`, this task's 5 `[-]` (the placeholder `Watch.ps1` throws `not implemented yet`).

- [x] **Step 3: Write `Watch.ps1`**

`pos/package/Watch.ps1` (replacing the placeholder):

```powershell
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

    # sshd is Manual, so after a restart it is down until this starts it.
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
```

- [x] **Step 4: Commit, push, and watch them pass**

Run the local check (expected: no output), then:

```bash
git add pos/package/Watch.ps1
git commit -m "feat(pos): Watch, the session lifecycle on the POS

Between sessions it keeps the idle state (undoing an OpenSSH upgrade's restart
of sshd); on expiry it tears down through Stop-Session; during a session it
starts sshd, which is Manual and so down after the nightly restart, and the
tunnel. It waits 60 s for the lock and otherwise skips its run.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: success`, `Tests Passed: 23`.

---

### Task 5: `Rekey`

**Files:**
- Modify: `tests/pos/PosTunnel.Tests.ps1` (append a `Describe`)
- Replace: `pos/package/Rekey.ps1` (Task 1's placeholder)

**Interfaces:**
- Consumes: `Common.ps1` (`Enter-Lock`, `Exit-Lock`, `Write-Result`, `Publish-DeviceFields`, `$RelayKey`, `$SshDir`, `$OpenSsh`, `$SessionFile`).
- Produces: `Invoke-PosTunnel -Action Rekey`, which `posctl rekey` (its own plan) calls.

- [x] **Step 1: Append the tests**

Append to `tests/pos/PosTunnel.Tests.ps1`:

```powershell
Describe 'Rekey' {
    It 'refuses while a session is open' {
        (Open-TestSession).ExitCode | Should -Be 0

        $r = Invoke-Action Rekey

        $r.ExitCode | Should -Be 1
        $r.Text | Should -Match "FAILED`tsession`ta session is open"
        (Invoke-Action Close).ExitCode | Should -Be 0
    }

    It 'regenerates both key pairs, and a session works with the new ones' {
        $oldRelayKey, $oldServerKey = (Get-Field posTunnelRelayKey), (Get-Field posTunnelHostKey)

        $r = Invoke-Action Rekey

        $r.ExitCode | Should -Be 0
        Get-Field posTunnelRelayKey | Should -Not -Be $oldRelayKey
        Get-Field posTunnelHostKey | Should -Not -Be $oldServerKey
        (Open-TestSession).ExitCode | Should -Be 0
        Wait-Port $TunnelPort | Should -BeTrue
        (Invoke-ThroughTunnel 'hostname').ExitCode | Should -Be 0
        (Invoke-Action Close).ExitCode | Should -Be 0
    }
}
```

- [x] **Step 2: Commit, push, and watch them fail**

Run the local check (expected: no output), then:

```bash
git add tests/pos/PosTunnel.Tests.ps1
git commit -m "test(pos): Rekey refuses during a session and regenerates both key pairs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: failure`, the first 23 tests `[+]`, both of this task's `[-]` (the placeholder throws `not implemented yet`).

- [x] **Step 3: Write `Rekey.ps1`**

`pos/package/Rekey.ps1` (replacing the placeholder):

```powershell
<#
.SYNOPSIS
Regenerates the POS relay key pair and the POS SSH server key pair, then republishes both public keys.
Refused while a session is open.
.NOTES
Design: docs/design.md, section 7.8. Run through Invoke-PosTunnel, as SYSTEM.
#>

. "$PSScriptRoot\Common.ps1"

if (-not (Enter-Lock 600)) { Write-Result 'FAILED' 'lock' 'another PosTunnel script held it for 10 minutes'; exit 1 }
$step = 'session'
try {
    if (Test-Path -LiteralPath $SessionFile) { Write-Result 'FAILED' $step 'a session is open; close it first'; exit 1 }

    $step = 'relay key pair'
    Remove-Item -LiteralPath $RelayKey, "$RelayKey.pub" -Force -ErrorAction SilentlyContinue
    # Windows PowerShell 5.1 drops an empty native argument; '""' reaches ssh-keygen as one.
    & "$OpenSsh\ssh-keygen.exe" -q -t ed25519 -N '""' -C "pos-tunnel $env:COMPUTERNAME" -f $RelayKey
    if ($LASTEXITCODE) { throw "ssh-keygen exited $LASTEXITCODE" }
    Write-Result 'CHANGED' $step 'regenerated'

    $step = 'server key pair'
    Get-ChildItem -LiteralPath $SshDir -Filter 'ssh_host_*' | Remove-Item -Force
    & "$OpenSsh\ssh-keygen.exe" -A
    if ($LASTEXITCODE) { throw "ssh-keygen -A exited $LASTEXITCODE" }
    Write-Result 'CHANGED' $step 'regenerated'

    $step = 'fields'
    Publish-DeviceFields (Split-Path $PSScriptRoot -Leaf)
} catch {
    Write-Result 'FAILED' $step $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
```

- [ ] **Step 4: Commit, push, and watch them pass**

Run the local check (expected: no output), then:

```bash
git add pos/package/Rekey.ps1
git commit -m "feat(pos): Rekey regenerates the relay and SSH server key pairs

Verified on windows-latest: ssh-keygen -A regenerates the Win32-OpenSSH server
key pair in C:\\ProgramData\\ssh, and sshd accepts it (design 11).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Run the CI check. Expected: `pos-integration: success`, `Tests Passed: 25`.

---

### Task 6: The design, the README, and the signed manifest

**Files:**
- Modify: `docs/design.md`, `README.md`
- Re-signed by the user: `pos/manifest.json`, `pos/manifest.json.sig`

**Interfaces:**
- Consumes: everything above, and `scripts/sign_pos.py` (`poe sign-pos`), unchanged. It hashes every file in `pos/package/`, `Common.ps1` and `Rekey.ps1` included, and bumps the manifest `version` from 1 to 2.

- [ ] **Step 1: Bring `docs/design.md` up to date**

Make these twelve replacements. Each Old block is the passage exactly as it stands today, line breaks included; replace it with the New block.

1. Section 1, the "POS package" row's last cell (then re-pad that table's columns to the new width):

   Old:
   ```
   PowerShell, run as SYSTEM: `Setup`, `Open`, `Close`, `Touch`, and `Watch`, which owns the session lifecycle on the POS. Signed release asset.
   ```
   New:
   ```
   PowerShell, run as SYSTEM: `Setup`, `Open`, `Close`, `Touch`, `Rekey`, and `Watch`, which owns the session lifecycle on the POS; all dot-source `Common` (the lock and the one teardown). Signed release asset.
   ```

2. Section 7.1, the `Invoke-PosTunnel` paragraph:

   Old:
   ```
   **`Invoke-PosTunnel -Action <Open|Close|Touch|Rekey> …`** (library): runs
   `versions\<current>\<Action>.ps1` with the remaining arguments. `posctl` runs every per-session action
   through it, so a session never downloads anything.
   ```
   New:
   ```
   **`Invoke-PosTunnel -Action <Open|Close|Touch|Rekey> …`** (library): runs
   `versions\<current>\<Action>.ps1` with the remaining arguments, which must be `-Name value` pairs; it
   re-splats them by name, since splatting the raw list hands `-Port` to the action as a value. It first
   checks the state folder is SYSTEM-only (`Install-PosTunnel` step 1, without the repair), since SYSTEM
   runs whatever that folder holds. `posctl` runs every per-session action through it, so a session never
   downloads anything. Both library scripts rerun themselves in 64-bit PowerShell if NinjaOne starts a
   32-bit one, where `System32` redirects (no OpenSSH) and the LocalAccounts cmdlets are missing.
   ```

3. Section 7.1, `Install-PosTunnel` step 2:

   Old:
   ```
   With
      `-Force` (used by `relay point`), run `Watch`'s teardown first.
   ```
   New:
   ```
   With
      `-Force` (used by `relay point`), run the installed `Close` first.
   ```

4. Section 7.1, `Install-PosTunnel` step 4:

   Old:
   ```
      delete older ones. Equal → skip the download.
   ```
   New:
   ```
      delete older ones. Equal → skip the download, unless `versions\<version>` no longer matches the
      manifest, which reinstalls it (repair).
   ```

5. Section 7.1, `Install-PosTunnel` step 5:

   Old:
   ```
   5. Run `versions\<version>\Setup.ps1` with the relay values. Only after it succeeds, write
      `current` = the version, so a failed upgrade leaves the previous version active.
   ```
   New:
   ```
   5. Run `versions\<version>\Setup.ps1` with the relay values. Only after it succeeds, write
      `current` = the version, so a failed upgrade leaves the previous version active. If `Setup` defers
      (its step 2), report deferred and leave `current` alone.
   ```

6. Section 7.1, `Setup` step 2:

   Old:
   ```
      OpenSSH Server capability if present (it competes for the `sshd` service name), then install the
      Win32-OpenSSH MSI. Only this first install happens here;
   ```
   New:
   ```
      OpenSSH Server capability if present (it competes for the `sshd` service name), then download the
      Win32-OpenSSH MSI `Setup` pins by URL and SHA256 into the state folder and install it. If the removal
      needs a restart, report deferred and stop: the 3 AM restart comes before the next 4 AM run. Only this
      first install happens here;
   ```

7. Section 7.1, `Setup` step 3:

   Old:
   ```
   3. Service start type Manual, stopped. Registry `DefaultShell` = Windows PowerShell.
   ```
   New:
   ```
   3. Registry `DefaultShell` = Windows PowerShell; `ssh-keygen -A` if the MSI's first start of `sshd` left
      no server key pair.
   ```

8. Section 7.1, `Setup` step 8:

   Old:
   ```
   8. Publish `posTunnelRelayKey`, `posTunnelHostKey`, `posTunnelVersion` custom fields
      (`Ninja-Property-Set`).
   ```
   New:
   ```
   8. Converge to `Watch`'s idle state (`Stop-Session`): `sshd` Manual and stopped,
      `administrators_authorized_keys` empty, `support` and `PosTunnel-Link` disabled.
   9. Publish `posTunnelRelayKey`, `posTunnelHostKey`, `posTunnelVersion` custom fields
      (`Ninja-Property-Set`), each only where it differs.
   ```

9. Section 7.2, the whole `Open` paragraph:

   Old:
   ```
   **`Open`** (POS, SYSTEM): validate parameters → write the session key as the sole line of
   `administrators_authorized_keys` (SYSTEM+Administrators ACL, or `sshd` ignores it) → enable `support`
   → start `sshd`, then verify its listeners are loopback only (abort and tear down if not — the
   Windows firewall is off, so this is the only thing keeping `sshd` off the store LAN) → write
   `session.json` (`port`, `idle_seconds`, `started`) and touch `lease` → set `PosTunnel-Link`'s action to
   `ssh -N -R <port>:localhost:22 tunnel@<relay> -p <relay port> -i relay_key -o ExitOnForwardFailure=yes
   -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o UserKnownHostsFile=known_hosts
   -o IdentitiesOnly=yes` (only `relay_key` is offered: the relay records every key a POS offers, section 6.5)
   → enable and start `PosTunnel-Link` and run `PosTunnel-Watch`.
   ```
   New:
   ```
   **`Open -Port <port> -IdleSeconds <s> -SessionKey <base64>`** (POS, SYSTEM; the session key is the bare
   base64 of the ed25519 public key, so NinjaOne's parameter string needs no quoting): validate parameters
   → if a session is already there, tear it down (the relay refuses a second lease for the port, so it is
   left over, from a `connect` that timed out, say) → write `ssh-ed25519 <base64>` as the sole line of
   `administrators_authorized_keys` (SYSTEM+Administrators ACL, or `sshd` ignores it) → enable `support`
   → start `sshd`, then verify its listeners are loopback only (abort and tear down if not — the Windows
   firewall is off, so this is the only thing keeping `sshd` off the store LAN) → write `session.json`
   (`port`, `idle_seconds`, `started` in Unix seconds) and touch `lease` → set `PosTunnel-Link`'s action
   to `ssh -N -F none -R <port>:127.0.0.1:22 -p <relay port> -i relay_key -o ExitOnForwardFailure=yes
   -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o StrictHostKeyChecking=yes
   -o UserKnownHostsFile=known_hosts -o IdentitiesOnly=yes tunnel@<relay>` (`127.0.0.1`, not `localhost`,
   which Windows resolves to `::1` first, where `sshd` isn't listening; only `relay_key` is offered: the
   relay records every key a POS offers, section 6.5) → enable and start `PosTunnel-Link`.
   ```

10. Section 7.2, the `Watch` list and the paragraph after it:

    Old:
    ```
    **`Watch`** (POS, SYSTEM, every 2 min and at startup):
    1. No `session.json` → ensure the idle state and exit: `sshd` Manual and stopped (an OpenSSH MSI
       upgrade sets it Automatic and starts it), `administrators_authorized_keys` empty, `support`
       disabled, `PosTunnel-Link` stopped and disabled.
    2. Lease mtime older than `idle_seconds`, or `started` older than 72h → **teardown**: stop
       `PosTunnel-Link`, stop `sshd`, empty `administrators_authorized_keys`, disable `support`, delete
       `session.json` and `lease`, disable `PosTunnel-Link`.
    3. `PosTunnel-Link` not running → start it.

    `Watch` is the only teardown implementation; everything else triggers it. The startup trigger means a
    reboot during a session brings the tunnel back, and a reboot after expiry cleans up.
    ```
    New:
    ```
    **`Watch`** (POS, SYSTEM, every 2 min and at startup):
    1. No `session.json` → ensure the idle state and exit: `sshd` Manual and stopped (an OpenSSH MSI
       upgrade sets it Automatic and starts it), `administrators_authorized_keys` empty, `support`
       disabled, `PosTunnel-Link` stopped and disabled.
    2. Lease mtime older than `idle_seconds`, `started` older than 72h, or session state unreadable →
       **teardown**: stop `PosTunnel-Link`, stop `sshd` and end its live connections, empty
       `administrators_authorized_keys`, disable `support` and end its processes, delete `session.json`
       and `lease`, disable `PosTunnel-Link`.
    3. Otherwise start `sshd` if it isn't running (it is Manual, so a restart leaves it down) and recheck
       it is loopback only, tearing down if not; enable `support`; start `PosTunnel-Link` if it isn't
       running.

    The idle state and the teardown are one function, `Stop-Session` in `Common.ps1`, and the only
    teardown implementation: `Watch`, `Close`, `Open` (replacing a leftover session), `Setup` and
    `Install-PosTunnel -Force` (through `Close`) all call it. The startup trigger means a reboot during a
    session brings `sshd` and the tunnel back, and a reboot after expiry cleans up.

    **Lock.** Every package script and `Install-PosTunnel` hold the machine-wide mutex `Global\PosTunnel`
    while they work, so `Watch` can't tear down a session `Open` is halfway through building. `Watch`
    waits 60 s for it and otherwise skips its run; the others wait 10 minutes. Ownership is per thread
    and recursive, so a script run in-process by the holder (`Install-PosTunnel` → `Setup`, `-Force` →
    `Close`) gets it at once.
    ```

11. Section 7.5:

    Old:
    ```
    (backdates `lease`, starts `PosTunnel-Watch`, which tears down)
    ```
    New:
    ```
    (tears down at once: `Stop-Session`, as `Watch` does on expiry)
    ```

12. Section 11, the end of the verified list, and its last open bullet:

    Old:
    ```
    `cron` blocking every job (even with `-L 0`) while `/dev/log` isn't read; killing a connection's `[priv]` process and its child frees the forwarded
    port (the relay's integration tests). Still open:
    ```
    New:
    ```
    `cron` blocking every job (even with `-L 0`) while `/dev/log` isn't read; killing a connection's `[priv]` process and its child frees the forwarded
    port (the relay's integration tests); on `windows-latest` (Windows Server 2025, PowerShell 5.1), the POS
    package's integration tests: removing Windows' OpenSSH Server capability (no restart needed there),
    installing the Win32-OpenSSH 10.0 MSI over it, a session's whole path through a stand-in relay, and
    `ssh-keygen -A` regenerating the server key pair (`rekey`). Still open:
    ```
    And delete this bullet:
    ```
    - `ssh-keygen -A` regenerating the Win32-OpenSSH server key pair in `C:\ProgramData\ssh` (`rekey`).
    ```

- [ ] **Step 2: Update the README's status line**

In `README.md`:

Old:
```
**Status:** design complete, implementation not started. Everything below `cli/`, `pos/` and `relay/`
is scaffolding.
```
New:
```
**Status:** the relay and the POS package are implemented; `posctl` is not (everything below `cli/` is
scaffolding).
```

- [ ] **Step 3: Commit**

```bash
git add docs/design.md README.md
git commit -m "docs(design): record the POS package's decisions

Re-splatted -Name value arguments, the bare base64 session key, the forward to
127.0.0.1, the machine-wide lock, Stop-Session as the one teardown, Watch
restarting sshd during a session, Setup deferring after a capability removal,
and what CI verified on Windows Server 2025.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Ask the user to re-sign the package**

Stop and ask the user to run, from the repo root on their workstation (the release signing private key never leaves it, and an agent never signs with it):

```bash
POS_TUNNEL_SIGNING_KEY=<path to the release signing private key> uv run poe sign-pos
```

Expected: `signed pos package version 2; commit pos/manifest.json and its .sig`. Wait for the user to confirm before continuing.

- [ ] **Step 5: Verify the signature and commit**

```bash
uv run --no-project scripts/sign_pos.py --check && echo signature ok
git add pos/manifest.json pos/manifest.json.sig
git commit -m "chore(pos): sign POS package version 2

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Expected: `signature ok`. Then run the CI check: `pos-integration: success`, `Tests Passed: 25`. Also confirm that every job in the run passed, `pos-package` included:

```bash
gh run view "$run" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
```

Expected: three lines, each ending `success`.

---

## After this plan

- `posctl` gets its own plan. It calls `Invoke-PosTunnel -Action Open -Port <port> -IdleSeconds <s> -SessionKey <bare base64>`, `-Action Close`, `-Action Touch`, `-Action Rekey`, and `Install-PosTunnel [-Force]`.
- Still open from design section 11, all for deployment (section 12) rather than this plan: NinjaOne passing named parameters (`-Port 20001`) to a library script, which only a real NinjaOne run can show (run a throwaway library script that prints `$args` with a preset parameter string before pasting the two real ones); `ssh-keygen -Y` with the `ssh-keygen` Windows bundles on the fleet's oldest build; NinjaOne's WinGet patching of an MSI it didn't install; and whether removing Windows' own OpenSSH Server needs a restart on client Windows.
- The throwaway branch `probe/pos-package` on GitHub holds the probe runs; delete it once this plan has landed.
