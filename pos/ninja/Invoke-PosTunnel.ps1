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
