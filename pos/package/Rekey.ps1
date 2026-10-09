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
