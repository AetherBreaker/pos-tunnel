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
