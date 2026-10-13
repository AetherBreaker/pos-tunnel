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
    # One key per operator workstation on the session (section 7.2, joining): close ends it for all.
    $keys = @(Get-Content -LiteralPath $AuthorizedKeys -ErrorAction SilentlyContinue | Where-Object { $_ }).Count
    Stop-Session
    Write-Result 'OK' 'close' $(if ($open) { "session ended, $keys session key$(if ($keys -ne 1) { 's' })" } else { 'no session was open' })
} catch {
    Write-Result 'FAILED' 'close' $_.Exception.Message
} finally { Exit-Lock }
exit [int]($script:failed -gt 0)
