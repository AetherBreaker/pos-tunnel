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
