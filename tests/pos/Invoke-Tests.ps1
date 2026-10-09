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
