<#
.SYNOPSIS
Device setup: OpenSSH Server, the disabled support account, the relay key, Watch and its scheduled tasks, custom fields. Idempotent.
.NOTES
Design: docs/design.md, section 7.1. Run by Install-PosTunnel, as SYSTEM.
#>
param(
    [Parameter(Mandatory)][string]$RelayHost,
    [int]$RelayPort = 2222,
    [Parameter(Mandatory)][string]$RelayHostKey
)

$ErrorActionPreference = 'Stop'
throw 'not implemented yet'
