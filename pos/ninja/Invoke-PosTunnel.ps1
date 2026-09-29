<#
.SYNOPSIS
NinjaOne library script, pasted once. Runs an action (Open, Close, Touch) from the installed POS
package with the remaining arguments.
.NOTES
Design: docs/design.md, section 7.1. Runs as SYSTEM.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Touch')][string]$Action,
    [Parameter(ValueFromRemainingArguments)][string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
throw 'not implemented yet'
