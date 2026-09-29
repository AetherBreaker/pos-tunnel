<#
.SYNOPSIS
Opens a session: installs the session key, enables support, starts sshd (loopback only), writes the lease, starts PosTunnel-Watch.
.NOTES
Design: docs/design.md, section 7.2. Run through Invoke-PosTunnel, as SYSTEM.
#>
param(
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][int]$IdleSeconds,
    [Parameter(Mandatory)][string]$SessionKey
)

$ErrorActionPreference = 'Stop'
throw 'not implemented yet'
