<#
.SYNOPSIS
NinjaOne library script, pasted once. Installs or upgrades the signed POS package from the latest
GitHub release, then runs its Setup. Idempotent; scheduled daily by the POS policy.
.NOTES
Design: docs/design.md, section 7.1. Runs as SYSTEM. Changes only if the release signing key rotates.
#>
param(
    [Parameter(Mandatory)][string]$RelayHost,
    [int]$RelayPort = 2222,
    [Parameter(Mandatory)][string]$RelayHostKey,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# allowed_signers line for the release signing key (namespace pos-tunnel-release).
$ReleaseSigner = 'pos-tunnel-release namespaces="pos-tunnel-release" ssh-ed25519 <set at first release>'

throw 'not implemented yet'
