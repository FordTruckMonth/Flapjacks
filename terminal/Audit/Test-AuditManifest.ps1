#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'M365SecurityAudit.psm1') -Force
try {
    $result=Test-M365AuditManifest -Path $Path
    $result | ConvertTo-Json -Depth 5
    if (-not $result.Valid) { exit 1 }
    exit 0
} catch { Write-Error $_; exit 1 }
