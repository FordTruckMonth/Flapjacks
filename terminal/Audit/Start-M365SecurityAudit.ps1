#Requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('Synthetic','Plan','Live')][string]$Mode='Synthetic',
    [string]$OutputPath='',
    [guid]$TenantId=[guid]::Empty,
    [string]$ExpectedAccount='',
    [guid]$ConfirmedTenantId=[guid]::Empty,
    [switch]$ConfirmOrganizationWide,
    [ValidateRange(1,10000)][int]$MaxPages=100,
    [ValidateRange(1,1000000)][int]$MaxRecords=50000,
    [switch]$FailOnIncomplete
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'M365SecurityAudit.psm1') -Force
try {
    if ($Mode -eq 'Plan') { Get-M365OrganizationAuditPlan | ConvertTo-Json -Depth 30; exit 0 }
    $result=Invoke-M365OrganizationAudit -Mode $Mode -OutputPath $OutputPath -TenantId $TenantId -ExpectedAccount $ExpectedAccount `
        -ConfirmedTenantId $ConfirmedTenantId -ConfirmOrganizationWide:$ConfirmOrganizationWide -MaxPages $MaxPages -MaxRecords $MaxRecords
    Write-M365AuditSummary -Result $result
    if ($FailOnIncomplete -and $result.IncompleteCount -gt 0) { exit 2 }
    exit 0
} catch { Write-Error $_; exit 1 }
