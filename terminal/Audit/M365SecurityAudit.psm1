#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AuditRoot = $PSScriptRoot
foreach ($file in @('Catalog','Collect','Evaluate','Report','Posture','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration','MailBaselineAntiphish','MailBaselineSpam','MailBaselineProtection','MailBaseline','Workbook','PostureReport','Run','Terminal')) {
    . (Join-Path $PSScriptRoot "src/$file.ps1")
}
Export-ModuleMember -Function Get-AuditSourceCatalog, Get-M365AuditPlan, Invoke-M365SecurityAudit, Test-M365AuditManifest, Get-M365OrganizationAuditPlan, Invoke-M365OrganizationAudit, Write-M365AuditSummary, Write-M365AuditSource, Get-FlapjacksPostureChecks, Get-FlapjacksAllPostureChecks, ConvertTo-FlapjacksWorkbookCollaborationSnapshot, Export-FlapjacksPostureBundle
