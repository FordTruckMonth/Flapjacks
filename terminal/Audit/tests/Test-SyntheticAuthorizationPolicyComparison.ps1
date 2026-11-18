#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '../workbook-fixture'
$helper = Join-Path $lib 'Compare-AuthorizationPolicy.ps1'
if ((Get-FileHash -LiteralPath $helper).Hash -ine '1a5ff3b8688486eb577c9142a142c6676fcb6bfe172370c869f6218ff400373b') {
    throw 'Authorization-policy evaluator differs from the reviewed bytes.'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Authorization-policy evaluator did not parse.' }
foreach ($call in $ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true)) {
    if ($call.GetCommandName() -cnotin @('HasOnlyFields','IsText','ReadUtc') -or $call.InvocationOperator -ne 'Unknown') {
        throw 'Unreviewed command in the authorization-policy evaluator.'
    }
}
. (Join-Path $lib 'PassiveJson.ps1')
. $helper

function New-Report {
    @{
        Metadata = @{SchemaVersion='1.1'; Mode='Synthetic'; TenantId='SYNTHETIC-NOT-A-TENANT'; SelectedGroups=@('Core')
            StartedAtUtc='2001-01-01T10:00:00.0000000Z'; FinishedAtUtc='2001-01-01T10:00:00.0000002Z'
            OrganizationWideConfirmed=$false; AccountVerification='Synthetic: not applicable'}
        Coverage = @(@{SourceId='authorization-policy'; Group='Core'; Provider='Graph'; Target='/policies/authorizationPolicy'
            Status='Collected'; CollectedAtUtc='2001-01-01T10:00:00.0000001Z'; Count=1; PageCount=1; RequestCount=0
            Reason='Synthetic fixture, not tenant data.'; Notes=''; MissingFields=@(); Items=@(@{id='authorizationPolicy'
                defaultUserRolePermissions=@{allowedToCreateSecurityGroups=$false; allowedToCreateApps=$true}})})
        Observations = @()
    }
}
$cases = 0
function Check([string]$Label, $Report, [string]$Expected='Unknown') {
    $wire = ConvertTo-Json -InputObject $Report -Depth 25 -Compress
    $parsed = ConvertFrom-FjcJson $wire
    $before = ConvertTo-Json -InputObject $parsed -Depth 25 -Compress
    $rows = @(Get-FlapjacksSyntheticAuthorizationPolicyComparison -Result $parsed)
    $reason = if ($Expected -ceq 'Unknown') { 'IncompleteSyntheticAuthorizationPolicyEvidence' } else { 'ComparedStoredDefaultRoleSwitch' }
    if ($rows.Count -ne 1 -or $rows[0].Row -ne 155 -or $rows[0].Comparison -cne $Expected -or $rows[0].Reason -cne $reason -or
        ($rows[0].PSObject.Properties.Name -join ',') -cne 'Row,Comparison,Reason') { throw "Unexpected comparison for $Label." }
    if ($before -cne (ConvertTo-Json -InputObject $parsed -Depth 25 -Compress)) { throw "Input changed for $Label." }
    $script:cases++
}
Check 'complete native false' (New-Report) 'Matches'
$report = New-Report
$role = $report.Coverage[0].Items[0].defaultUserRolePermissions
$role.allowedToCreateSecurityGroups = $true
Check 'complete native true' $report 'Differs'
$role.Remove('allowedToCreateSecurityGroups')
Check 'app creation alone' $report
foreach ($value in @($null,0,1,0.0,'false','true',@{value=$false},(,$false))) {
    $role.allowedToCreateSecurityGroups = $value
    Check 'missing or mistyped Boolean' $report
}
foreach ($field in 'Metadata','Observations','Coverage') {
    $report = New-Report
    $report.Remove($field)
    Check "missing $field" $report
}
foreach ($field in 'Evidence','TenantId','Mode','RunId') {
    $report = New-Report
    $report[$field] = $report.Coverage
    Check "parallel or misplaced $field" $report
}
foreach ($overrides in @(@{Mode='Live'},@{Mode=@('Synthetic')},@{TenantId='invented-tenant'},@{SchemaVersion=1.1},
        @{AccountVerification='Verified'},@{OrganizationWideConfirmed=0},@{SelectedGroups='Core'},
        @{SelectedGroups=@('Administration')},@{SelectedGroups=@('core','Core')},@{SelectedGroups=@('Core','')},
        @{SelectedGroups=@('Core','invented')},@{SelectedGroups=@('Core','workbookidentity')},@{RunId='invented-other'},
        @{Scope='Live'},@{Scope=@('Synthetic')},@{Privacy='Live'},@{AuditMode='Live'},@{ConfirmOrganizationScope=$true},
        @{WorkbookAntiPhishBaseline='Standard'},@{SelectedGroups=@('Core','WorkbookExchange');WorkbookAntiPhishBaseline='Other'})) {
    $report = New-Report
    foreach ($field in $overrides.Keys) { $report.Metadata[$field] = $overrides[$field] }
    Check "metadata $($overrides.Keys)" $report
}
$report = New-Report
$report.Metadata.SelectedGroups = @('Core','Authentication','Consent','Administration','TenantInventory','Intune',
    'Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')
$report.Metadata.WorkbookAntiPhishBaseline = 'Standard'
$report.Metadata.Scope = 'Current configuration and optional point-in-time identity attributes. Not event logs, effective-policy analysis or compliance certification.'
$report.Metadata.Privacy = 'Optional workbook identity sources use selected directory fields, registration flags and last successful sign-in time, not sign-in events or mail content. Saved evidence may include object IDs and precise times. Keep local and access controlled.'
Check 'all native catalog groups with selected-identity scope' $report 'Matches'
$report.Metadata.SelectedGroups = @('Core','WorkbookExchange')
Check 'scope contradicts selected groups' $report
foreach ($overrides in @(@{SourceId='invented-other'},@{Group='Administration'},@{Provider='OfflineSnapshot'},
        @{Target='/groupSettings'},@{Status='Partial'},@{Status='Unavailable'},@{Status='NotSelected'},
        @{Reason='PageLimit'},@{Notes='Partial'},@{MissingFields=@('allowedToCreateSecurityGroups')},
        @{Count=$true},@{PageCount=1.0},@{RequestCount=2},@{RequestCount=1},@{Count=2},@{Items=@()},
        @{Mode='Live'},@{SnapshotComplete=$true},@{TenantId='invented-other'},@{Provenance=@{Kind='AlreadyCollected'}},
        @{CollectedAtUtc='2001-01-01T10:00:00.0000003Z'},@{CollectedAtUtc='2001-02-30T10:00:00Z'})) {
    $report = New-Report
    foreach ($field in $overrides.Keys) { $report.Coverage[0][$field] = $overrides[$field] }
    Check "source $($overrides.Keys)" $report
}
$report = New-Report
$report.Coverage[0].RequestCount = 1
$report.Coverage[0].Reason = ''
Check 'injected singleton projection' $report 'Matches'
$report.Coverage[0].RequestCount = 0
Check 'zero requests but neither writer success marker' $report

foreach ($field in 'id','defaultUserRolePermissions','@odata.type','@odata.context','@odata.nextLink','@removed','error') {
    $report = New-Report
    $report.Coverage[0].Items[0][$field] = 'invented-other'
    Check "policy $field" $report
}
$report = New-Report
$report.Coverage[0].Items[0].defaultUserRolePermissions['@odata.type'] = '#microsoft.graph.group'
Check 'foreign default-role type' $report
$report = New-Report
$report.Coverage[0].Items += $report.Coverage[0].Items
Check 'duplicate policy items' $report
$report = New-Report
$report.Coverage += $report.Coverage
Check 'duplicate coverage records' $report
foreach ($alias in '/policies/authorizationPolicy','/policies/authorizationPolicy?x=1',
        'https://graph.microsoft.com/v1.0/POLICIES/AUTHORIZATIONPOLICY/#fixture','/%70olicies/authorizationPolicy') {
    $report = New-Report
    $report.Coverage += @{SourceId='invented-alias'; Target=$alias}
    Check "competing target $alias" $report
}
$snapshot = @{SourceId='workbook-teams-client'; Provider='OfflineSnapshot'; Target='Get-CsTeamsClientConfiguration'
    Status='OfflineSnapshot'; SnapshotComplete=$true; Provenance=@{Kind='AlreadyCollected'}; Items=@(@{AllowEmailIntoChannel=$false})}
$report = New-Report
$report.Coverage += $snapshot
Check 'unrelated snapshot' $report 'Matches'
$report.Coverage = @($snapshot)
Check 'unrelated snapshot alone' $report

Write-Output "$cases synthetic authorization-policy comparisons passed."
