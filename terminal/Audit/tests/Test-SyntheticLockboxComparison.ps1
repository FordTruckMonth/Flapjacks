#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$helper = Join-Path $root 'workbook-fixture/Compare-LockboxOrganizationSettings.ps1'
if ((Get-FileHash -LiteralPath $helper).Hash -ine '722e653a758a59249a3136eea7e28520061d571b3a9560a3703e333a4e7e62a0') {
    throw 'Customer Lockbox fixture evaluator bytes differ from the reviewed version.'
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Customer Lockbox fixture evaluator did not parse.' }
$allowed = @('ConvertTo-Json','HasOnlyFields','IsInteger','IsText','ReadUtc')
foreach ($call in $ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)) {
    if ($call.GetCommandName() -cnotin $allowed -or $call.InvocationOperator -ne 'Unknown') {
        throw 'Unreviewed command in the Customer Lockbox fixture evaluator.'
    }
}
. (Join-Path $root 'workbook-fixture/PassiveJson.ps1')
. $helper

function New-Report {
    @{
        Metadata=@{SchemaVersion='1.1'; Mode='Synthetic'; TenantId='SYNTHETIC-NOT-A-TENANT'
            AccountVerification='Synthetic: not applicable'; OrganizationWideConfirmed=$false
            StartedAtUtc='2026-01-01T10:00:00Z'; FinishedAtUtc='2026-01-01T10:00:01Z'
            SelectedGroups=@('Core','Exchange','WorkbookExchange')}
        Evidence=@(@{SourceId='exchange-organization'; Group='Exchange'; Provider='Exchange'; Status='Collected'
            Target='Get-OrganizationConfig'; Count=1; PageCount=1; RequestCount=0; MissingFields=@()
            Reason='Synthetic fixture, not tenant data.'; Notes=''; CollectedAtUtc='2026-01-01T10:00:00.5Z'
            Items=@(@{Identity='Invented organization'; AuditDisabled=$false; OAuth2ClientProfileEnabled=$true
                DefaultAuthenticationPolicy=$null; AutoExpandingArchiveEnabled=$false; RejectDirectSend=$false
                CustomerLockboxEnabled=$true})})
    }
}
function Add-Summary($Result) {
    $Result.Coverage=@(foreach ($source in $Result.Evidence) {
        $row=@{}
        foreach ($name in 'SourceId','Group','Provider','Status','Reason','Count','MissingFields','Notes') { $row[$name]=$source[$name] }
        $row
    })
}
$script:cases=0
function Check([string]$Name,$Result,[string]$Expected='Unknown') {
    $json=ConvertTo-Json -InputObject $Result -Depth 50 -Compress
    $passive=ConvertFrom-FjcJson $json
    $before=ConvertTo-Json -InputObject $passive -Depth 50 -Compress
    $out=@(Get-FlapjacksSyntheticLockboxComparison -Result $passive)
    if ($out.Count -ne 1 -or $out[0].Row -ne 157 -or $out[0].Comparison -cne $Expected -or
        $out[0].Reason -cnotin @('IncompleteSyntheticOrganizationEvidence','ComparedStoredOrganizationSwitch') -or
        ($out[0].PSObject.Properties.Name -join ',') -cne 'Row,Comparison,Reason') {
        throw "$Name expected $Expected. Got $($out.Comparison)."
    }
    if ($before -cne (ConvertTo-Json -InputObject $passive -Depth 50 -Compress)) { throw "$Name modified the input." }
    $script:cases++
}
Check 'null report' $null
Check 'missing metadata and source' @{}
$r=New-Report
Check 'complete singleton evidence' $r Matches
$r.Evidence[0].Items[0].CustomerLockboxEnabled=$false
Check 'stored false' $r Differs
$r.Coverage=$r.Evidence
$r.Remove('Evidence')
Check 'stored full Coverage' $r Differs
$r=New-Report; Add-Summary $r
Check 'consistent native summary' $r Matches
$r.Coverage[0].Count='1'; Check 'contradictory summary count type' $r
$r.Coverage[0].Count=0; Check 'contradictory summary count value' $r
foreach ($key in 'Group','Provider','Reason','Status','Notes','SourceId','MissingFields') {
    $r=New-Report; Add-Summary $r; $r.Coverage[0][$key]='Different'
    Check "contradictory summary $key" $r
}
$r=New-Report; Add-Summary $r; $r.Coverage[0].Remove('Notes'); Check 'partial native summary' $r
$r=New-Report; Add-Summary $r; $r.Remove('Evidence'); Check 'summary cannot establish configuration' $r
$r=New-Report; Add-Summary $r; $r.Coverage+=$r.Coverage[0]; Check 'duplicate summary' $r
$r=New-Report; $r.Coverage=$r.Evidence; Check 'ambiguous parallel full sources' $r
$r=New-Report; $r.Coverage=$r.Evidence; $r.Evidence=@(); Check 'conflicting explicit empty Evidence' $r

foreach ($key in 'Mode','TenantId','SchemaVersion','SelectedGroups','AccountVerification','OrganizationWideConfirmed','StartedAtUtc','FinishedAtUtc') {
    $r=New-Report; $r.Metadata.Remove($key); Check "missing metadata $key" $r
}
foreach ($claims in @(@{Mode='Live'},@{Mode=@('Synthetic')},@{TenantId='invented-other'},@{TenantId=@('SYNTHETIC-NOT-A-TENANT')},
    @{SchemaVersion='1.0'},@{OrganizationWideConfirmed=$true},@{OrganizationWideConfirmed=0},@{RunId='invented-run'},
    @{AccountVerification='Verified'},@{SelectedGroups='Exchange'},@{SelectedGroups=@('Exchange')},
    @{SelectedGroups=@('WorkbookExchange')},@{SelectedGroups=@('Exchange','Exchange','WorkbookExchange')},
    @{SelectedGroups=@('Exchange','WorkbookExchange',1)},@{FinishedAtUtc='2025-01-01T10:00:00Z'},@{StartedAtUtc='2027-01-01T10:00:00Z'},
    @{StartedAtUtc='2026-02-30T10:00:00Z'},@{FinishedAtUtc='2026-01-01T10:00:01+03:00'})) {
    $r=New-Report; foreach ($key in $claims.Keys) { $r.Metadata[$key]=$claims[$key] }; Check "metadata $($claims.Keys)" $r
}
foreach ($claims in @(@{Mode='Live'},@{TenantId='elsewhere'},@{RunId='invented-run'},@{Provenance=@{}},
    @{SelectedCount=0},@{CollectedCount=-1},@{IncompleteCount='0'},@{FindingCount=1;Observations=@()})) {
    $r=New-Report; foreach ($key in $claims.Keys) { $r[$key]=$claims[$key] }; Check "report $($claims.Keys)" $r
}
$r=New-Report; $r.Mode='Synthetic'; $r.TenantId=$r.Metadata.TenantId; $r.Observations=@(); $r.FindingCount=0
$r.SelectedCount=1; $r.CollectedCount=1; $r.IncompleteCount=0
Check 'coherent repeated native metadata' $r Matches

foreach ($claims in @(@{SourceId='exchange-atp-organization'},@{Group='WorkbookExchange'},@{Provider='OfflineSnapshot'},
    @{Target='Get-TransportConfig'},@{Command='Get-Other'},@{RequiredNativeCommand='Get-Other'},
    @{TenantId='different-tenant'},@{RunId='different-run'},@{Truncated=$true},@{Provenance=@{ScopeVerification='Unverified'}},
    @{SnapshotComplete=$true},@{Status='OfflineSnapshot'},@{Status='Partial'},@{Status='Unavailable'},@{Status='NotSelected'},
    @{Reason='Partial data'},@{Notes='Partial collection'},@{Notes=@('')},@{Count='1'},@{Count=$true},@{Count=0},@{Count=2},@{RequestCount=-1},@{RequestCount=1},
    @{RequestCount=$false},@{PageCount=0},@{PageCount='1'},@{MissingFields=@('CustomerLockboxEnabled')},
    @{MissingFields=''},@{CollectedAtUtc='2026-02-30T12:00:00Z'},@{CollectedAtUtc='2026-01-01T10:00:02Z'},
    @{CollectedAtUtc='2026-01-01T09:59:59Z'},@{CollectedAtUtc='2026-01-01T10:00:00-01:00'},
    @{Items=@()},@{Items=@{}},@{Items=@(@{},@{})},@{Items=@($null)})) {
    $r=New-Report; foreach ($key in $claims.Keys) { $r.Evidence[0][$key]=$claims[$key] }; Check "source $($claims.Keys)" $r
}
foreach ($key in 'SourceId','Group','Provider','Target','Status','Count','PageCount','RequestCount','CollectedAtUtc','Items','MissingFields') {
    $r=New-Report; $r.Evidence[0].Remove($key); Check "source requires $key" $r
}
$r=New-Report; $r.Evidence+=$r.Evidence[0]; Check 'duplicate organization sources' $r
$r=New-Report; $r.Evidence[0].Items+=$r.Evidence[0].Items[0]; $r.Evidence[0].Count=2; Check 'two organization items' $r
foreach ($id in 'Not assessed','Unavailable','', ' ', 'Unknown','<unknown>','None',$null,$true,1,@('invented'),@{Name='invented'},
    ' Invented','Invented ',"invented`nname",'00000000-0000-0000-0000-000000000000','00000000000000000000000000000000',
    '{00000000-0000-0000-0000-000000000000}') {
    $r=New-Report; $r.Evidence[0].Items[0].Identity=$id; Check 'unusable singleton identity' $r
}
foreach ($value in $null,$true.ToString(),'false',0,1,@($false),@{Value=$true}) {
    $r=New-Report; $r.Evidence[0].Items[0].CustomerLockboxEnabled=$value; Check 'mistyped workbook Boolean' $r
}
foreach ($key in (New-Report).Evidence[0].Items[0].Keys) {
    $r=New-Report; $r.Evidence[0].Items[0].Remove($key); Check "incomplete organization projection $key" $r
}
$r=New-Report; $r.Evidence[0].Items[0].AuditDisabled=@{}; Check 'malformed companion projection' $r
$r=New-Report; $r.Evidence[0].Items[0].DefaultAuthenticationPolicy=@('unexpected'); Check 'malformed policy projection' $r
$r=New-Report; $r.Evidence[0].Items[0].AuditDisabled=$null; Check 'null unrelated optional value' $r Matches
$r=New-Report; $r.Evidence[0].Items[0].CustomerLockboxRequestApproved=$true; Check 'request record is outside the configured projection' $r

# Use a real schema 1.1 result generated from the repository's invented suite.
# The legacy source omits the Lockbox switch and one unrelated projection field.
$audit=Import-Module (Join-Path $root 'M365SecurityAudit.psm1') -PassThru -DisableNameChecking
$run=& $audit { Invoke-M365OrganizationAudit -Mode Synthetic -Workbook }
$r=ConvertFrom-FjcJson (ConvertTo-Json $run -Depth 50)
Check 'unmodified legacy public result' $r
$org=@($r.Evidence | Where-Object SourceId -ceq 'exchange-organization')[0]
$org.Items[0]['AutoExpandingArchiveEnabled']=$false
$org.Items[0]['CustomerLockboxEnabled']=$true
Check 'public synthetic schema with stored optional field supplied' $r Matches
Check 'saved full Coverage of public synthetic schema' @{Metadata=$r.Metadata;Coverage=$r.Evidence;Observations=$r.Observations} Matches

Write-Output "PASS $script:cases synthetic Customer Lockbox cases."
