#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$auditRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $auditRoot 'workbook-fixture/PassiveJson.ps1')
. (Join-Path $auditRoot 'workbook-fixture/ConnectionFilter.ps1')

function New-Fixture {
    @{
        Metadata=@{Mode='Synthetic'; SelectedGroups=@('WorkbookExchange'); TenantId='invented'}
        Evidence=@(@{
            SourceId='exchange-connection-filter-policies'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-HostedConnectionFilterPolicy'; Status='Collected'; Count=2; MissingFields=@()
            PageCount=1; RequestCount=0; Reason='Synthetic fixture'; Notes=''
            Items=@(
                @{Identity='opaque-a'; Name='Other'; EnableSafeList=$true; IPAllowList=@('192.0.2.7'); IPBlockList=@()}
                @{Identity='opaque-b'; Name='dEfAuLt'; EnableSafeList=$false; IPAllowList=@(); IPBlockList=@()}
            )
        })
    }
}
function Add-CoverageSummary($report) {
    $report.Coverage=@(@{})
    foreach ($key in 'SourceId','Group','Provider','Status','Count','Reason','MissingFields','Notes') {
        $report.Coverage[0][$key]=$report.Evidence[0][$key]
    }
}
$cases=0
function Check-Fixture([string]$Label, $Report, [string]$Want165, [string]$Want169) {
    $json = ConvertTo-Json -InputObject $Report -Depth 30 -Compress
    $actual = @(Get-FlapjacksSyntheticConnectionFilterComparison -Result (ConvertFrom-FjcJson $json))
    if ($actual.Count -ne 2 -or ($actual.Row -join ',') -cne '165,169' -or
        $actual[0].Comparison -cne $Want165 -or $actual[1].Comparison -cne $Want169) {
        throw "Unexpected stored comparisons for $Label ($($actual.Comparison -join ','))."
    }
    foreach ($row in $actual) {
        if (($row.psobject.Properties.Name -join ',') -cne 'Row,Comparison,Reason' -or
            $row.Reason -cnotin @('ConnectionFixtureContractRefused','IncompleteSavedConnectionEvidence','ComparedSavedDefaultPolicy')) {
            throw "Unexpected output fields for $Label."
        }
    }
    $script:cases++
}

$yes='Matches'; $no='Differs'; $unknown='Unknown'
$r=New-Fixture; Check-Fixture 'named Default' $r $yes $yes
$r.Evidence[0].Items[1].EnableSafeList=$true
$r.Evidence[0].Items[1].IPAllowList=@('192.0.2.7')
Check-Fixture 'stored differences' $r $no $no
$r.Evidence[0].Items[1].EnableSafeList='false'; Check-Fixture 'textual Boolean' $r $unknown $no
$r.Evidence[0].Items[1].EnableSafeList=$false; $r.Evidence[0].Items[1].IPAllowList='192.0.2.7'
Check-Fixture 'scalar masquerading as a list' $r $yes $unknown
$r.Evidence[0].Items[1].IPAllowList=@('bad'); Check-Fixture 'malformed list member' $r $yes $unknown
$r.Evidence[0].Items[1].IPAllowList=$null; Check-Fixture 'unknown list' $r $yes $unknown
$r=New-Fixture; $r.Evidence[0].Items[0].Name='Default'; Check-Fixture 'duplicate Default' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Items[0].Identity='OPAQUE-B'; Check-Fixture 'duplicate ID' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Items[1].Name='Backup'; Check-Fixture 'Default missing' $r $unknown $unknown
$r=New-Fixture; $r.Evidence+=@($r.Evidence[0]); Check-Fixture 'duplicate source' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].MissingFields=@('Name'); Check-Fixture 'incomplete projection' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Status='Partial'; Check-Fixture 'partial read' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Status='NotSelected'; Check-Fixture 'skipped source' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Status='NotConnected'; Check-Fixture 'unavailable' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Target='Another-Command'; Check-Fixture 'wrong target' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.SelectedGroups=@(); Check-Fixture 'omitted group' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.Mode='Live'; Check-Fixture 'live input' $r $unknown $unknown
$r=New-Fixture; $r.Mode='Live'; Check-Fixture 'mode conflict' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.Remove('Mode'); $r.Mode='Synthetic'; Check-Fixture 'outer mode alone' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.Mode=@('Synthetic'); Check-Fixture 'ill-typed mode' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.OrganizationWideConfirmed=$true; Check-Fixture 'conflicting live confirmation' $r $unknown $unknown
$r=New-Fixture; $r.TenantId='different'; Check-Fixture 'conflicting report identity' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].Count=1; Check-Fixture 'count mismatch' $r $unknown $unknown
$r=New-Fixture; $r.Evidence[0].RequestCount=2; Check-Fixture 'conflicting counters' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; Check-Fixture 'consistent result plus summary' $r $yes $yes
$r.Coverage[0].Count='2'; Check-Fixture 'summary field type conflict' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; $r.Coverage[0].Status='Partial'; Check-Fixture 'contradictory summary' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; $r.Coverage[0].Remove('Provider'); Check-Fixture 'incomplete summary' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; $r.Coverage+=@($r.Coverage[0]); Check-Fixture 'duplicate coverage record' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; $r.Remove('Evidence'); Check-Fixture 'summary alone' $r $unknown $unknown
$r=New-Fixture; $r.Coverage=$r.Evidence; Check-Fixture 'two full sources' $r $unknown $unknown
$r.Remove('Evidence'); Check-Fixture 'saved full Coverage' $r $yes $yes
$r.Evidence=@(); Check-Fixture 'empty Evidence and full Coverage' $r $yes $yes
$r=New-Fixture; $r.Coverage=@(); Check-Fixture 'missing in-memory summary record' $r $unknown $unknown
$r=New-Fixture; $r.Coverage=@($null); Check-Fixture 'unidentifiable summary record' $r $unknown $unknown
$r.Coverage=$false; Check-Fixture 'non-array Coverage' $r $unknown $unknown
$r=New-Fixture; $r['mode']='Synthetic'; Check-Fixture 'outer mode case alias' $r $unknown $unknown
$r=New-Fixture; $r.Metadata.Remove('Mode'); $r.Metadata['mode']='Synthetic'; Check-Fixture 'inner mode case alias' $r $unknown $unknown
$r=New-Fixture; $r['coverage']=@(); Check-Fixture 'coverage case alias' $r $unknown $unknown
$r=New-Fixture; $r['Sources']=$r.Evidence; Check-Fixture 'additional evidence container' $r $unknown $unknown
$r=New-Fixture; $r.Metadata['Evidence']=$r.Evidence; Check-Fixture 'unexpected evidence inside metadata' $r $unknown $unknown
$r=New-Fixture; Add-CoverageSummary $r; $r.Coverage[0].Remove('Count'); $r.Coverage[0]['count']=2
Check-Fixture 'summary field case alias' $r $unknown $unknown
$pin='92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
$r=New-Fixture; $r.ReferenceWorkbookSha256=$pin; $r.Metadata.ReferenceWorkbookSha256=$pin
Check-Fixture 'corroborating optional pins' $r $yes $yes
$r.Metadata.ReferenceWorkbookSha256='incorrect'; Check-Fixture 'conflicting inner pin' $r $unknown $unknown
$r.Metadata.ReferenceWorkbookSha256=$pin; $r.ReferenceWorkbookSha256='incorrect'; Check-Fixture 'conflicting outer pin' $r $unknown $unknown
$r=New-Fixture; $r['referenceworkbooksha256']=$pin; Check-Fixture 'outer pin case alias' $r $unknown $unknown
$r=New-Fixture; $r.Metadata['referenceworkbooksha256']=$pin; Check-Fixture 'inner pin case alias' $r $unknown $unknown
Check-Fixture 'null report' $null $unknown $unknown
Check-Fixture 'wrong report type' 'invalid' $unknown $unknown

Import-Module (Join-Path $auditRoot 'M365SecurityAudit.psm1') -DisableNameChecking
foreach ($selected in @($true,$false)) {
    $groups=@()
    if ($selected) { $groups=@('WorkbookExchange') }
    $shipped=Invoke-M365SecurityAudit -Mode Synthetic -Include $groups
    $expected=if ($selected) { $yes } else { $unknown }
    Check-Fixture 'product synthetic in-memory report' $shipped $expected $expected
    $saved=@{Metadata=$shipped.Metadata; Coverage=$shipped.Evidence; Observations=$shipped.Observations}
    Check-Fixture 'product synthetic persisted report shape' $saved $expected $expected
}
Write-Output "PASS: $cases synthetic saved-report fixtures ($($cases*2) stored row comparisons)."
