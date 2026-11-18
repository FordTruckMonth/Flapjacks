#requires -Version 7.4
param([string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'workbook-fixture/PassiveJson.ps1')
# The package entry accepts only registered fixtures. These negative tests inject
# invented variations into the unexported comparison function.
$reviewModule = Import-Module (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -Scope Local -PassThru
$entry = & $reviewModule { Get-Command Get-WorkbookFixtureComparison -CommandType Function }
$sample = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v2.synthetic.json')
$assertions = 0
function Check([bool]$Ok, [string]$Description) {
    if (-not $Ok) { throw "Failed: $Description" }
    $script:assertions++
}
function Run-Pack($Pack) {
    & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json -InputObject $Pack -Depth 48 -Compress)
}
function Assert-Results($Review, $Expected, [string]$Scenario) {
    $ids = @(31,69,74,93,132,140,144,165,167,169,176)
    Check ($Review.SchemaVersion -ceq 'FlapjacksWorkbookFixtureReview/2' -and ($Review.Rows.Row -join ',') -ceq ($ids -join ',')) "$Scenario exact row set"
    Check ($null -eq $Review.VerifiedCoverageNumerator -and $Review.NewFullRowMappings -eq 0 -and $Review.LiveValidations -eq 0) "$Scenario coverage"
    foreach ($row in $Review.Rows) {
        $want = if ($Expected.ContainsKey($row.Row)) { $Expected[$row.Row] } else { 'Matches' }
        Check ($row.StoredComparison -ceq $want) "$Scenario row $($row.Row) stored comparison"
        Check ($row.Status -ceq 'Not assessed' -and $row.FullRowMappingCredit -eq 0 -and -not $row.LiveVerified) "$Scenario row $($row.Row) assessment"
    }
}

$pack = ConvertFrom-FjcJson $sample
Assert-Results (Run-Pack $pack) @{} 'complete fixture'
$weak = ConvertFrom-FjcJson $sample
$weak.ProjectedCollaboration[1].Items[0].Remove('ExternalUserExpireInDays')
$weak.ProjectedCollaboration[1].Items[0].OverrideTenantExternalUserExpirationPolicy=$true
$weak.ProjectedCollaboration[1].Items[0].ExternalUserExpirationInDays=60
$weak.ProjectedCollaboration[2].Provenance.RequiredNativeCommand='Get-AntiPhishPolicy'
$weak.ConnectionFilter.Metadata.Mode='Live'
Assert-Results (Run-Pack $weak) @{140='Unknown';165='Unknown';169='Unknown';176='Unknown'} 'weak scope / mismatched command'

$mixed = ConvertFrom-FjcJson $sample
$mixed.ProjectedCollaboration[1].Items[0].ExternalUserExpirationRequired=$false
$mixed.ProjectedCollaboration[1].Items[0].Remove('ExternalUserExpireInDays')
$mixed.ConnectionFilter.Evidence[0].Items[1].EnableSafeList='false'
$mixed.ConnectionFilter.Evidence[0].Items[1].IPAllowList=@('192.0.2.23')
$mixed.ProjectedCollaboration[2].Items[0].Name='Invented renamed organization policy'
$mixedExpected = @{140='Differs';165='Unknown';169='Differs';176='Matches'}
Assert-Results (Run-Pack $mixed) $mixedExpected 'independent fields'

$partial = ConvertFrom-FjcJson $sample
$partial.ConnectionFilter.Evidence[0].Status='Partial'
$partial.ProjectedCollaboration[2].RequestCount=1
$partial.ProjectedCollaboration[1].Items[0].ExternalUserExpireInDays=731
Assert-Results (Run-Pack $partial) @{140='Unknown';165='Unknown';169='Unknown';176='Unknown'} 'incomplete or invalid'
$duplicate = ConvertFrom-FjcJson $sample
$duplicate.ConnectionFilter.Evidence[0].Items[0].Name='default'
$duplicate.ProjectedCollaboration+=@($duplicate.ProjectedCollaboration[2])
Assert-Results (Run-Pack $duplicate) @{165='Unknown';169='Unknown';176='Unknown'} 'ambiguous source or policy'

$invalidJson = $sample.Replace('"EnableSafeList": false','"EnableSafeList": false, "EnableSafeList": true')
Check ($invalidJson -cne $sample) 'conflicting duplicate key injected'
Assert-Results (& $entry -EnableFixtureReview -FixtureJson $invalidJson) @{165='Unknown';169='Unknown'} 'passive parser boundary'

$omitted = ConvertFrom-FjcJson $sample
$omitted.Remove('ConnectionFilter')
$omitted.ProjectedCollaboration = @($omitted.ProjectedCollaboration[0],$omitted.ProjectedCollaboration[1])
$omitted.ProjectedCollaboration[1].Items[0].Remove('ExternalUserExpirationRequired')
Assert-Results (Run-Pack $omitted) @{140='Unknown';165='Unknown';169='Unknown';176='Unknown'} 'older or absent evidence'

$legacy = ConvertFrom-FjcJson (Get-Content -LiteralPath (Join-Path $root 'fixtures/workbook-review.synthetic.json') -Raw)
$v1 = Run-Pack $legacy
Check ($v1.SchemaVersion -ceq 'FlapjacksWorkbookFixtureReview/1' -and ($v1.Rows.Row -join ',') -ceq '31,69,74,93,132,144,167') 'legacy result schema and IDs'
$legacy['ConnectionFilter']=$pack.ConnectionFilter
$refused=$false
try { $null=Run-Pack $legacy } catch { $refused=$true }
Check $refused 'legacy schema rejects v2 connection input'
if ($OutputDirectory) {
    $json=ConvertTo-Json -InputObject $mixed -Compress -Depth 48
    $exported=& $entry -EnableFixtureReview -FixtureJson $json -OutputDirectory $OutputDirectory
    Assert-Results $exported $mixedExpected 'rendered mixed fixture'
    $saved=Get-Content -Raw -LiteralPath (Join-Path $OutputDirectory 'review.json') | ConvertFrom-Json
    $csv=@(Import-Csv -LiteralPath (Join-Path $OutputDirectory 'checks.csv'))
    Check ($saved.Rows.Count -eq 11 -and $csv.Count -eq 11) 'detailed export cardinality'
    foreach ($index in 0..10) {
        $item=$exported.Rows[$index]
        foreach ($record in $saved.Rows[$index],$csv[$index]) {
            Check ([int]$record.Row -eq $item.Row -and $record.Status -ceq 'Not assessed' -and $record.StoredComparison -ceq $item.StoredComparison -and $record.Predicate -ceq $item.Predicate) 'detailed export matches evaluation'
        }
    }
}
[pscustomobject]@{Passed=$true;Checks=$assertions;SyntheticOnly=$true} | ConvertTo-Json
