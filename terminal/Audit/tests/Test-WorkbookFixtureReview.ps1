#requires -Version 7.4
[CmdletBinding()]
param([string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'workbook-fixture/PassiveJson.ps1')
# The package entry accepts only registered fixtures. These negative tests inject
# invented variations into the unexported comparison function.
$reviewModule = Import-Module (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -Scope Local -PassThru
$entry = & $reviewModule { Get-Command Get-WorkbookFixtureComparison -CommandType Function }
$sample = Get-Content -LiteralPath (Join-Path $root 'fixtures/workbook-review.synthetic.json') -Raw
$count = 0
function Check([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Failed: $Label" }
    $script:count++
}
function Run-Pack($Pack) {
    & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json -InputObject $Pack -Depth 48 -Compress)
}
function Check-Rows($Review, [string[]]$Expected) {
    Check (($Review.Rows.Row -join ',') -ceq '31,69,74,93,132,144,167') 'row identities'
    Check ($null -eq $Review.VerifiedCoverageNumerator -and $Review.LiveValidations -eq 0 -and $Review.NewFullRowMappings -eq 0) 'review boundaries'
    for ($i=0; $i -lt $Expected.Count; $i++) {
        $row=$Review.Rows[$i]
        Check ($row.StoredComparison -ceq $Expected[$i]) "row $($row.Row) comparison"
        Check ($row.Status -ceq 'Not assessed' -and $row.LiveVerified -eq $false -and $row.FullRowMappingCredit -eq 0) "row $($row.Row) boundaries"
    }
}

$complete = ConvertFrom-FjcJson $sample
$review = Run-Pack $complete
Check-Rows $review (@('Matches') * 7)
$empty = [ordered]@{}
foreach ($key in 'SchemaVersion','Mode','ReferenceWorkbookSha256') { $empty[$key]=$complete[$key] }
Check-Rows (Run-Pack $empty) (@('Unknown') * 7)

$different = ConvertFrom-FjcJson $sample
$different.Thresholds.Evidence[0].Items[0].PhishThresholdLevel=1
$different.Thresholds.Evidence[1].Items[0].BulkThreshold=7
$different.Allowlists.Evidence[0].Items[0].AllowedSenders=@('made-up@example.invalid')
$different.Row93Fixture='or-mfa-alternative'
$different.Row167Fixture='split-reversed'
$different.ProjectedCollaboration[0].Items[0].AllowEmailIntoChannel=$true
$different.ProjectedCollaboration[1].Items[0].DisallowInfectedFileDownload=$false
Check-Rows (Run-Pack $different) (@('Differs') * 7)

$weak = ConvertFrom-FjcJson $sample
$weak.Thresholds.Evidence[0].Status='NotSelected'
$weak.Thresholds.Evidence[1].Items[0].BulkThreshold='6'
$weak.Allowlists.Evidence[0].Items[0].Remove('AllowedSenderDomains')
$weak.Row93Fixture='or-single-omitted-strength'
$weak.Row167Fixture='or-missing-authenticationstrength'
$weak.ProjectedCollaboration[0].SnapshotComplete=$false
$weak.ProjectedCollaboration[1].MissingFields=@('DisallowInfectedFileDownload')
Check-Rows (Run-Pack $weak) (@('Unknown') * 7)

$mixed = ConvertFrom-FjcJson $sample
$mixed.Thresholds.Evidence[1].RunId='synthetic-different-run'
$mixed.Allowlists.Metadata.Mode='Live'
$mixed.Row93Fixture='cross-tenant'
$mixed.Row167Fixture='unregistered'
$mixed.ProjectedCollaboration+=@($mixed.ProjectedCollaboration[0])
Check-Rows (Run-Pack $mixed) @('Matches','Unknown','Unknown','Unknown','Unknown','Matches','Unknown')

$invalid = ConvertFrom-FjcJson $sample
$invalid.Row93Fixture=@('and-single')
$invalid.Row167Fixture='../fixture'
$invalid.ProjectedCollaboration=@{}
$invalid.Allowlists=@{}
$invalid.Thresholds=@{}
Check-Rows (Run-Pack $invalid) (@('Unknown') * 7)

$duplicateField = $sample.Replace('"PhishThresholdLevel": 2', '"PhishThresholdLevel": 2, "PhishThresholdLevel": 1')
Check-Rows (& $entry -EnableFixtureReview -FixtureJson $duplicateField) @('Unknown','Unknown','Matches','Matches','Matches','Matches','Matches')
$nonInteger = $sample.Replace('"PhishThresholdLevel": 2', '"PhishThresholdLevel": 2e0')
Check-Rows (& $entry -EnableFixtureReview -FixtureJson $nonInteger) @('Unknown','Matches','Matches','Matches','Matches','Matches','Matches')
$badProjection = $sample.Replace('"AllowEmailIntoChannel": false','"AllowEmailIntoChannel": false, "AllowEmailIntoChannel": true')
Check-Rows (& $entry -EnableFixtureReview -FixtureJson $badProjection) @('Matches','Matches','Matches','Matches','Unknown','Matches','Matches')
foreach ($change in @(@{Key='Mode';Value='Live'},@{Key='Mode';Value=@('Synthetic')},@{Key='ReferenceWorkbookSha256';Value='unset'},@{Key='UnknownField';Value=1})) {
    $bad = ConvertFrom-FjcJson $sample
    $bad[$change.Key]=$change.Value
    $refused=$false
    try { $null=Run-Pack $bad } catch { $refused=$true }
    Check $refused 'invalid fixture pack refused'
}
$refused=$false
try { $null=& $entry -FixtureJson $sample } catch { $refused=$true }
Check $refused 'explicit opt-in'

if ($OutputDirectory) {
    $json=ConvertTo-Json -InputObject $mixed -Compress -Depth 48
    $rendered=& $entry -EnableFixtureReview -FixtureJson $json -OutputDirectory $OutputDirectory
    $saved=Get-Content -LiteralPath (Join-Path $OutputDirectory 'review.json') -Raw | ConvertFrom-Json
    $csv=@(Import-Csv -LiteralPath (Join-Path $OutputDirectory 'checks.csv'))
    Check ($csv.Count -eq 7 -and $saved.Rows.Count -eq 7) 'export cardinality'
    foreach ($index in 0..6) {
        Check ($csv[$index].StoredComparison -ceq $rendered.Rows[$index].StoredComparison -and $csv[$index].Status -ceq 'Not assessed') 'CSV parity'
        Check ($saved.Rows[$index].StoredComparison -ceq $rendered.Rows[$index].StoredComparison -and $saved.Rows[$index].Status -ceq 'Not assessed') 'JSON parity'
    }
    $refused=$false
    try { $null=& $entry -EnableFixtureReview -FixtureJson $sample -OutputDirectory $OutputDirectory } catch { $refused=$true }
    Check $refused 'existing output refused'
}
[pscustomobject]@{Passed=$true;Checks=$count;SyntheticOnly=$true} | ConvertTo-Json
