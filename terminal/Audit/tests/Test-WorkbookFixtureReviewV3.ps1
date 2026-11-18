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
$sample = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v3.synthetic.json')
$prior = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v2.synthetic.json')
$previous = & $entry -EnableFixtureReview -FixtureJson $prior
$ids = '31,69,74,83,84,93,132,140,144,157,165,167,169,176'
$checks = 0
function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "Failed: $Description" }
    $script:checks++
}
function Review($Pack) {
    & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json -InputObject $Pack -Depth 48 -Compress)
}
function Confirm-Review($Report, [string[]]$Expected, [string]$Scenario) {
    Check ($Report.SchemaVersion -ceq 'FlapjacksWorkbookFixtureReview/3' -and ($Report.Rows.Row -join ',') -ceq $ids) "$Scenario schema and row set"
    Check ($null -eq $Report.VerifiedCoverageNumerator -and $Report.NewFullRowMappings -eq 0 -and $Report.LiveValidations -eq 0) "$Scenario assessment totals"
    $newRows = @($Report.Rows | Where-Object { $_.Row -in @(83,84,157) })
    Check (($newRows.StoredComparison -join ',') -ceq ($Expected -join ',')) "$Scenario stored Booleans"
    foreach ($row in $newRows) {
        Check ($row.Status -ceq 'Not assessed' -and $row.FullRowMappingCredit -eq 0 -and $row.LiveVerified -is [bool] -and -not $row.LiveVerified) "$Scenario tenant status row $($row.Row)"
    }
    $oldRows = @($Report.Rows | Where-Object { $_.Row -notin @(83,84,157) })
    Check ((ConvertTo-Json -Compress -InputObject $oldRows) -ceq (ConvertTo-Json -Compress -InputObject $previous.Rows)) "$Scenario prior eleven complete row records"
}
$positive = ConvertFrom-FjcJson $sample
Confirm-Review (Review $positive) @('Matches','Matches','Matches') 'positive'
$mixed = ConvertFrom-FjcJson $sample
$mixed.MailOrganizationSettings.Coverage[0].Items[0].EnableATPForSPOTeamsODB = $false
$mixed.MailOrganizationSettings.Coverage[0].Items[0].Remove('EnableSafeDocs')
$mixed.MailOrganizationSettings.Coverage[0].Items[0].AllowSafeDocsOpen = $true
$mixed.LockboxOrganizationSettings.Coverage[0].Items[0].CustomerLockboxEnabled = $false
Confirm-Review (Review $mixed) @('Differs','Unknown','Differs') 'individual switches'
$wrongType = ConvertFrom-FjcJson $sample
$wrongType.MailOrganizationSettings.Coverage[0].Items[0].EnableATPForSPOTeamsODB = 1
$wrongType.MailOrganizationSettings.Coverage[0].Items[0].EnableSafeDocs = $false
$wrongType.LockboxOrganizationSettings.Coverage[0].Items[0].CustomerLockboxEnabled = 'true'
Confirm-Review (Review $wrongType) @('Unknown','Differs','Unknown') 'typed evidence'

$weak = ConvertFrom-FjcJson $sample
$weak.MailOrganizationSettings.Coverage[0].Status = 'Partial'
$weak.LockboxOrganizationSettings.Coverage[0].Items[0].Identity = ' '
Confirm-Review (Review $weak) @('Unknown','Unknown','Unknown') 'incomplete or unidentifiable singleton'
$weak = ConvertFrom-FjcJson $sample
$weak.LockboxOrganizationSettings.Coverage += @($weak.LockboxOrganizationSettings.Coverage[0])
$weak.MailOrganizationSettings.Coverage[0].Target = 'Get-OrganizationConfig'
Confirm-Review (Review $weak) @('Unknown','Unknown','Unknown') 'duplicate or rebound source'
$missing = ConvertFrom-FjcJson $sample
$missing.Remove('MailOrganizationSettings')
$missing.Remove('LockboxOrganizationSettings')
Confirm-Review (Review $missing) @('Unknown','Unknown','Unknown') 'omitted evidence'
foreach ($field in 'EnableSafeDocs','CustomerLockboxEnabled') {
    $needle = '"' + $field + '": true'
    $ambiguous = $sample.Replace($needle, ($needle + ', "' + $field + '": false'))
    Check ($ambiguous -cne $sample) "duplicate injection $field"
    $expected = if ($field -ceq 'EnableSafeDocs') { 'Unknown','Unknown','Matches' } else { 'Matches','Matches','Unknown' }
    Confirm-Review (& $entry -EnableFixtureReview -FixtureJson $ambiguous) $expected 'ambiguous raw JSON envelope'
}
foreach ($version in 1,2) {
    foreach ($key in 'MailOrganizationSettings','LockboxOrganizationSettings') {
        $legacy = ConvertFrom-FjcJson $prior
        $legacy.SchemaVersion = "FlapjacksWorkbookFixturePack/$version"
        if ($version -eq 1) { $legacy.Remove('ConnectionFilter') }
        $legacy[$key] = $positive[$key]
        $message = ''
        try { $null = Review $legacy } catch { $message = $_.Exception.Message }
        Check ($message -ceq 'Expected a synthetic fixture pack for the reviewed workbook.') "v$version rejects $key"
    }
}
if ($OutputDirectory) {
    $json = ConvertTo-Json -InputObject $mixed -Depth 48 -Compress
    $rendered = & $entry -EnableFixtureReview -FixtureJson $json -OutputDirectory $OutputDirectory
    Confirm-Review $rendered @('Differs','Unknown','Differs') 'exported mixed'
    $saved = ConvertFrom-FjcJson (Get-Content -Raw -LiteralPath (Join-Path $OutputDirectory 'review.json'))
    $csv = @(Import-Csv -LiteralPath (Join-Path $OutputDirectory 'checks.csv'))
    Check ($saved.Rows.Count -eq 14 -and $csv.Count -eq 14) 'exported cardinality'
    for ($i=0; $i -lt $rendered.Rows.Count; $i++) {
        foreach ($record in $saved.Rows[$i],$csv[$i]) {
            Check ([int]$record.Row -eq $rendered.Rows[$i].Row -and $record.StoredComparison -ceq $rendered.Rows[$i].StoredComparison -and $record.Status -ceq 'Not assessed') 'serialized comparison and tenant status'
        }
    }
}
[pscustomobject]@{Passed=$true; Checks=$checks; SyntheticOnly=$true} | ConvertTo-Json
