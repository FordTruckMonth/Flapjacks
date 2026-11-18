#requires -Version 7.4
param([string]$OutputDirectory, [switch]$RequireRiskRuntime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'workbook-fixture/PassiveJson.ps1')
# The package entry accepts only registered fixtures. These negative tests inject
# invented variations into the unexported comparison function.
$reviewModule = Import-Module (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -Scope Local -PassThru
$entry = & $reviewModule { Get-Command Get-WorkbookFixtureComparison -CommandType Function }
$sample = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v4.synthetic.json')
$prior = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v3.synthetic.json')
$previous = & $entry -EnableFixtureReview -FixtureJson $prior
$expectedIds = '31,69,74,83,84,93,117,118,132,140,144,155,157,165,167,169,176'
$checks = 0
function Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "Failed: $Description" }
    $script:checks++
}
function Review($Pack) {
    & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json -InputObject $Pack -Depth 48 -Compress)
}
function Check-Review($Report, $SignIn, $UserRisk, $DefaultRole, $SignInWitness, $UserWitness) {
    Check ($Report.SchemaVersion -ceq 'FlapjacksWorkbookFixtureReview/4' -and ($Report.Rows.Row -join ',') -ceq $expectedIds) 'v4 exact row set'
    $old = @($Report.Rows | Where-Object { $_.Row -notin 117,118,155 })
    Check ((ConvertTo-Json -InputObject $old -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $previous.Rows -Depth 8 -Compress)) 'all fourteen prior row records'
    Check ($null -eq $Report.VerifiedCoverageNumerator -and $Report.NewFullRowMappings -eq 0 -and $Report.LiveValidations -eq 0) 'coverage limits'
    foreach ($row in $Report.Rows) {
        Check ($row.Status -ceq 'Not assessed' -and $row.FullRowMappingCredit -eq 0 -and $row.LiveVerified -is [bool] -and -not $row.LiveVerified) "tenant outcome for $($row.Row)"
    }
    $row117, $row118, $row155 = @($Report.Rows | Where-Object { $_.Row -in 117,118,155 })
    Check ($row155.StoredComparison -ceq $DefaultRole) 'default-role comparison'
    if ($row117.Reason -ceq 'RiskRuntimeUnavailable' -or $row118.Reason -ceq 'RiskRuntimeUnavailable') {
        Check (-not $RequireRiskRuntime -and $row117.Reason -ceq $row118.Reason) 'optional risk runtime availability'
        $SignIn = 'Unknown'; $UserRisk = 'Unknown'; $SignInWitness = ''; $UserWitness = ''
    }
    Check ($row117.StoredComparison -ceq $SignIn -and $row118.StoredComparison -ceq $UserRisk) 'separate risk comparisons'
    Check ($row117.WitnessOrdinals -is [array] -and ($row117.WitnessOrdinals -join ',') -ceq $SignInWitness) 'sign-in risk witnesses'
    Check ($row118.WitnessOrdinals -is [array] -and ($row118.WitnessOrdinals -join ',') -ceq $UserWitness) 'user risk witnesses'
}
$pack = ConvertFrom-FjcJson $sample
Check-Review (Review $pack) 'Matches' 'Matches' 'Matches' '1' '2'
foreach ($form in '','snapshot-') {
    $pack.ConditionalAccessRiskFixture = $form + 'conjoined'
    Check-Review (Review $pack) 'Differs' 'Differs' 'Matches' '' ''
    $pack.ConditionalAccessRiskFixture = $form + 'signin-only'
    Check-Review (Review $pack) 'Matches' 'Differs' 'Matches' '1' ''
    $pack.ConditionalAccessRiskFixture = $form + 'user-only'
    Check-Review (Review $pack) 'Differs' 'Matches' 'Matches' '' '1'
    $pack.ConditionalAccessRiskFixture = $form + 'missing-risk'
    Check-Review (Review $pack) 'Unknown' 'Unknown' 'Matches' '' ''
}
foreach ($selector in 'wrong-target','contradictory-summary','summary-only','native-sparse','unregistered','../outside',$null,@{id='independent'}) {
    $pack.ConditionalAccessRiskFixture = $selector
    Check-Review (Review $pack) 'Unknown' 'Unknown' 'Matches' '' ''
}
$pack = ConvertFrom-FjcJson $sample
$perm = $pack.AuthorizationPolicy.Coverage[0].Items[0].defaultUserRolePermissions
$perm.allowedToCreateSecurityGroups = $true
Check-Review (Review $pack) 'Matches' 'Matches' 'Differs' '1' '2'
$perm.allowedToCreateSecurityGroups = 'false'
Check-Review (Review $pack) 'Matches' 'Matches' 'Unknown' '1' '2'
$pack.AuthorizationPolicy.Coverage[0].Target = '/groups'
Check-Review (Review $pack) 'Matches' 'Matches' 'Unknown' '1' '2'
$duplicate = $sample.Replace('"allowedToCreateSecurityGroups": false','"allowedToCreateSecurityGroups": true, "allowedToCreateSecurityGroups": false')
Check ($duplicate -cne $sample) 'duplicate field injected'
Check-Review (& $entry -EnableFixtureReview -FixtureJson $duplicate) 'Matches' 'Matches' 'Unknown' '1' '2'
$pack.Remove('AuthorizationPolicy')
$pack.Remove('ConditionalAccessRiskFixture')
Check-Review (Review $pack) 'Unknown' 'Unknown' 'Unknown' '' ''
foreach ($version in 1,2,3) {
    foreach ($key in 'AuthorizationPolicy','ConditionalAccessRiskFixture') {
        $legacy = @{ SchemaVersion="FlapjacksWorkbookFixturePack/$version"; Mode='Synthetic'; ReferenceWorkbookSha256=$pack.ReferenceWorkbookSha256 }
        $legacy[$key] = $null
        $message = ''
        try { $null = Review $legacy } catch { $message = $_.Exception.Message }
        Check ($message -ceq 'Expected a synthetic fixture pack for the reviewed workbook.') "v$version excludes $key"
    }
}
if ($OutputDirectory) {
    $pack = ConvertFrom-FjcJson $sample
    $pack.ConditionalAccessRiskFixture = 'snapshot-independent'
    $pack.AuthorizationPolicy.Coverage[0].Items[0].defaultUserRolePermissions.allowedToCreateSecurityGroups = $true
    $rendered = & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json $pack -Depth 48 -Compress) -OutputDirectory $OutputDirectory
    Check-Review $rendered 'Matches' 'Matches' 'Differs' '1' '2'
    $saved = ConvertFrom-FjcJson (Get-Content -Raw -LiteralPath (Join-Path $OutputDirectory 'review.json'))
    $csv = @(Import-Csv -LiteralPath (Join-Path $OutputDirectory 'checks.csv'))
    Check ($saved.Rows.Count -eq 17 -and $csv.Count -eq 17) 'saved cardinality'
    for ($i = 0; $i -lt $csv.Count; $i++) {
        Check ($csv[$i].StoredComparison -ceq $saved.Rows[$i].StoredComparison -and $csv[$i].Reason -ceq $saved.Rows[$i].Reason -and $csv[$i].Status -ceq 'Not assessed') 'CSV and JSON findings'
    }
}
[pscustomobject]@{Passed=$true; Checks=$checks; SyntheticOnly=$true} | ConvertTo-Json
