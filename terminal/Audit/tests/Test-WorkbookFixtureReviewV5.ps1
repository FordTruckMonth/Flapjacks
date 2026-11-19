#requires -Version 7.4
param([string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'workbook-fixture/PassiveJson.ps1')
# Internal tests supply invented variations to the module-private evaluator.
$reviewModule = Import-Module (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -Scope Local -PassThru
$entry = & $reviewModule { Get-Command Get-WorkbookFixtureComparison -CommandType Function }
$sample = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v5.synthetic.json')
$prior = Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/workbook-review-v4.synthetic.json')
$previous = & $entry -EnableFixtureReview -FixtureJson $prior
$checks = 0
function Check([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Failed: $Label" }
    $script:checks++
}
function Review($Pack) {
    & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json -InputObject $Pack -Depth 48 -Compress)
}
function Check-Report($Report, [string]$Forwarding, [string]$Reauth, [string]$Migration) {
    Check ($Report.SchemaVersion -ceq 'FlapjacksWorkbookFixtureReview/5' -and $Report.Mode -ceq 'Synthetic') 'synthetic schema'
    Check (($Report.Rows.Row -join ',') -ceq '31,69,74,76,83,84,93,117,118,132,140,141,144,151,155,157,165,167,169,176') 'v5 sorted rows'
    $old = @($Report.Rows | Where-Object { $_.Row -notin 76,141,151 })
    Check ((ConvertTo-Json -InputObject $old -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $previous.Rows -Depth 8 -Compress)) 'all seventeen prior records'
    Check ($null -eq $Report.VerifiedCoverageNumerator -and $Report.NewFullRowMappings -eq 0 -and $Report.LiveValidations -eq 0) 'coverage credits'
    $new = @($Report.Rows | Where-Object { $_.Row -in 76,141,151 })
    Check ($new[0].StoredComparison -ceq $Forwarding) 'workbook forwarding mode'
    Check ($new[1].StoredComparison -ceq $Reauth) 'stored verification-code reauthentication'
    if ($new[2].Reason -ceq 'MigrationRuntimeUnavailable') { $Migration = 'Unknown' }
    Check ($new[2].StoredComparison -ceq $Migration) 'saved method policy comparison'
    foreach ($r in $Report.Rows) {
        Check ($r.Status -ceq 'Not assessed' -and $r.FullRowMappingCredit -eq 0 -and $r.LiveVerified -is [bool] -and -not $r.LiveVerified) "tenant status $($r.Row)"
    }
    if ($new[2].StoredComparison -cne 'Unknown') {
        $b = $new[2].Binding
        Check ($b.AuditSha256 -cmatch '\A[a-f0-9]{64}\z' -and $b.ReferenceWorkbookSha256 -ceq $pack.ReferenceWorkbookSha256) 'original audit and workbook binding'
        Check ($b.SourceArray -cin @('Evidence','Coverage') -and $b.ClaimantCount -eq 1 -and $b.SelectedOrdinal -ge 1) 'unique source position'
        Check ([datetimeoffset]$b.StartedAtUtc -le [datetimeoffset]$b.CollectedAtUtc -and [datetimeoffset]$b.CollectedAtUtc -le [datetimeoffset]$b.FinishedAtUtc -and [datetimeoffset]$b.FinishedAtUtc -le [datetimeoffset]$b.ReviewAtUtc) 'capture lies inside the run'
        Check (([datetimeoffset]$b.ReviewAtUtc - [datetimeoffset]$b.CollectedAtUtc).Ticks -le [timespan]::TicksPerDay) '24-hour review window'
    }
}
$pack = ConvertFrom-FjcJson $sample
Check-Report (Review $pack) 'Matches' 'Matches' 'Matches'
$item = $pack.ProjectedCollaboration[1].Items[0]
$item.EmailAttestationReAuthDays = 16
$pack.OutboundForwarding.Coverage[0].Items[0].AutoForwardingMode = 'Off'
$pack.AuthenticationMigrationFixture = 'typed-enabled-snapshot'
Check-Report (Review $pack) 'Differs' 'Differs' 'Differs'
$item.EmailAttestationRequired = $false
$item.Remove('EmailAttestationReAuthDays')
$pack.OutboundForwarding.Coverage[0].Items[0].AutoForwardingMode = 'On'
$pack.AuthenticationMigrationFixture = 'stock-report'
Check-Report (Review $pack) 'Differs' 'Differs' 'Unknown'
$item.EmailAttestationRequired = $true
$pack.OutboundForwarding.Coverage[0].Status = 'Partial'
Check-Report (Review $pack) 'Unknown' 'Unknown' 'Unknown'
$pack = ConvertFrom-FjcJson $sample
foreach ($selector in 'stale-review','mismatched-input','mismatched-source','mismatched-capture','unregistered',$null,@{SourceId='authentication-methods-policy'}) {
    $pack.AuthenticationMigrationFixture = $selector
    Check-Report (Review $pack) 'Matches' 'Matches' 'Unknown'
}
foreach ($selector in 'typed-disabled-snapshot','boundary-review') {
    $pack.AuthenticationMigrationFixture = $selector
    Check-Report (Review $pack) 'Matches' 'Matches' 'Matches'
}
$pack.Remove('AuthenticationMigrationFixture')
$pack.Remove('OutboundForwarding')
$pack.ProjectedCollaboration[1].Items[0].Remove('EmailAttestationRequired')
Check-Report (Review $pack) 'Unknown' 'Unknown' 'Unknown'
foreach ($version in 1,2,3,4) {
    foreach ($key in 'OutboundForwarding','AuthenticationMigrationFixture') {
        $legacy = @{ SchemaVersion="FlapjacksWorkbookFixturePack/$version"; Mode='Synthetic'; ReferenceWorkbookSha256=$pack.ReferenceWorkbookSha256 }
        $legacy[$key] = $null
        $message = ''
        try { $null = Review $legacy } catch { $message = $_.Exception.Message }
        Check ($message -ceq 'Expected a synthetic fixture pack for the reviewed workbook.') "v$version refuses $key"
    }
}
if ($OutputDirectory) {
    $pack = ConvertFrom-FjcJson $sample
    $pack.OutboundForwarding.Coverage[0].Items[0].AutoForwardingMode = 'Off'
    $pack.ProjectedCollaboration[1].Items[0].EmailAttestationReAuthDays = '15'
    $pack.AuthenticationMigrationFixture = 'typed-disabled-snapshot'
    $rendered = & $entry -EnableFixtureReview -FixtureJson (ConvertTo-Json $pack -Depth 48 -Compress) -OutputDirectory $OutputDirectory
    Check-Report $rendered 'Differs' 'Unknown' 'Matches'
    $saved = ConvertFrom-FjcJson (Get-Content -Raw -LiteralPath (Join-Path $OutputDirectory 'review.json'))
    $csv = @(Import-Csv -LiteralPath (Join-Path $OutputDirectory 'checks.csv'))
    Check ($saved.Rows.Count -eq 20 -and $csv.Count -eq 20) 'all rows exported'
    for ($i=0; $i -lt $csv.Count; $i++) {
        Check ($csv[$i].StoredComparison -ceq $saved.Rows[$i].StoredComparison -and $csv[$i].Reason -ceq $saved.Rows[$i].Reason -and $csv[$i].Status -ceq 'Not assessed') 'CSV/JSON parity'
    }
}
[pscustomobject]@{Passed=$true; Checks=$checks; SyntheticOnly=$true} | ConvertTo-Json
