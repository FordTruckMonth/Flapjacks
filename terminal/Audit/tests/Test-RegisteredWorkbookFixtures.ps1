#requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$entry = Join-Path $root 'Invoke-WorkbookFixtureReview.ps1'
$checks = 0
function Check([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Failed: $Label" }
    $script:checks++
}
function MustRefuse([scriptblock]$Action, [string]$Label) {
    $failed = $false
    try { $null = & $Action } catch { $failed = $true }
    Check $failed $Label
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Tests require a new output directory.' }
$rejectedPath = "$OutputDirectory-rejected"
MustRefuse { & $entry -OutputDirectory $rejectedPath } 'missing opt-in'
foreach ($inputName in 'FixtureJson','InputPath','WorkbookPath','TenantId','Mode') {
    $parameters = @{EnableFixtureReview=$true; OutputDirectory=$rejectedPath}
    $parameters[$inputName] = 'invented-placeholder'
    MustRefuse { & $entry @parameters } "unsupported parameter $inputName"
}
foreach ($value in @('../fixture.json','workbook.xlsx','audit.json','Live','{"Metadata":{"Mode":"Synthetic"}}','6')) {
    MustRefuse { & $entry -EnableFixtureReview -FixtureVersion $value -OutputDirectory $rejectedPath } 'invalid pack selection'
}
Check (-not (Test-Path -LiteralPath $rejectedPath)) 'no outputs for rejected input'
$null = New-Item -ItemType Directory -Path $OutputDirectory
$counts = @(7,11,14,17,20)
for ($index=0; $index -lt $counts.Length; $index++) {
    $version = [string]($index + 1)
    $where = Join-Path $OutputDirectory "v$version"
    $report = & $entry -EnableFixtureReview -FixtureVersion $version -OutputDirectory $where
    Check ($report.Rows.Count -eq $counts[$index]) "v$version exact count"
    Check ($report.Mode -ceq 'Synthetic' -and $null -eq $report.VerifiedCoverageNumerator -and $report.NewFullRowMappings -eq 0 -and $report.LiveValidations -eq 0) 'evidence limits'
    Check (@($report.Rows | Where-Object { $_.Status -cne 'Not assessed' -or $_.LiveVerified -or $_.FullRowMappingCredit -ne 0 }).Count -eq 0) 'all tenant claims unassessed'
    # Keep the original timestamp strings and compare JSON values without relying on key order.
    $saved = [Text.Json.Nodes.JsonNode]::Parse([IO.File]::ReadAllText((Join-Path $where 'review.json')))
    $returned = [Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -InputObject $report -Depth 32 -Compress))
    Check ([Text.Json.Nodes.JsonNode]::DeepEquals($saved, $returned)) 'JSON replay'
    foreach ($filename in 'checks.csv','Posture-Report.csv','Posture-Report.pdf','Posture-Report.xlsx') {
        Check ((Get-Item -LiteralPath (Join-Path $where $filename)).Length -gt 0) "export $filename"
    }
}
$default = & $entry -EnableFixtureReview
Check (($default.Rows.Row -join ',') -ceq '31,69,74,76,83,84,93,117,118,132,140,141,144,151,155,157,165,167,169,176') 'default v5 row identities'
$conjoined = & $entry -EnableFixtureReview -RiskFixture conjoined
$unknown = & $entry -EnableFixtureReview -RiskFixture missing-risk
$unregistered = & $entry -EnableFixtureReview -RiskFixture unregistered
$compared = @($conjoined.Rows | Where-Object Row -in 117,118)
# Python is optional. An unavailable interpreter must leave both the ordinary
# and conjoined risk observations unresolved.
if ($compared[0].Reason -ceq 'RiskRuntimeUnavailable') {
    Check (($compared.StoredComparison -join ',') -ceq 'Unknown,Unknown') 'optional runtime unavailable'
} else {
    Check (($compared.StoredComparison -join ',') -ceq 'Differs,Differs') 'registered conjoined risks'
}
Check ((($unknown.Rows | Where-Object Row -in 117,118).StoredComparison -join ',') -ceq 'Unknown,Unknown') 'registered unknown risks'
Check ((($unregistered.Rows | Where-Object Row -in 117,118).Reason -join ',') -ceq 'UnregisteredFixture,UnregisteredFixture') 'unregistered selection gives no comparison'
MustRefuse { & $entry -EnableFixtureReview -RiskFixture '../report.json' } 'a path cannot select a risk fixture'
MustRefuse { & $entry -EnableFixtureReview -FixtureVersion 3 -RiskFixture conjoined } 'older versions have no risk selector'
$module = Import-Module (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -PassThru -Scope Local
Check (($module.ExportedCommands.Keys -join ',') -ceq 'Invoke-RegisteredWorkbookFixtureReview') 'private raw evaluator'
# Change a copy of a packaged fixture. The digest check must run before interpretation or export.
$copy = Join-Path $OutputDirectory 'integrity-case'
$null = New-Item -ItemType Directory -Path "$copy/fixtures","$copy/workbook-fixture"
Copy-Item -LiteralPath $entry -Destination $copy
Copy-Item -LiteralPath (Join-Path $root 'workbook-fixture/WorkbookFixtureReview.psm1') -Destination "$copy/workbook-fixture"
[IO.File]::WriteAllText("$copy/fixtures/workbook-review-v5.synthetic.json", '{"Mode":"Synthetic","tenant":"invented"}')
$message = ''
try { $null = & "$copy/Invoke-WorkbookFixtureReview.ps1" -EnableFixtureReview -OutputDirectory $rejectedPath } catch { $message = $_.Exception.Message }
Check ($message -ceq 'Packaged synthetic fixture integrity check failed.' -and -not (Test-Path -LiteralPath $rejectedPath)) 'reject file substitution'
[pscustomobject]@{Passed=$true;Checks=$checks;Versions=$counts.Length} | ConvertTo-Json
