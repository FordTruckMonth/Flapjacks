#requires -Version 7.4
# Standalone regression for registered synthetic Conditional Access fixtures.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = Join-Path $PSScriptRoot '../workbook-fixture/ca'
$manifest = Join-Path $package 'package-manifest.json'
$validator = Join-Path $package 'support/Integrity.ps1'
if ((Get-FileHash -LiteralPath $manifest).Hash -ine '5b62299b5a75ca97cf23e073a40ae8a711c229a5b8970f64ff5a12d1639d48d7' -or
    (Get-FileHash -LiteralPath $validator).Hash -ine 'ef973e6a35194b51d2d842fa5277c22588de54a1c740adaa961542717ec38555') {
    throw 'CA fixture package identity differs from the tested revision.'
}
. $validator
Assert-PortablePayload $package
$device = Import-Module (Join-Path $package 'adapters/row93/src/FlapjacksMandatoryDeviceCompliance.psm1') -PassThru -DisableNameChecking
$enrollment = Import-Module (Join-Path $package 'adapters/row167/EnrollmentMfa.psm1') -PassThru -DisableNameChecking

$matches = 'MatchesStoredConfiguration'
$differs = 'DoesNotMatchStoredConfiguration'
$deviceCases = [ordered]@{
    'and-single' = $matches
    'or-single-omitted-strength' = 'Unknown'
    'or-mfa-alternative' = $differs
    'report-only' = $differs
    'stale' = 'Unknown'
    'empty-source' = 'Unknown'
    'missing-source' = 'Unknown'
    'partial-source' = 'Unknown'
}
$enrollmentCases = [ordered]@{
    # Session alone, then session and mandatory built-in MFA on one policy.
    'and-mfa' = @($matches, $matches)
    'session-only' = @($matches, $differs)
    'split' = @($matches, $differs)
    'split-reversed' = @($matches, $differs)
    'or-missing-authenticationstrength' = @($matches, 'Unknown')
    'report-only' = @($differs, $differs)
    'excluded' = @('Unknown', 'Unknown')
    'partial' = @('Unknown', 'Unknown')
}

$observations = @(
    foreach ($id in $deviceCases.Keys) {
        $review = & $device.ExportedCommands['Get-FlapjacksMandatoryDeviceCompliance'] -FixtureId $id -EnableFixtureReview
        $row = $review.Rows[0]
        if ($row.PhysicalRow -ne 93 -or $row.StoredComparison -cne $deviceCases[$id] -or
            $row.WorkbookCriterion -cne 'Unknown' -or $row.Status -cne 'Not assessed' -or
            $row.EffectiveOutcomeVerified -or $row.DeviceComplianceVerified -or $row.PopulationResolved -or
            $row.FullRowMappingCredit -ne 0 -or $review.Metadata.NewLiveCoverage -ne 0 -or $review.Metadata.RealInputEnabled) {
            throw "Unexpected row 93 result for $id"
        }
        [ordered]@{ Row=93; Case=$id; Comparison=$row.StoredComparison; Status=$row.Status }
    }
    foreach ($id in $enrollmentCases.Keys) {
        $row = & $enrollment.ExportedCommands['Get-EnrollmentMfaComparison'] -FixtureId $id -EnableFixtureReview
        if ($row.PhysicalRow -ne 167 -or $row.SessionOnly -cne $enrollmentCases[$id][0] -or
            $row.SamePolicySessionAndMandatoryBuiltinMfa -cne $enrollmentCases[$id][1] -or
            $row.WorkbookCriterion -cne 'Unknown' -or $row.Status -cne 'Not assessed' -or
            $row.EffectiveOutcomeVerified -or $row.FullRowMappingCredit -ne 0 -or $row.LiveCoverageCredit -ne 0) {
            throw "Unexpected row 167 result for $id"
        }
        [ordered]@{ Row=167; Case=$id; Comparison=$row.SamePolicySessionAndMandatoryBuiltinMfa; SessionOnly=$row.SessionOnly; Status=$row.Status }
    }
)
[ordered]@{ Passed=$true; SyntheticOnly=$true; Cases=$observations } | ConvertTo-Json -Depth 4
