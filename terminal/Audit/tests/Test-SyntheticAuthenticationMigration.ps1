#requires -Version 7.4
[CmdletBinding()]
param([switch]$RequireRuntime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '../workbook-fixture'
$helper = Join-Path $root 'Compare-AuthenticationMigration.ps1'
. $helper
$book = '92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
$cases = [ordered]@{
    'typed-disabled-report'='Matches'; 'typed-disabled-snapshot'='Matches'
    'typed-enabled-report'='Differs'; 'typed-enabled-snapshot'='Differs'
    'stock-report'='Unknown'; 'stock-snapshot'='Unknown'
    'boundary-review'='Matches'; 'stale-review'='Unknown'
    'mismatched-source'='Unknown'; 'mismatched-input'='Unknown'; 'mismatched-capture'='Unknown'
}
$checks = 0
function Check([bool]$Ok,[string]$Case) {
    if (-not $Ok) { throw "Failed migration review check $Case" }
    $script:checks++
}
$expectedReasons = @{
    'mismatched-capture'='CaptureBindingMismatch'; 'mismatched-input'='CaptureInputMismatch'
    'mismatched-source'='SourceBindingMismatch'; 'stale-review'='CaptureOutsideFreshnessWindow'
}
$package = Join-Path $root 'auth-migration'
$registry = ConvertFrom-FjcJson ([IO.File]::ReadAllText((Join-Path $package 'registry.json')))
Check ($registry.Cases.Count -eq $cases.Count) 'all registered cases covered'
foreach ($id in $null,123,'','../typed-disabled-report','Typed-disabled-report','unregistered',@('typed-disabled-report'),@{SourceId='authentication-methods-policy'}) {
    $r = Get-FlapjacksSyntheticMigrationComparison -FixtureId $id -ReferenceWorkbookSha256 $book
    Check ($r.Row -eq 151 -and $r.Comparison -ceq 'Unknown' -and $null -eq $r.Binding) 'unregistered or invalid input'
}
$r = Get-FlapjacksSyntheticMigrationComparison 'typed-disabled-report' ('0'*64)
Check ($r.Comparison -ceq 'Unknown' -and $null -eq $r.Binding -and $r.Reason -ceq 'ReferenceWorkbookMismatch') 'workbook reference'
$r = & {
    function Get-FlapjacksRiskFixturePython { return }
    Get-FlapjacksSyntheticMigrationComparison 'typed-disabled-report' $book
}
Check ($r.Comparison -ceq 'Unknown' -and $r.Reason -ceq 'MigrationRuntimeUnavailable') 'absent interpreter'
$python = Get-FlapjacksRiskFixturePython
if ($RequireRuntime -and -not $python) { throw 'Row 151 synthetic suite requires an existing supported Python.' }
$originChecks = 0
if ($python) {
    foreach ($id in $cases.Keys) {
        $r = Get-FlapjacksSyntheticMigrationComparison $id $book
        $entry = $registry.Cases[$id]
        Check ($r.Row -eq 151 -and $r.Comparison -ceq $cases[$id]) "$id comparison"
        Check ($r.Binding.Representation -ceq $entry.Representation -and $r.Binding.AuditSha256 -ceq $entry.AuditSha256 -and
            $r.Binding.ReferenceWorkbookSha256 -ceq $book) "$id original binding"
        Check ($r.Binding.StartedAtUtc -ceq $entry.StartedAtUtc -and $r.Binding.FinishedAtUtc -ceq $entry.FinishedAtUtc -and
            $r.Binding.ReviewAtUtc -ceq $entry.ReviewAtUtc -and $r.Binding.ClaimantCount -eq 1) "$id run and claimants"
        $bank = if ($id.EndsWith('snapshot')) { 'Evidence' } else { 'Coverage' }
        Check ($r.Binding.SourceArray -ceq $bank) "$id original projection"
        if ($expectedReasons.ContainsKey($id)) {
            Check ($r.Reason -ceq $expectedReasons[$id] -and $r.Binding.SelectionResult -ceq $r.Reason) "$id origin refusal"
        } else {
            Check ($r.Binding.SelectionResult -ceq 'Selected' -and $r.Binding.SelectedOrdinal -eq 8 -and
                $r.Binding.CollectedAtUtc -ceq $entry.CollectedAtUtc) "$id selected record"
        }
    }
    $stdout = & $python -I -S -B (Join-Path $PSScriptRoot 'test_authentication_migration_origin.py')
    if ($LASTEXITCODE -ne 0) { throw 'Row 151 origin mutation suite failed.' }
    $originChecks = (ConvertFrom-Json -InputObject $stdout).Passed
    Check ($originChecks -ge 70) 'whole-audit origin mutation suite'
}
# Change only private copies to exercise integrity checks before review.
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('fj-migration-'+[guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory($scratch)
    foreach ($file in 'Compare-AuthenticationMigration.ps1','Compare-ConditionalAccessRiskFixtures.ps1','PassiveJson.ps1') {
        [IO.File]::Copy((Join-Path $root $file),(Join-Path $scratch $file))
    }
    $files = @('registry.json','review.py','row151.py','audits/typed-disabled-report.json','inputs/typed-disabled.json')
    foreach ($file in $files) {
        $dest = Join-Path $scratch "auth-migration/$file"
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
        [IO.File]::Copy((Join-Path $package $file),$dest)
    }
    foreach ($file in $files) {
        $dest = Join-Path $scratch "auth-migration/$file"
        [IO.File]::AppendAllText($dest, ' ')
        $message = & {
            . (Join-Path $scratch 'Compare-AuthenticationMigration.ps1')
            try { $null = Get-FlapjacksSyntheticMigrationComparison 'typed-disabled-report' $book }
            catch { $_.Exception.Message }
        }
        Check ($message -cin @('Authentication migration fixture package integrity check failed.',
            'Authentication migration saved fixture integrity check failed.')) "tampered $file"
        [IO.File]::Copy((Join-Path $package $file),$dest,$true)
    }
} finally {
    if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch,$true) }
}
"PASS: $checks migration fixture assertions; $originChecks whole-audit origin mutation cases."
