#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lib = Join-Path (Split-Path $PSScriptRoot -Parent) 'workbook-fixture'
$helper = Join-Path $lib 'Compare-ConditionalAccessRiskFixtures.ps1'
$package = Join-Path $lib 'ca-risk'
if ((Get-FileHash -LiteralPath $helper).Hash -ine 'b7da9d2671c1ddf8667c36516ad73fab50da36e267a3c398b0b9db127eca4642') {
    throw 'Unreviewed Conditional Access fixture bridge bytes.'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Conditional Access fixture bridge did not parse.' }
$commands = @('UnassessedRiskPair','Get-FileHash','Get-FlapjacksRiskFixturePython','ConvertFrom-Json','ForEach-Object')
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($node in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true)) {
    if ($node.InvocationOperator -ne 'Unknown' -or $node.GetCommandName() -cnotin $commands) {
        throw 'Unreviewed command in the Conditional Access risk bridge.'
    }
    [void]$seen.Add($node.GetCommandName())
}
if (-not $seen.SetEquals([string[]]$commands)) { throw 'Conditional Access risk command inventory changed.' }
. $helper
$checks = 0
function Check([bool]$Ok, [string]$Label) {
    if (-not $Ok) { throw "Failed: $Label" }
    $script:checks++
}

$missingRuntime = & {
    function Get-FlapjacksRiskFixturePython { return }
    Get-FlapjacksSyntheticRiskComparison -FixtureId 'independent'
}
Check (($missingRuntime.Comparison -join ',') -ceq 'Unknown,Unknown' -and
    ($missingRuntime.Reason -join ',') -ceq 'RiskRuntimeUnavailable,RiskRuntimeUnavailable') 'no trusted Python available'
foreach ($value in $null,$true,123,@{SourceId='conditional-access'},@('independent'),'','../independent','Independent',"independent`n",'--stdin','not-registered') {
    $refused = @(Get-FlapjacksSyntheticRiskComparison -FixtureId $value)
    Check ($refused.Count -eq 2 -and ($refused.Comparison -join ',') -ceq 'Unknown,Unknown') 'invalid or unregistered selector'
    foreach ($row in $refused) {
        Check ($row.Reason -cin @('InvalidFixtureIdentifier','UnregisteredFixture') -and $row.WitnessOrdinals.Count -eq 0) 'invalid selector has no witness'
    }
}

# Check corruption using copies. Package problems are errors even if the runtime is absent.
$scratch = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'fj-risk-' + [guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory($scratch)
    $copy = [IO.Path]::Combine($scratch, [IO.Path]::GetFileName($helper))
    [IO.File]::Copy($helper, $copy)
    $testFiles = @('wave2/risk/risk.py','wave4/adapter/adapter.py','wave4/adapter/manifest.json','wave4/native/reports/independent/audit.json')
    foreach ($file in $testFiles) {
        $destination = [IO.Path]::Combine($scratch, 'ca-risk', $file)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        [IO.File]::Copy([IO.Path]::Combine($package, $file), $destination)
    }
    foreach ($file in $testFiles) {
        $destination = [IO.Path]::Combine($scratch, 'ca-risk', $file)
        [IO.File]::AppendAllText($destination, ' ')
        $failure = & {
            . $copy
            try { $null = Get-FlapjacksSyntheticRiskComparison -FixtureId 'independent' }
            catch { return $_.Exception.Message }
        }
        Check ($failure -cin @('Conditional Access risk fixture package integrity check failed.',
            'Conditional Access saved fixture integrity check failed.')) "tampered $file"
        [IO.File]::Copy([IO.Path]::Combine($package, $file), $destination, $true)
    }
} finally {
    if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
}

$registry = ConvertFrom-Json -AsHashtable -InputObject ([IO.File]::ReadAllText((Join-Path $package 'wave4/adapter/manifest.json')))
Check ($registry.Cases.Count -eq 53) 'registered saved reports'
$runtime = Get-FlapjacksRiskFixturePython
$exercised = 0
foreach ($id in $registry.Cases.Keys) {
    $rows = @(Get-FlapjacksSyntheticRiskComparison -FixtureId $id)
    Check (($rows.Row -join ',') -ceq '117,118') "$id row identity and order"
    if (-not $runtime) {
        Check (($rows.Comparison -join ',') -ceq 'Unknown,Unknown' -and
            ($rows.Reason -join ',') -ceq 'RiskRuntimeUnavailable,RiskRuntimeUnavailable') "$id unavailable"
        continue
    }
    $exercised++
    $expected = switch -CaseSensitive ($id) {
        { $_ -cin @('signin-only','snapshot-signin-only') } { 'Matches,Differs' }
        { $_ -cin @('user-only','snapshot-user-only') } { 'Differs,Matches' }
        { $_ -cin @('independent','snapshot-independent','equal-tick') } { 'Matches,Matches' }
        { $_ -cin @('conjoined','snapshot-conjoined','split-grant','reportonly-and-disabled','embedded-claims') } { 'Differs,Differs' }
        'witness-and-unknown' { 'Matches,Unknown' }
        default { 'Unknown,Unknown' }
    }
    Check (($rows.Comparison -join ',') -ceq $expected) "$id stored configuration comparisons"
    foreach ($row in $rows) {
        $ordinal = if ($row.Comparison -cne 'Matches') { '' }
            elseif ($row.Row -eq 118 -and $id -cin @('independent','snapshot-independent','equal-tick')) { '2' }
            else { '1' }
        Check ($row.WitnessOrdinals -is [array] -and ($row.WitnessOrdinals -join ',') -ceq $ordinal) "$id policy witness for $($row.Row)"
        if ($row.Comparison -ceq 'Matches') { Check ($row.Reason -ceq 'IndependentBlockWitness') "$id witness reason" }
    }
    if ($id -cin @('conjoined','snapshot-conjoined')) {
        Check (($rows.Reason -join ',') -ceq 'ConjoinedRiskAxes,ConjoinedRiskAxes') "$id conjunctive policy"
    }
    if ($id -cin @('wrong-target','wrong-provider','wrong-group')) {
        Check (($rows.Reason -join ',') -ceq 'NativeSourceIdentity,NativeSourceIdentity') "$id rejected source binding"
    }
}
[pscustomobject]@{Passed=$true; Checks=$checks; RegisteredCases=$registry.Cases.Count; EvaluatedCases=$exercised
    EvaluatedRowComparisons=2*$exercised; RuntimeAvailable=[bool]$runtime; CorruptionRefusals=$testFiles.Count
    SyntheticOnly=$true} | ConvertTo-Json
