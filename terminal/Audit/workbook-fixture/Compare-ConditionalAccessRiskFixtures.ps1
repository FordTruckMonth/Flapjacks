#requires -Version 7.4
function Get-FlapjacksRiskFixturePython {
    # Check existing system installations directly. In particular, do not launch
    # the macOS developer-tools installer shim or search the caller's PATH.
    if ($IsMacOS) {
        $paths = @('/Library/Developer/CommandLineTools/usr/bin/python3',
            '/Applications/Xcode.app/Contents/Developer/usr/bin/python3')
    } elseif ($IsLinux) {
        $paths = @('/usr/bin/python3')
    } elseif ($IsWindows) {
        $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        if (-not $programFiles) { return }
        $paths = foreach ($minor in 14,13,12,11,10,9) {
            [IO.Path]::Combine($programFiles, "Python3$minor", 'python.exe')
        }
    } else { return }
    foreach ($path in $paths) {
        if ([IO.File]::Exists($path)) { return $path }
    }
}

function Get-FlapjacksSyntheticRiskComparison {
    param($FixtureId)

    function UnassessedRiskPair([string]$Reason) {
        foreach ($row in 117,118) {
            [pscustomobject]@{Row=$row; Comparison='Unknown'; Reason=$Reason; WitnessOrdinals=@()}
        }
    }
    if ($FixtureId -isnot [string] -or $FixtureId -cnotmatch '\A[a-z0-9-]{1,80}\z') {
        return UnassessedRiskPair 'InvalidFixtureIdentifier'
    }

    $package = [IO.Path]::Combine($PSScriptRoot, 'ca-risk')
    $pins = [ordered]@{
        'wave4/adapter/adapter.py' = 'b16e9c642cafea4d5ed04b2cf3ae58ac390584745b036c4889acec1f045ea078'
        'wave2/risk/risk.py' = 'a8cf5fe09108a3f3b481fd3785a7cc5ab81159ab7aeabb35ba2a26f154acd5f9'
        'wave4/adapter/manifest.json' = 'b1ef9b2cc6f109fdb4401b8a44654c824ca62a8b8f72142e276c6fc737e7cc8c'
    }
    foreach ($relative in $pins.Keys) {
        $file = [IO.Path]::Combine($package, $relative)
        if (-not [IO.File]::Exists($file) -or (Get-FileHash -LiteralPath $file).Hash -ine $pins[$relative]) {
            throw 'Conditional Access risk fixture package integrity check failed.'
        }
    }
    $manifestPath = [IO.Path]::Combine($package, 'wave4/adapter/manifest.json')
    $manifest = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($manifestPath))
    try {
        $item = [Text.Json.JsonElement]::new()
        if (-not $manifest.RootElement.GetProperty('Cases').TryGetProperty($FixtureId, [ref]$item)) {
            return UnassessedRiskPair 'UnregisteredFixture'
        }
        # Only the pinned registry selects files. No paths are accepted from the caller.
        $inputPath = [IO.Path]::Combine($package, 'wave4', $item.GetProperty('Path').GetString())
        if (-not [IO.File]::Exists($inputPath) -or (Get-FileHash -LiteralPath $inputPath).Hash -ine $item.GetProperty('FileSha256').GetString()) {
            throw 'Conditional Access saved fixture integrity check failed.'
        }
    } finally { $manifest.Dispose() }

    $python = Get-FlapjacksRiskFixturePython
    if (-not $python) { return UnassessedRiskPair 'RiskRuntimeUnavailable' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $python
    $start.UseShellExecute = $false
    $start.WorkingDirectory = $package
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment.Clear()
    if ($IsWindows) { $start.Environment['SystemRoot'] = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows) }
    $adapter = [IO.Path]::Combine($package, 'wave4/adapter/adapter.py')
    foreach ($argument in '-I','-S','-B',$adapter,$FixtureId) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0 -or $stderr.GetAwaiter().GetResult().Length -gt 0) {
            throw 'Conditional Access risk fixture evaluator failed.'
        }
        $result = ConvertFrom-Json -AsHashtable -InputObject $stdout.GetAwaiter().GetResult()
    } finally { $process.Dispose() }

    if ($result.Fixture -cne $FixtureId -or $result.SyntheticOnly -ne $true -or
        ($result.Checks.PhysicalRow -join ',') -cne '117,118') { throw 'Unexpected Conditional Access risk result.' }
    foreach ($check in $result.Checks) {
        if ($check.Status -cne 'Not assessed' -or $check.FullRowMappingCredit -ne 0 -or
            $check.LiveCredit -ne 0 -or $check.LiveVerified -ne $false -or $check.EffectiveOutcomeVerified -ne $false) {
            throw 'Unexpected Conditional Access risk assessment.'
        }
        $ordinals = @($check.WitnessOrdinals)
        $policyReasons = @($check.PolicyResults | ForEach-Object { $_.Reason })
        switch -CaseSensitive ($check.StoredComparison) {
            'StoredPatternObserved' {
                $comparison = 'Matches'
                $reason = 'IndependentBlockWitness'
            }
            'StoredPatternDifferent' {
                $comparison = 'Differs'
                $reason = if ($policyReasons -clike 'ConjoinedRiskAxis.*') { 'ConjoinedRiskAxes' } else { 'NoIndependentBlockWitness' }
            }
            'Unknown' {
                $comparison = 'Unknown'
                $reason = if ($check.SourceProblem) { $check.SourceProblem } else { 'InsufficientPolicyEvidence' }
            }
            default { throw 'Unexpected Conditional Access risk comparison.' }
        }
        [pscustomobject]@{Row=$check.PhysicalRow; Comparison=$comparison; Reason=$reason; WitnessOrdinals=$ordinals}
    }
}
