#requires -Version 7.4
. (Join-Path $PSScriptRoot 'Compare-ConditionalAccessRiskFixtures.ps1')
. (Join-Path $PSScriptRoot 'PassiveJson.ps1')

function Get-FlapjacksSyntheticMigrationComparison {
    param($FixtureId, [string]$ReferenceWorkbookSha256)

    function UnassessedMigration([string]$Reason) {
        [pscustomobject]@{ Row=151; Comparison='Unknown'; Reason=$Reason; Binding=$null }
    }
    if ($FixtureId -isnot [string] -or $FixtureId -cnotmatch '\A[a-z0-9-]{1,80}\z') {
        return UnassessedMigration 'InvalidFixtureIdentifier'
    }
    $root = Join-Path $PSScriptRoot 'auth-migration'
    $pins = [ordered]@{
        'registry.json'='ea08a41ed0dc1df73b40e65ea0ebee2931d2d608ea472939b913d127ff5395d8'
        'review.py'='889869a46d978b4cae944584c17eab066bd15f3d0370c4fbaadd57d0f387330d'
        'row151.py'='d68f41489be0bcc76aef8c8707adb69f6c4b8f0ef6fe6be4e81b3d5b2fc84d63'
    }
    foreach ($name in $pins.Keys) {
        $file = Join-Path $root $name
        if (-not [IO.File]::Exists($file) -or (Get-FileHash -LiteralPath $file).Hash -ine $pins[$name]) {
            throw 'Authentication migration fixture package integrity check failed.'
        }
    }
    $document = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText((Join-Path $root 'registry.json')))
    try {
        $registry = $document.RootElement
        if ($registry.GetProperty('ReferenceWorkbookSha256').GetString() -cne $ReferenceWorkbookSha256) {
            return UnassessedMigration 'ReferenceWorkbookMismatch'
        }
        $entry = [Text.Json.JsonElement]::new()
        if (-not $registry.GetProperty('Cases').TryGetProperty($FixtureId, [ref]$entry)) {
            return UnassessedMigration 'UnregisteredFixture'
        }
        # Audit and input paths come only from the pinned local registry. Detect
        # missing or corrupt originals even when no supported Python is present.
        foreach ($asset in 'Audit','Input') {
            $file = Join-Path $root $entry.GetProperty($asset+'Path').GetString()
            $digest = $entry.GetProperty($asset+'Sha256').GetString()
            if (-not [IO.File]::Exists($file) -or (Get-FileHash -LiteralPath $file).Hash -ine $digest) {
                throw 'Authentication migration saved fixture integrity check failed.'
            }
        }
    } finally { $document.Dispose() }

    $python = Get-FlapjacksRiskFixturePython
    if (-not $python) { return UnassessedMigration 'MigrationRuntimeUnavailable' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $python
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    $start.Environment.Clear()
    if ($IsWindows) { $start.Environment['SystemRoot'] = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows) }
    foreach ($argument in '-I','-S','-B',(Join-Path $root 'review.py'),$FixtureId) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0 -or $stderr.GetAwaiter().GetResult().Length -gt 0) {
            throw 'Authentication migration fixture evaluator failed.'
        }
        $row = ConvertFrom-FjcJson $stdout.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
    if ($row.Row -ne 151 -or $row.Comparison -cnotin @('Matches','Differs','Unknown') -or
        $row.Reason -cnotmatch '\A[A-Za-z][A-Za-z0-9-]{0,79}\z') { throw 'Unexpected migration comparison.' }
    [pscustomobject]$row
}
