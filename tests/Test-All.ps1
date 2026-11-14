#requires -Version 7.4
param([string]$EvidenceRoot)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if(-not $EvidenceRoot){$EvidenceRoot=Join-Path $root ('test-results/'+[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))}
[void][IO.Directory]::CreateDirectory($EvidenceRoot)
$parseErrors=@(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1') -and $_.FullName -notmatch '[/\\]provenance[/\\]'} | ForEach-Object {
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
    foreach($e in $errors){[pscustomobject]@{File=$_.FullName;Line=$e.Extent.StartLineNumber;Message=$e.Message}}
})
if($parseErrors.Count){$parseErrors | ConvertTo-Json | Set-Content (Join-Path $EvidenceRoot 'parse-errors.json');throw 'Native parser errors'}
$exe=(Get-Process -Id $PID).Path
foreach($test in @('Test-UtcQueryWindow.ps1','Test-UtcQueryWindow.EdgeCases.ps1')){
    $out=& $exe -NoLogo -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot $test) 2>&1
    $out | Set-Content -LiteralPath (Join-Path $EvidenceRoot ($test+'.txt'))
    if($LASTEXITCODE -ne 0){throw "Failed $test"}
}
$out=& $exe -NoLogo -NoProfile -NonInteractive -File "$PSScriptRoot/Test-Pager.Operator.ps1" -PagerPath "$root/Invoke-SyntheticTracePager.ps1" 2>&1
$out | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'pager.json')
if($LASTEXITCODE -ne 0){throw 'Pager evaluator failed to run'}
$pager=($out -join "`n") | ConvertFrom-Json -Depth 100
if($pager.Failed -ne 0){throw "Pager failures: $($pager.Failed)"}
$out=& $exe -NoLogo -NoProfile -NonInteractive -File "$PSScriptRoot/Test-Investigator.ps1" -ResultsPath (Join-Path $EvidenceRoot 'investigator.json') 2>&1
$out | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'investigator.stdout.txt')
if($LASTEXITCODE -ne 0){throw 'Investigator fixture failure; see evidence'}
$tests=Get-Content -LiteralPath (Join-Path $EvidenceRoot 'investigator.json') -Raw | ConvertFrom-Json -Depth 100
$summary=[pscustomobject]@{Passed=$true;PowerShell=$PSVersionTable.PSVersion.ToString();NativeParser='Passed';OriginalHelperScenarios=9;OriginalHelperAssertions=21;PagerCases=$pager.Total;InvestigatorChecks=$tests.Total;CasePath=$tests.CasePath;EvidenceRoot=$EvidenceRoot;LiveTenantTested=$false}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'summary.json')
$summary
