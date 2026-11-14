#requires -Version 7.4
param([string]$EvidenceRoot)
$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent
if(-not $EvidenceRoot){$EvidenceRoot=Join-Path $root ('test-results/'+[guid]::NewGuid().ToString('N'))}
[void][IO.Directory]::CreateDirectory($EvidenceRoot);$exe=(Get-Process -Id $PID).Path
foreach($test in @('Test-UtcQueryWindow.ps1','Test-UtcQueryWindow.EdgeCases.ps1')){
 $out=& $exe -NoLogo -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot $test) 2>&1
 $out | Set-Content (Join-Path $EvidenceRoot ($test+'.txt'));if($LASTEXITCODE -ne 0){throw "Failed $test"}
}
$out=& $exe -NoLogo -NoProfile -NonInteractive -File "$PSScriptRoot/Test-Pager.Operator.ps1" -PagerPath "$root/Invoke-SyntheticTracePager.ps1" 2>&1
$out | Set-Content (Join-Path $EvidenceRoot 'pager.json');if($LASTEXITCODE -ne 0){throw 'Pager failed'}
$pager=($out -join "`n") | ConvertFrom-Json;if($pager.Failed){throw 'Pager assertions failed'}
$out=& $exe -NoLogo -NoProfile -NonInteractive -File "$PSScriptRoot/Test-Logs.ps1" -ResultsPath (Join-Path $EvidenceRoot 'logs.json') 2>&1
$out | Set-Content (Join-Path $EvidenceRoot 'logs.stdout.txt');if($LASTEXITCODE -ne 0){throw 'Logs tests failed'}
$logs=Get-Content (Join-Path $EvidenceRoot 'logs.json') -Raw | ConvertFrom-Json
$result=[pscustomobject]@{Passed=$true;PowerShell=$PSVersionTable.PSVersion.ToString();OriginalHelperScenarios=9;OriginalHelperAssertions=21;PagerCases=$pager.Total;LogsChecks=$logs.Checks;LiveTenantTested=$false;EvidenceRoot=$EvidenceRoot}
$result | ConvertTo-Json | Set-Content (Join-Path $EvidenceRoot 'summary.json');$result
