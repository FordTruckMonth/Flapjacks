#requires -Version 7.4
param([string]$EvidenceRoot)
$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent
if(-not $EvidenceRoot){$EvidenceRoot=Join-Path $root ('test-output/'+[guid]::NewGuid().ToString('N'))}
[void][IO.Directory]::CreateDirectory($EvidenceRoot)
$exe=(Get-Process -Id $PID).Path
$parse=@(Get-ChildItem $root -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1')} | ForEach-Object {
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors);$errors
})
if($parse.Count){throw 'Native parser errors'}
$subtests=@(
 @{Name='posture-export';Path="$root/tests/Test-PostureExport.ps1";Parameters=@{ResultsPath=(Join-Path $EvidenceRoot 'posture-export.json')}},
 @{Name='posture-evaluator';Path="$root/Audit/tests/Test-Posture.ps1";Parameters=@{}},
 @{Name='workbook-identity';Path="$root/Audit/tests/Test-WorkbookIdentity.ps1";Parameters=@{}},
 @{Name='workbook-exchange';Path="$root/Audit/tests/Test-WorkbookExchange.ps1";Parameters=@{}},
 @{Name='workbook-collaboration';Path="$root/Audit/tests/Test-WorkbookCollaboration.ps1";Parameters=@{}},
 @{Name='workbook-gates';Path="$root/Audit/tests/Test-WorkbookGates.ps1";Parameters=@{}},
 @{Name='workbook-formats';Path="$root/Audit/tests/Test-PostureWorkbookExport.ps1";Parameters=@{}},
 @{Name='mail-antiphish';Path="$root/Audit/tests/Test-MailBaselineAntiphish.ps1";Parameters=@{}},
 @{Name='mail-spam';Path="$root/Audit/tests/Test-MailBaselineSpam.ps1";Parameters=@{}},
 @{Name='mail-protection';Path="$root/Audit/tests/Test-MailBaselineProtection.ps1";Parameters=@{}},
 @{Name='mail-presentation';Path="$root/Audit/tests/Test-MailBaselinePresentation.ps1";Parameters=@{}},
 @{Name='mail-gates';Path="$root/Audit/tests/Test-MailBaselineGates.ps1";Parameters=@{}},
 @{Name='mail-additive-projection';Path="$root/Audit/tests/Test-MailBaselineOptionalProjection.ps1";Parameters=@{}},
 @{Name='mail-filetypes';Path="$root/Audit/tests/Test-MailBaselineFileTypes.ps1";Parameters=@{}},
 @{Name='authentication-display';Path="$root/tests/Test-AuthenticationDisplay.ps1";Parameters=@{ResultsPath=(Join-Path $EvidenceRoot 'authentication-display.json')}},
 @{Name='mailbox-snapshot';Path="$root/tests/Test-MailboxSnapshot.ps1";Parameters=@{ResultsPath=(Join-Path $EvidenceRoot 'mailbox-snapshot.json')}},
 @{Name='prerequisites';Path="$root/tests/Test-Prerequisites.ps1";Parameters=@{ResultsPath=(Join-Path $EvidenceRoot 'prerequisites.json')}},
 @{Name='toolkit';Path="$root/tests/Test-Toolkit.ps1";Parameters=@{ResultsPath=(Join-Path $EvidenceRoot 'toolkit.json')}},
 @{Name='logs';Path="$root/Logs/tests/Test-All.ps1";Parameters=@{EvidenceRoot=(Join-Path $EvidenceRoot 'logs')}},
 @{Name='audit';Path="$root/Audit/tests/Test-All.ps1";Parameters=@{}},
 @{Name='audit-gates';Path="$root/Audit/tests/Test-TerminalGates.ps1";Parameters=@{}}
)
foreach($test in $subtests){
 $parameters=$test.Parameters
 $out=& $exe -NoLogo -NoProfile -NonInteractive -File $test.Path @parameters 2>&1
 $out | Set-Content -LiteralPath (Join-Path $EvidenceRoot ($test.Name+'.txt'))
 if($LASTEXITCODE -ne 0){throw ('Failed '+$test.Name+'; see '+$EvidenceRoot)}
}
$prerequisites=Get-Content (Join-Path $EvidenceRoot 'prerequisites.json') -Raw | ConvertFrom-Json
$toolkit=Get-Content (Join-Path $EvidenceRoot 'toolkit.json') -Raw | ConvertFrom-Json
$logs=Get-Content (Join-Path $EvidenceRoot 'logs/summary.json') -Raw | ConvertFrom-Json
$audit=Get-Content (Join-Path $EvidenceRoot 'audit.txt') -Raw
$gates=Get-Content (Join-Path $EvidenceRoot 'audit-gates.txt') -Raw
$auditCount=[int]([regex]::Match($audit,'PASS: (\d+) offline assertions').Groups[1].Value)
$gateCount=[int]([regex]::Match($gates,'PASS: (\d+)').Groups[1].Value)
if($auditCount -lt 150 -or $gateCount -lt 45){throw 'Could not confirm audit test counts'}
$snapshot=Get-Content (Join-Path $EvidenceRoot 'mailbox-snapshot.json') -Raw | ConvertFrom-Json
$authDisplay=Get-Content (Join-Path $EvidenceRoot 'authentication-display.json') -Raw | ConvertFrom-Json
$postureExport=Get-Content (Join-Path $EvidenceRoot 'posture-export.json') -Raw | ConvertFrom-Json
$summary=[pscustomobject]@{PostureExportChecks=$postureExport.Checks;AuthenticationDisplayChecks=$authDisplay.Checks;MailboxSnapshotChecks=$snapshot.Checks;Passed=$true;PowerShell=$PSVersionTable.PSVersion.ToString();NativeParser='Passed';ToolkitChecks=$toolkit.Checks;PrerequisiteChecks=$prerequisites.PrerequisiteChecks;LogsChecks=$logs.LogsChecks;OriginalHelperScenarios=$logs.OriginalHelperScenarios;OriginalHelperAssertions=$logs.OriginalHelperAssertions;PagerCases=$logs.PagerCases;AuditAssertions=$auditCount;AuditTerminalGateAssertions=$gateCount;LiveTenantTested=$false;Authentication='Mocks only';EvidenceRoot=$EvidenceRoot}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceRoot 'summary.json')
$summary
