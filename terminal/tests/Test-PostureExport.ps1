#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/Audit/M365SecurityAudit.psm1" -Force -DisableNameChecking
Import-Module "$root/M365Toolkit.psm1" -Force -DisableNameChecking
$work=Join-Path $root ('test-output/flapjacks-export-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$checks=[Collections.Generic.List[object]]::new()
function Check($n,$c){$checks.Add(@{Name=$n;Passed=[bool]$c});if(-not $c){throw "FAIL: $n"}}
function Rejects([scriptblock]$b){try{& $b|Out-Null;return $false}catch{return $true}}
function Copy-Result($r){$r|ConvertTo-Json -Depth 100|ConvertFrom-Json -Depth 100}
function Runtime([string[]]$answers){
 $state=@{Input=[Collections.Generic.Queue[string]]::new();Prompts=[Collections.Generic.List[string]]::new();Text=[Collections.Generic.List[string]]::new();Calls=0}
 foreach($a in $answers){$state.Input.Enqueue($a)}
 @{State=$state;Read={param($p)$state.Prompts.Add($p);if(-not $state.Input.Count){throw 'Unexpected prompt'};$state.Input.Dequeue()}.GetNewClosure();Write={param($t)$state.Text.Add([string]$t)}.GetNewClosure();Connect={$state.Calls++;throw 'No auth allowed'}.GetNewClosure();Local={$state.Calls++;throw 'No session lookup allowed'}.GetNewClosure();ReadCommand={$state.Calls++;throw 'No provider allowed'}.GetNewClosure()}
}
$r=Invoke-M365OrganizationAudit -Mode Synthetic
# Source shape matches terminal saved result and lower-level saved audit shape.
$terminal=Join-Path $work 'terminal.json';$r|ConvertTo-Json -Depth 100|Set-Content $terminal
$inputHash=(Get-FileHash $terminal).Hash
$a=Export-FlapjacksPostureBundle -InputJson $terminal -OutputDirectory (Join-Path $work 'terminal-bundle')
Check 'five posture checks' ($a.PostureChecks -eq 5)
Check 'all 46 sources preserved' ($a.Sources -eq 46)
Check 'PDF created' ((Get-Item (Join-Path $a.OutputDirectory 'review.pdf')).Length -gt 1000)
Check 'one valid complete manifest' (Test-M365AuditManifest $a.OutputDirectory).Valid
$manifest=Get-Content (Join-Path $a.OutputDirectory 'manifest.json') -Raw|ConvertFrom-Json
foreach($name in @('review.pdf','checks.csv','checks.json','coverage.csv','inventory.csv','observations.csv')){Check "manifest includes $name" ($name -in $manifest.Files.Path)}
$b=Export-FlapjacksPostureBundle -InputJson (Join-Path $a.OutputDirectory 'audit.json') -OutputDirectory (Join-Path $work 'audit-bundle')
Check 'saved audit Coverage shape supported' ($b.Sources -eq 46 -and (Test-M365AuditManifest $b.OutputDirectory).Valid)
Check 'posture equivalent across saved shapes' ((Get-Content (Join-Path $a.OutputDirectory 'checks.json') -Raw) -ceq (Get-Content (Join-Path $b.OutputDirectory 'checks.json') -Raw))
Check 'overwrite refused' (Rejects {Export-FlapjacksPostureBundle -Result $r -OutputDirectory $a.OutputDirectory})
Check 'input JSON unchanged' ((Get-FileHash $terminal).Hash -eq $inputHash)
$bad=Copy-Result $r;$bad.Evidence[0].SourceId='../escape'
Check 'path traversal refused' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'bad-id')})
Check 'bad id creates no output' (-not (Test-Path (Join-Path $work 'bad-id')))
$bad=Copy-Result $r;$bad.Evidence[1].SourceId=$bad.Evidence[0].SourceId
Check 'duplicate source refused' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'duplicate')})
$bad=Copy-Result $r;$bad.Evidence[0].Count=999
Check 'inconsistent source count refused' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'bad-count')})
$bad=Copy-Result $r;$bad.Evidence=@();$bad.Coverage[0].PSObject.Properties.Remove('Items')
Check 'summary only refused' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'summary')})
Check 'missing parent refused' (Rejects {Export-FlapjacksPostureBundle -Result $r -OutputDirectory (Join-Path $work 'missing/child')})
# Formula injection is neutralized in CSV; raw evidence remains faithful JSON, never PDF text.
$evil=Copy-Result $r;$org=@($evil.Evidence|Where-Object SourceId -eq 'exchange-organization')[0]
$org.Items[0].Identity='=SYNTHETIC_FORMULA';$org.Items[0].AuditDisabled=$false
$e=Export-FlapjacksPostureBundle -Result $evil -OutputDirectory (Join-Path $work 'formula')
$inventory=Import-Csv (Join-Path $e.OutputDirectory 'inventory.csv')
Check 'CSV formula-neutralized' (@($inventory|Where-Object ObjectId -eq "'=SYNTHETIC_FORMULA").Count -eq 1)
$raw=Get-Content (Join-Path $e.OutputDirectory 'evidence/exchange-organization.json') -Raw|ConvertFrom-Json
Check 'false preserved' ($raw.Items[0].AuditDisabled -ceq $false)
$pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $e.OutputDirectory 'review.pdf')))
Check 'PDF excludes raw identity' (-not $pdf.Contains('SYNTHETIC_FORMULA'))
Check 'PDF no active features' ($pdf -notmatch '/(JavaScript|Launch|URI|AcroForm|EmbeddedFile|OpenAction)\b')
Check 'PDF PIM unknown warning' ($pdf.Contains('does NOT establish that PIM is not configured'))
# No network/auth adapter should be needed to save an already-collected synthetic result.
$rt=Runtime @('');Save-ToolkitPostureBundle $r $rt
Check 'cancel prompts once' ($rt.State.Prompts.Count -eq 1)
Check 'cancel no provider or auth' ($rt.State.Calls -eq 0)
$rt=Runtime @();Check 'mailbox result refused before prompt' (Rejects {Save-ToolkitPostureBundle ([pscustomobject]@{Target='synthetic@example.invalid'}) $rt})
Check 'mailbox refusal no prompt' ($rt.State.Prompts.Count -eq 0)
$bundle=Join-Path $work 'menu-bundle';$json=Join-Path $work 'menu.json'
$rt=Runtime @('A','AUDIT','P',$bundle,'S',$json,'Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt
Check 'P saves explicit bundle' (Test-Path (Join-Path $bundle 'review.pdf'))
Check 'S still saves JSON' (Test-Path $json)
Check 'menu does not authenticate or call provider' ($rt.State.Calls -eq 0)
Check 'one Audit result no recollect on P or S' ($history.Count -eq 1)
Check 'only one Audit authorization prompt' (@($rt.State.Prompts|Where-Object {$_ -like 'Type AUDIT*'}).Count -eq 1)
$rt=Runtime @('A','','P','Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt
Check 'Audit cancellation no result' ($history.Count -eq 0)
Check 'P with no history asks no destination' (@($rt.State.Prompts|Where-Object {$_ -like 'NEW posture*'}).Count -eq 0)
$rt=Runtime @('A','AUDIT','Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt
Check 'Audit no default export' (-not $history[0].OutputPath)
# A link destination cannot redirect an evidence export.
$link=Join-Path $work 'link'
try{New-Item -ItemType SymbolicLink -Path $link -Target $a.OutputDirectory -ErrorAction Stop|Out-Null;Check 'linked ancestor refused' (Rejects {Export-FlapjacksPostureBundle -Result $r -OutputDirectory (Join-Path $link 'escaped')})}catch{throw "Symlink refusal test failed: $_"}
$result=[pscustomobject]@{Passed=$true;Checks=$checks.Count;SyntheticOnly=$true;EvidenceRoot=$work;Assertions=$checks}
if($ResultsPath){$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultsPath}
$result|Select-Object Passed,Checks,SyntheticOnly,EvidenceRoot
