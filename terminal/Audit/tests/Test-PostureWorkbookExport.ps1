#requires -Version 7.4
# Offline structural/export tests. Invented fixtures only; no provider/session calls or dependency installs.
param([string]$ResultsPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'M365SecurityAudit.psm1') -Force -DisableNameChecking
$module=Get-Module M365SecurityAudit
$work=Join-Path (Join-Path (Split-Path $root -Parent) 'test-output') ('posture-workbook-output-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$assertions=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Passed){$assertions.Add([pscustomobject]@{Name=$Name;Passed=$Passed});if(-not $Passed){throw "FAIL: $Name"}}
function Rejects([scriptblock]$Action){try{& $Action|Out-Null;$false}catch{$true}}
function Read-Zip([string]$Path){
 $zip=[IO.Compression.ZipFile]::OpenRead($Path);$entries=@{}
 try{foreach($entry in $zip.Entries){$reader=[IO.StreamReader]::new($entry.Open());try{$entries[$entry.FullName]=$reader.ReadToEnd()}finally{$reader.Dispose()}}}finally{$zip.Dispose()}
 return $entries
}
function Read-Rows([string]$Xml){
 $doc=[xml]$Xml
 foreach($row in $doc.SelectNodes('//*[local-name()="sheetData"]/*[local-name()="row"]')){
  $cells=@($row.SelectNodes('*[local-name()="c"]')|ForEach-Object {$_.InnerText})
  Write-Output -NoEnumerate $cells
 }
}
$base=Invoke-M365OrganizationAudit -Mode Synthetic
$expanded=Invoke-M365OrganizationAudit -Mode Synthetic -Workbook
$baselineSnapshot=$base|ConvertTo-Json -Depth 100
$expandedSnapshot=$expanded|ConvertTo-Json -Depth 100
$bundles=@{}
foreach($name in @('baseline','expanded')){
 $result=if($name -eq 'baseline'){$base}else{$expanded}
 $expected=@(Get-FlapjacksAllPostureChecks -Result $result)
 $bundle=Export-FlapjacksPostureBundle -Result $result -OutputDirectory (Join-Path $work $name)
 $bundles[$name]=$bundle
 Check "$name has dynamic control count" ($bundle.PostureChecks -eq $expected.Count)
 Check "$name preserves all source entries" ($bundle.Sources -eq $result.Evidence.Count)
 Check "$name valid full manifest" (Test-M365AuditManifest -Path $bundle.OutputDirectory).Valid
 $manifest=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'manifest.json') -Raw|ConvertFrom-Json
 foreach($file in @('Posture-Report.pdf','Posture-Report.xlsx','Posture-Report.csv','review.pdf','checks.csv','checks.json','coverage.csv','inventory.csv','observations.csv','audit.json','collection-plan.json')){Check "$name manifest includes $file" ($file -cin $manifest.Files.Path)}
 Check "$name PDF compatibility copy exact" ((Get-FileHash (Join-Path $bundle.OutputDirectory 'review.pdf')).Hash -ceq (Get-FileHash (Join-Path $bundle.OutputDirectory 'Posture-Report.pdf')).Hash)
 $pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $bundle.OutputDirectory 'Posture-Report.pdf')))
 Check "$name PDF no active features" ($pdf -notmatch '/(JavaScript|Launch|URI|AcroForm|EmbeddedFile|OpenAction)\b')
 Check "$name PDF control table precedes coverage" ($pdf.IndexOf('(Status details)') -gt 0 -and $pdf.IndexOf('(Status details)') -lt $pdf.IndexOf('(Source coverage)'))
 Check "$name PDF dynamic pages" ($pdf.Contains('/Count '+$bundle.PdfPages+' /Kids'))
 Check "$name PDF PIM unknown warning" ($pdf.Contains('does NOT establish that PIM is not configured'))
 Check "$name PDF visibly synthetic" ($pdf.Contains('SYNTHETIC DEMONSTRATION'))
 $csv=@(Import-Csv -LiteralPath (Join-Path $bundle.OutputDirectory 'Posture-Report.csv'))
 $headers=@('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
 Check "$name CSV exact five requested columns" (($csv[0].PSObject.Properties.Name -join '|') -ceq ($headers -join '|'))
 Check "$name CSV one row per control" ($csv.Count -eq $expected.Count)
 Check "$name display statuses match evaluator" (($csv.Status -join '|') -ceq ($expected.Status -join '|'))
 Check "$name display prerequisites are populated" (@($csv|Where-Object {[string]::IsNullOrWhiteSpace($_.'M365 access/licensing/prerequisites')}).Count -eq 0)
 $zip=Read-Zip (Join-Path $bundle.OutputDirectory 'Posture-Report.xlsx')
 Check "$name is real OOXML workbook" ($zip.ContainsKey('[Content_Types].xml') -and $zip.ContainsKey('xl/workbook.xml') -and $zip.ContainsKey('_rels/.rels'))
 foreach($path in $zip.Keys){$xml=[xml]$zip[$path];Check "$name valid XML $path" ($null -ne $xml.DocumentElement)}
 $allXml=($zip.Values -join "`n")
 Check "$name XLSX no formulas/macros/external links" ($allXml -notmatch '<f(?:\s|>)|vbaProject|externalLink|TargetMode="External"|<hyperlink')
 Check "$name XLSX three worksheets" (([xml]$zip['xl/workbook.xml']).GetElementsByTagName('sheet').Count -eq 3)
 $sheet=[xml]$zip['xl/worksheets/sheet1.xml']
 $cells=@($sheet.GetElementsByTagName('c'))
 Check "$name XLSX all literal strings" (@($cells|Where-Object {$_.t -cne 'inlineStr'}).Count -eq 0)
 Check "$name XLSX freezes header" ($sheet.GetElementsByTagName('pane')[0].state -ceq 'frozen')
 Check "$name XLSX filters controls" ($sheet.GetElementsByTagName('autoFilter')[0].ref -ceq ('A1:E'+($expected.Count+1)))
 $xlsxRows=@(Read-Rows $zip['xl/worksheets/sheet1.xml'])
 Check "$name XLSX and CSV headers identical" (($xlsxRows[0] -join '|') -ceq ($headers -join '|'))
 Check "$name XLSX rows match control count" ($xlsxRows.Count -eq $csv.Count+1)
 $same=$true
 for($n=0;$n -lt $csv.Count;$n++){for($c=0;$c -lt 5;$c++){if([string]$csv[$n].($headers[$c]) -cne [string]$xlsxRows[$n+1][$c]){$same=$false}}}
 Check "$name all XLSX control cells equal CSV" $same
 $coverage=@(Read-Rows $zip['xl/worksheets/sheet2.xml'])
 Check "$name source coverage separate and complete" ($coverage.Count -eq $result.Evidence.Count+1)
 $plan=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'collection-plan.json') -Raw|ConvertFrom-Json
 Check "$name collection plan selected groups exact" (($plan.SelectedGroups -join '|') -ceq ($result.Metadata.SelectedGroups -join '|'))
 $audit=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'audit.json') -Raw|ConvertFrom-Json -Depth 100
 Check "$name saved evidence source count exact" ($audit.Coverage.Count -eq $result.Evidence.Count)
 Check "$name existing false values preserved" (@($audit.Coverage|Where-Object SourceId -eq 'exchange-organization')[0].Items[0].AuditDisabled -ceq $false)
}
Check 'Baseline still five controls' ($bundles.baseline.PostureChecks -eq 5)
Check 'Workbook adds controls without removing pilot' ($bundles.expanded.PostureChecks -gt $bundles.baseline.PostureChecks)
Check 'Baseline input unchanged' (($base|ConvertTo-Json -Depth 100) -ceq $baselineSnapshot)
Check 'Expanded input unchanged' (($expanded|ConvertTo-Json -Depth 100) -ceq $expandedSnapshot)
Check 'Overwrite refused' (Rejects {Export-FlapjacksPostureBundle -Result $base -OutputDirectory $bundles.baseline.OutputDirectory})
# Hostile identifiers, arbitrary errors and statuses remain detailed local evidence, never the display files.
$evil=$expandedSnapshot|ConvertFrom-Json -Depth 100
$evil.Metadata.TenantId='SENSITIVE_TENANT_MARKER'
$org=@($evil.Evidence|Where-Object SourceId -eq 'exchange-organization')[0]
$org.Items[0].Identity='=SENSITIVE_FORMULA_MARKER';$org.Reason='SENSITIVE_ERROR_MARKER';$org.Status='SENSITIVE_STATUS_MARKER'
$evil.Evidence+=@([pscustomobject]@{SourceId='sensitive-unknown-id-marker';Group='Synthetic';Provider='Synthetic';Target='SENSITIVE_TARGET_MARKER';Status='Error';Reason='SENSITIVE_REASON_MARKER';Items=@();Count=0;MissingFields=@();CollectedAtUtc='2026-01-01T00:00:00Z';PageCount=0;RequestCount=0;Notes='SENSITIVE_NOTE_MARKER'})
$hostile=Export-FlapjacksPostureBundle -Result $evil -OutputDirectory (Join-Path $work 'hostile')
$xml=Read-Zip (Join-Path $hostile.OutputDirectory 'Posture-Report.xlsx')
$display=([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $hostile.OutputDirectory 'Posture-Report.pdf'))))+(Get-Content -LiteralPath (Join-Path $hostile.OutputDirectory 'Posture-Report.csv') -Raw)+($xml.Values -join '')
Check 'Display PDF/XLSX/CSV excludes hostile raw IDs/status/errors/metadata' ($display -notmatch '(?i)sensitive[-_]')
$raw=Get-Content -LiteralPath (Join-Path $hostile.OutputDirectory 'evidence/exchange-organization.json') -Raw|ConvertFrom-Json
Check 'Raw evidence identity preserved in JSON' ($raw.Items[0].Identity -ceq '=SENSITIVE_FORMULA_MARKER')
$inventory=Import-Csv -LiteralPath (Join-Path $hostile.OutputDirectory 'inventory.csv')
Check 'Detailed CSV formula identity neutralized' (@($inventory|Where-Object ObjectId -ceq "'=SENSITIVE_FORMULA_MARKER").Count -eq 1)
Check 'Hostile-data bundle valid manifest' (Test-M365AuditManifest -Path $hostile.OutputDirectory).Valid
# Exercise formula handling directly with deliberately malicious display strings (never tenant data).
$formula=Join-Path $work 'literal-text.xlsx'
& $module {param($path)
 $r=[pscustomobject]@{'Control'='=1+1';'Status'='+SUM(1,1)';'Status details'="`t@COMMAND";'Rationale'='<xml>&text';'M365 access/licensing/prerequisites'="-1`n"}
 Write-FlapjacksPostureWorkbook -Path $path -Controls @($r) -Coverage @([pscustomobject]@{'Source'='source';'Collection state'='Read OK';'Returned records'=0}) -Notes @('Synthetic formula safety test')
} $formula
$f=Read-Zip $formula;$fRows=@(Read-Rows $f['xl/worksheets/sheet1.xml'])
Check 'Formula-leading XLSX text neutralized' ($fRows[1][0] -ceq "'=1+1" -and $fRows[1][1] -ceq "'+SUM(1,1)" -and $fRows[1][2].StartsWith("'`t"))
Check 'XML escapes round-trip' ($fRows[1][3] -ceq '<xml>&text')
Check 'Literal-test workbook no formulas' ($f['xl/worksheets/sheet1.xml'] -notmatch '<f(?:\s|>)')
$bad=$baselineSnapshot|ConvertFrom-Json -Depth 100;$bad.Evidence[0].SourceId='../escape'
Check 'Bad source path rejected before output' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'bad-source')})
Check 'Rejected export created no directory' (-not (Test-Path -LiteralPath (Join-Path $work 'bad-source')))
# File-input path is supported without changing evidence or re-collecting.
$file=Join-Path $work 'saved.json';[IO.File]::WriteAllText($file,$expandedSnapshot)
# ISO-looking evidence strings must not be automatically converted to DateTime.
$strings=$expandedSnapshot.Replace('2026-10-31T00:00:00Z','2026-10-31T00:00:00.0000000+00:00')
[IO.File]::WriteAllText($file,$strings)
$before=(Get-FileHash -LiteralPath $file).Hash
$saved=Export-FlapjacksPostureBundle -InputJson $file -OutputDirectory (Join-Path $work 'saved-input')
Check 'Saved JSON export has same dynamic count' ($saved.PostureChecks -eq $bundles.expanded.PostureChecks)
Check 'Saved JSON input unchanged' ((Get-FileHash -LiteralPath $file).Hash -ceq $before)
$loaded=& $module {param($path) ConvertFrom-FlapjacksEvidenceJson -Json (Get-Content -LiteralPath $path -Raw)} $file
Check 'Saved JSON parser preserves source ISO string exactly' ($loaded.Evidence[0].CollectedAtUtc -is [string] -and $loaded.Evidence[0].CollectedAtUtc -ceq $expanded.Evidence[0].CollectedAtUtc)
$savedRaw=Get-Content -LiteralPath (Join-Path $saved.OutputDirectory 'audit.json') -Raw
Check 'Saved JSON retained fractional and offset registration timestamp text' ($savedRaw.Contains('2026-10-31T00:00:00.0000000+00:00'))
$types=& $module {ConvertFrom-FlapjacksEvidenceJson -Json '{"a":[],"b":[false,null,[1]],"c":"2026-01-01T01:00:00.0000000+01:00","d":"2026-01-01T00:00:00.1234567Z","e":1.5}'}
Check 'JSON parser retains empty/nested arrays, Boolean and null' ($types.a.Count -eq 0 -and $types.b.Count -eq 3 -and $types.b[0] -ceq $false -and $null -eq $types.b[1] -and $types.b[2][0] -eq 1)
Check 'JSON parser retains offset and precise timestamp strings' ($types.c -ceq '2026-01-01T01:00:00.0000000+01:00' -and $types.d -ceq '2026-01-01T00:00:00.1234567Z')
Check 'JSON parser rejects ambiguous duplicate names' (Rejects {& $module {ConvertFrom-FlapjacksEvidenceJson -Json '{"a":1,"A":2}'}})
$subset=Invoke-M365SecurityAudit -Mode Synthetic -Include WorkbookIdentity
$subsetOut=Export-FlapjacksPostureBundle -Result $subset -OutputDirectory (Join-Path $work 'subset')
$subsetPlan=Get-Content -LiteralPath (Join-Path $subsetOut.OutputDirectory 'collection-plan.json') -Raw|ConvertFrom-Json
Check 'Subset collection plan is not broadened by export' (($subsetPlan.SelectedGroups -join '|') -ceq ($subset.Metadata.SelectedGroups -join '|'))

$out=[pscustomobject]@{Passed=$true;Checks=$assertions.Count;SyntheticOnly=$true;EvidenceRoot=$work;Baseline=$bundles.baseline;Expanded=$bundles.expanded;Assertions=$assertions}
if($ResultsPath){$out|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $ResultsPath}
$out|Select-Object Passed,Checks,SyntheticOnly,EvidenceRoot
