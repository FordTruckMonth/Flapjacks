#requires -Version 7.4
# Synthetic presentation contract only. No authentication, tenant calls or installs.
param([string]$ResultsPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'M365SecurityAudit.psm1') -Force -DisableNameChecking
$module=Get-Module M365SecurityAudit
$work=Join-Path (Join-Path (Split-Path $root -Parent) 'test-output') ('mail-baseline-presentation-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Passed){$tests.Add([pscustomobject]@{Name=$Name;Passed=$Passed});if(-not $Passed){throw "FAIL: $Name"}}
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
function Pdf-Text([string]$Pdf){
 return (([regex]::Matches($Pdf,'\(((?:\\.|[^\\)])*)\) Tj')|ForEach-Object {$_.Groups[1].Value.Replace('\(','(').Replace('\)',')').Replace('\\','\')}) -join ' ')
}
function Compact([string]$Text){return ($Text -replace '\s+','')}

$reference='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-phishing-policy-settings-in-microsoft-defender-for-office-365'
$expected='EnableMailboxIntelligence = true in every returned policy (Standard recommendation).'
$checks=@(
 [pscustomobject]@{
  ControlId='MAIL-TEST';Control='Mailbox intelligence in returned policies';Status='Meets selected setting';Field='EnableMailboxIntelligence'
  RecommendationAuthority='Microsoft';Expected=$expected;Reference=$reference
  StatusDetailsSafe='2 of 2 returned policies match the selected Standard recommendation.'
  Observed='SENSITIVE_OBSERVATION';EvidenceIds=@('SENSITIVE_ID');SourceStatus='SENSITIVE_PROVIDER_STATUS'
  Rationale='Microsoft recommends enabling mailbox intelligence.'
  Limitation='Stored settings only. Policy assignment, precedence, licensing and effective recipient protection require separate review.'
  AccessPrerequisites='Existing authorized Exchange read access to Get-AntiPhishPolicy; Defender for Office 365 licensing applies.'
 },
 [pscustomobject]@{
  ControlId='LOCAL-TEST';Control='Local safe-list choice';Status='Needs action';Field='EnableSafeList'
  Expected='EnableSafeList = false.';Reference='https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
  Observed='EnableSafeList = true.';Rationale='Analyst-selected local baseline, not a Microsoft recommendation.';Limitation='Review approved exceptions.'
 }
)
$display=@(& $module {param($rows) Get-FlapjacksControlDisplayRows -Checks $rows} $checks)
$headers=@('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
Check 'Display retains exact five columns' (($display[0].PSObject.Properties.Name -join '|') -ceq ($headers -join '|'))
Check 'Microsoft row includes exact recommendation' ($display[0].Rationale.Contains('Microsoft recommendation: '+$expected))
Check 'Microsoft row includes exact inert reference' ($display[0].Rationale.Contains('Reference: '+$reference))
Check 'Microsoft row retains rationale and caveats' ($display[0].Rationale.Contains($checks[0].Rationale) -and $display[0].Rationale.Contains($checks[0].Limitation))
Check 'Safe typed observation remains separate from recommendation' ($display[0].'Status details' -ceq $checks[0].StatusDetailsSafe)
Check 'Access prerequisites retained' ($display[0].'M365 access/licensing/prerequisites' -ceq $checks[0].AccessPrerequisites)
Check 'Microsoft URL alone never labels a local rule as recommended' (-not $display[1].Rationale.Contains('Microsoft recommendation:'))
Check 'No raw evidence IDs or provider details in display' (($display|ConvertTo-Json) -notmatch 'SENSITIVE_')
foreach($bad in @('https://learn.microsoft.com.evil.example/test','https://learn.microsoft.com@evil.example/test','http://learn.microsoft.com/test','javascript:alert(1)','https://evil.example/test')){
 $invalid=$checks[0].PSObject.Copy();$invalid.Reference=$bad
 Check ('Unsupported recommendation reference rejected: '+$bad) (Rejects {& $module {param($row) Get-FlapjacksControlDisplayRows -Checks @($row)} $invalid})
}
$invalid=$checks[0].PSObject.Copy();$invalid.Expected=''
Check 'Microsoft authority cannot appear without specific recommendation' (Rejects {& $module {param($row) Get-FlapjacksControlDisplayRows -Checks @($row)} $invalid})

# The shared display projection must render identically in all three formats.
$paths=@{Csv=(Join-Path $work 'parity.csv');Xlsx=(Join-Path $work 'parity.xlsx');Pdf=(Join-Path $work 'parity.pdf')}
& $module {param($paths,$rows)
 $coverage=@([pscustomobject]@{'Source'='synthetic-source';'Collection state'='Read OK';'Returned records'=2})
 $notes=@('SYNTHETIC DEMONSTRATION. Recommendation references are static inert text.')
 Write-AuditCsv $paths.Csv $rows @('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
 Write-FlapjacksPostureWorkbook -Path $paths.Xlsx -Controls $rows -Coverage $coverage -Notes $notes
 $null=Write-FlapjacksPosturePdf -Path $paths.Pdf -Controls $rows -Coverage $coverage -Notes $notes -Summary 'Synthetic presentation test' -CoverageSummary '1 synthetic source' -Synthetic $true
} $paths $display
$csv=@(Import-Csv -LiteralPath $paths.Csv);$zip=Read-Zip $paths.Xlsx;$xlsx=@(Read-Rows $zip['xl/worksheets/sheet1.xml'])
$pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($paths.Pdf));$text=Pdf-Text $pdf
Check 'XLSX and CSV headers exact' (($xlsx[0] -join '|') -ceq ($headers -join '|') -and ($csv[0].PSObject.Properties.Name -join '|') -ceq ($headers -join '|'))
Check 'All formats contain every control' ($csv.Count -eq $display.Count -and $xlsx.Count -eq $display.Count+1 -and $text.Contains($display[1].Control))
for($n=0;$n -lt $display.Count;$n++){
 for($c=0;$c -lt $headers.Count;$c++){
  $value=[string]$display[$n].($headers[$c])
  Check ("CSV/XLSX exact cell parity row $n column $c") ([string]$csv[$n].($headers[$c]) -ceq $value -and [string]$xlsx[$n+1][$c] -ceq $value)
  Check ("PDF complete cell text row $n column $c") ((Compact $text).Contains((Compact $value)))
 }
}
Check 'Long PDF URL wraps instead of overflowing a single text operation' (-not $pdf.Contains($reference))
Check 'Wrapped PDF URL is complete and exact' ((Compact $text).Contains($reference))
Check 'PDF has no active link or action objects' ($pdf -notmatch '/(JavaScript|Launch|URI|AcroForm|EmbeddedFile|OpenAction)\b')
Check 'XLSX references are literal text without formulas or hyperlinks' (($zip.Values -join "`n") -notmatch '<f(?:\s|>)|vbaProject|externalLink|TargetMode="External"|<hyperlink')

# Export rebuilds checks from source evidence, never from supplied recommendation fields.
$base=Invoke-M365OrganizationAudit -Mode Synthetic -Workbook
$snapshot=$base|ConvertTo-Json -Depth 100
foreach($profile in @('Standard','Strict','missing','SENSITIVE_PROFILE')){
 $result=$snapshot|ConvertFrom-Json -Depth 100
 $result.Metadata.PSObject.Properties.Remove('WorkbookAntiPhishBaseline')
 if($profile -cne 'missing'){$result.Metadata|Add-Member -NotePropertyName WorkbookAntiPhishBaseline -NotePropertyValue $profile}
 $result|Add-Member -NotePropertyName Checks -NotePropertyValue @([pscustomobject]@{Control='SENSITIVE_FAKE_CHECK';RecommendationAuthority='Microsoft';Expected='SENSITIVE_FAKE_EXPECTATION';Reference='https://evil.example/SENSITIVE_FAKE_URL'}) -Force
 $result.Evidence[0]|Add-Member -NotePropertyName RecommendationAuthority -NotePropertyValue 'Microsoft' -Force
 $result.Evidence[0]|Add-Member -NotePropertyName Reference -NotePropertyValue 'https://evil.example/SENSITIVE_PROVIDER_URL' -Force
 $bundle=Export-FlapjacksPostureBundle -Result $result -OutputDirectory (Join-Path $work $profile)
 $entries=Read-Zip (Join-Path $bundle.OutputDirectory 'Posture-Report.xlsx')
 $pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $bundle.OutputDirectory 'Posture-Report.pdf')))
 $allDisplay=($entries.Values -join '')+(Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'Posture-Report.csv') -Raw)+$pdf
 $profileLabel=if($profile -cin @('Standard','Strict')){$profile}else{'Not selected (None, missing or unsupported saved value)'}
 Check ($profile+' workbook profile visibly explicit') ($entries['xl/worksheets/sheet3.xml'].Contains('Saved Microsoft mail recommendation profile: '+$profileLabel+'.'))
 Check ($profile+' PDF profile visibly explicit') ((Pdf-Text $pdf).Contains('Saved Microsoft mail recommendation profile: '+$profileLabel+'.'))
 Check ($profile+' untrusted checks/provider strings cannot become Microsoft recommendation') ($allDisplay -notmatch 'SENSITIVE_')
 $saved=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'audit.json') -Raw|ConvertFrom-Json -Depth 100
 Check ($profile+' original selected profile metadata preserved') $(if($profile -ceq 'missing'){$null -eq $saved.Metadata.PSObject.Properties['WorkbookAntiPhishBaseline']}else{$saved.Metadata.WorkbookAntiPhishBaseline -ceq $profile})
 $detail=@(Import-Csv -LiteralPath (Join-Path $bundle.OutputDirectory 'checks.csv'))
 Check ($profile+' detailed CSV includes authority and safe summary fields') ('RecommendationAuthority' -cin $detail[0].PSObject.Properties.Name -and 'StatusDetailsSafe' -cin $detail[0].PSObject.Properties.Name)
 $actual=@(Get-FlapjacksAllPostureChecks -Result $result)
 $visible=@(Import-Csv -LiteralPath (Join-Path $bundle.OutputDirectory 'Posture-Report.csv'))
 $xlsxRows=@(Read-Rows $entries['xl/worksheets/sheet1.xml']);$pdfCompact=Compact (Pdf-Text $pdf)
 for($n=0;$n -lt $actual.Count;$n++){
  if($null -eq $actual[$n].PSObject.Properties['RecommendationAuthority'] -or $actual[$n].RecommendationAuthority -cne 'Microsoft'){continue}
  $name=$profile+' '+$actual[$n].ControlId
  Check ($name+' exact expected recommendation and reference visible') ($visible[$n].Rationale.Contains('Microsoft recommendation: '+$actual[$n].Expected) -and $visible[$n].Rationale.Contains('Reference: '+$actual[$n].Reference))
  Check ($name+' typed detail preserved') ($visible[$n].'Status details' -ceq $actual[$n].StatusDetailsSafe)
  foreach($c in 0..4){
   $value=[string]$visible[$n].($headers[$c])
   Check ($name+" CSV/XLSX/PDF complete cell $c") ($value -ceq [string]$xlsxRows[$n+1][$c] -and $pdfCompact.Contains((Compact $value)))
  }
 }
 Check ($profile+' full bundle manifest valid') (Test-M365AuditManifest -Path $bundle.OutputDirectory).Valid
}
Check 'Synthetic input untouched' (($base|ConvertTo-Json -Depth 100) -ceq $snapshot)
$out=[pscustomobject]@{Passed=$true;Checks=$tests.Count;SyntheticOnly=$true;EvidenceRoot=$work;Assertions=$tests}
if($ResultsPath){$out|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $ResultsPath}
$out|Select-Object Passed,Checks,SyntheticOnly,EvidenceRoot
