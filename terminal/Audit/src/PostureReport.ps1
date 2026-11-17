# Offline renderers. Loading this file creates no files, opens no sessions and installs nothing.
# Detailed evidence remains in the local bundle; the display workbook deliberately excludes identities.
function ConvertTo-FlapjacksDisplayText {
 param([AllowNull()][object]$Value)
 if($null -eq $Value){return ''}
 # A deterministic ASCII display subset works with the PDF's built-in Helvetica font.
 return (([string]$Value -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',' ' -replace '[^\x09\x0A\x0D\x20-\x7E]','?') -replace '\s+',' ').Trim()
}
function Get-FlapjacksControlDisplayRows {
 param([Parameter(Mandatory)][object[]]$Checks)
 $pilotAccess=@{
  'EXO-AUDIT'='Existing Exchange read access to Get-OrganizationConfig. Audit retention and capabilities depend on licensing.'
  'EXO-DIRECT-SEND'='Existing Exchange read access to Get-OrganizationConfig. Validate approved device/application mail flows and operational dependencies.'
  'EXO-SMTP-AUTH'='Existing Exchange read access to Get-TransportConfig. Mailbox exceptions require separate authorized evidence.'
  'ENTRA-APP-REG'='Existing Graph Policy.Read.All access and appropriate delegated role. This flag alone does not assess OAuth consent.'
  'EOP-FILE-FILTER'='Existing Exchange read access to Get-MalwareFilterPolicy. Applicable Exchange Online Protection service and policy access.'
 }
 foreach($c in $Checks){
  # Never copy raw source status, reasons, IDs, operator notes or arbitrary observations into a display file.
  $details=switch($c.Status){
   'Meets selected setting' {'The saved evidence meets this selected setting only. Effective protection is not established.'}
   'Needs action' {'The saved evidence does not meet this selected setting. Review scope and business exceptions before any change.'}
   'N/A' {'Excluded by an explicit applicability decision. This is not a technical pass.'}
   default {'Saved evidence does not support this assessment. Missing or incomplete evidence is not a pass or failure.'}
  }
  if($c.Status -in @('Meets selected setting','Needs action')){
   $observed=[string](Get-AuditProperty $c 'Observed' '')
   $field=[regex]::Escape([string](Get-AuditProperty $c 'Field' ''))
   # The pilot evaluator emits only booleans or integer aggregate counts in these exact templates.
   if($field -and ($observed -cmatch ('^'+$field+' = (true|false)\.$') -or $observed -cmatch ('^[0-9]+ of [0-9]+ returned policies have '+$field+' = (true|false)\.$'))){$details=$observed}
  }
  # Additional bounded templates emitted by the typed workbook evaluators. The identity
  # report's precise update timestamps stay in detailed evidence, not the display workbook.
  $observed=[string](Get-AuditProperty $c 'Observed' '')
  if($observed -cmatch '^([0-9]+ of [0-9]+ (reported enabled admins|reported enabled non-admins|reported SSPR-enabled accounts) have (isMfaRegistered|isSsprRegistered|isSsprCapable) = true; [0-9]+ false; [0-9]+ unknown\. Denominator reconciled to [0-9]+ enabled directory accounts\.) Report update range: '){$details=$Matches[1]}
  elseif($observed -cmatch '^[0-9]+ of [0-9]+ enabled accounts have a known last successful sign-in at least 90 days before collection; [0-9]+ are more recent; [0-9]+ are unknown\. Review candidates, not automatic disablement\.$'){$details=$observed}
  elseif($observed -cmatch '^[0-9]+ total (AllowList|IPAllowList) entries across [0-9]+ returned records\.$'){$details=$observed}
  elseif($observed -cmatch '^[0-9]+ of [0-9]+ returned policies meet the selected (Standard|Strict) minimum threshold\.$'){$details=$observed}
  elseif($observed -cmatch '^(sharingCapability = (disabled|externalUserSharingOnly|existingExternalUserSharingOnly|externalUserAndGuestSharing)|isRequireAcceptingUserToMatchInvitedUserEnabled = (true|false)|isResharingByExternalUsersEnabled = (true|false))\. Stored tenant setting only\.$'){$details=$observed}
  elseif($c.Status -eq 'Not assessed'){
   # Exact fixed evaluator messages are safe; arbitrary source error/status strings are not.
   $safeGaps=@(
    'Successful empty response; this does not establish applicability or a configured setting.',
    'No threshold baseline was selected; Standard and Strict have different recommendations.',
    'At least one required field is missing, null or not a Boolean; false is never inferred.',
    'Source reports missing fields; it cannot establish a complete setting assessment.',
    'A required field is absent, null, outside the supported range or has the wrong type; no default is inferred.',
    'Registration IDs do not exactly match the enabled-user inventory; report lag, missing users or scope gaps leave the denominator unresolved.'
   )
   if($observed -cin $safeGaps){$details=$observed}
   elseif([string]$c.SourceId -cin @('workbook-teams-federation','workbook-teams-client','workbook-spo-tenant')){$details='Exact native tenant/account binding is not verified. Any offline snapshot is informational only, never an assessed tenant pass.'}
  }
  # Extended evaluators may supply a separately constructed, static/typed display field.
  # This field must never be populated from input object properties, IDs, raw status or errors.
  $safeDetails=[string](Get-AuditProperty $c 'StatusDetailsSafe' '')
  if($safeDetails){$details=$safeDetails}
  $access=[string](Get-AuditProperty $c 'AccessPrerequisites' '')
  if(-not $access){$access=$pilotAccess[[string]$c.ControlId]}
  if(-not $access -and [string]$c.ControlId -cin @('EXO-UNIFIED-AUDIT','EXO-EXTERNAL-TAG','EXO-EXTERNAL-TAG-EXCEPTIONS','EOP-CONNECTION-IP-ALLOW','EOP-CONNECTION-SAFE-LIST','EOP-SPOOF-INTELLIGENCE','EOP-PHISH-THRESHOLD')){
   $access='Existing tenant/account-matching Exchange Online session and read RBAC for the named cmdlet. EOP/Defender service and licensing applicability require separate review; no consent or role escalation.'
   if([string]$c.ControlId -ceq 'EOP-PHISH-THRESHOLD'){$access+=' A Standard or Strict threshold baseline must be explicitly selected.'}
  }
  if(-not $access){$access='Existing authorized read access to the named source. Licensing, service availability and operator roles require separate verification.'}
  $why=[string]$c.Rationale
  if($c.Status -eq 'N/A'){$why='Applicability was explicitly excluded; review the detailed local evidence for the operator decision.'}
  $limit=[string](Get-AuditProperty $c 'Limitation' '')
  $rationale=($why+' '+$limit).Trim()
  # Checks are always recomputed by the evaluator, never read from supplied Checks
  # or Recommendations. Only its explicit authority marker identifies Microsoft
  # recommendations: a Microsoft documentation URL alone does not endorse a local rule.
  if((Get-AuditProperty $c 'RecommendationAuthority' '') -ceq 'Microsoft'){
   $expected=Get-AuditProperty $c 'Expected' ''
   $reference=Get-AuditProperty $c 'Reference' ''
   if($expected -isnot [string] -or [string]::IsNullOrWhiteSpace($expected) -or
      $reference -isnot [string] -or $reference -cnotmatch '^https://learn\.microsoft\.com/[A-Za-z0-9/_?=&.#%+-]+$'){
    throw 'Microsoft recommendation display requires a static expected setting and Microsoft Learn reference.'
   }
   $rationale='Microsoft recommendation: '+$expected+' '+$rationale+' Reference: '+$reference
  }
  [pscustomobject][ordered]@{
   'Control'=ConvertTo-FlapjacksDisplayText $c.Control
   'Status'=[string]$c.Status
   'Status details'=ConvertTo-FlapjacksDisplayText $details
   'Rationale'=ConvertTo-FlapjacksDisplayText $rationale
   'M365 access/licensing/prerequisites'=ConvertTo-FlapjacksDisplayText $access
  }
 }
}
function Get-FlapjacksCoverageOutcome {
 param([string]$Status,[long]$Count)
 switch -CaseSensitive ($Status){
  'Collected' {if($Count -eq 0){'Read OK / empty'}else{'Read OK'}}
  'Partial' {'Partial / unknown'}
  {$_ -cin @('NotConnected','ModuleUnavailable')} {'Session/module gap'}
  {$_ -cin @('AccessDenied','Unauthorized','InsufficientPermissions')} {'Access gap'}
  {$_ -cin @('Error','Throttled','Unavailable')} {'Error / unavailable'}
  'NotSelected' {'Not selected'}
  'NotProvided' {'Fixture gap'}
  'OfflineSnapshot' {'Offline / unverified'}
  'Unlicensed' {'License gap'}
  {$_ -cin @('TenantMismatch','IdentityMismatch','UnsupportedCloud')} {'Context / scope gap'}
  default {'Unknown / gap'}
 }
}
function ConvertTo-FlapjacksXmlText {
 param([AllowNull()][object]$Value)
 $s=ConvertTo-AuditCsvValue $Value
 # XML 1.0 forbids certain code points, including control characters retained in raw evidence JSON.
 $s=[regex]::Replace($s,'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]','?')
 return [Security.SecurityElement]::Escape($s)
}
function Write-FlapjacksPostureWorkbook {
 [CmdletBinding()]
 param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object[]]$Controls,[Parameter(Mandatory)][object[]]$Coverage,[Parameter(Mandatory)][string[]]$Notes)
 # Dependency-free Office Open XML. All cells are inline strings, never formulas or external links.
 $sheets=@(
  @{Name='Controls';Columns=@('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites');Rows=$Controls;Widths=@(31,24,60,85,62)},
  @{Name='Source coverage';Columns=@('Source','Collection state','Returned records');Rows=$Coverage;Widths=@(48,32,20)},
  @{Name='Read me';Columns=@('Report notes');Rows=@($Notes|ForEach-Object {[pscustomobject]@{'Report notes'=$_}});Widths=@(130)}
 )
 $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 $zip=$null
 try{
  $zip=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$true)
  function Entry([string]$Name,[string]$Content){
   $entry=$zip.CreateEntry($Name,[IO.Compression.CompressionLevel]::Optimal)
   $stream=$entry.Open();$writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false))
   try{$writer.Write($Content)}finally{$writer.Dispose();$stream.Dispose()}
  }
  $ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
  $types='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
  $workbook='<workbook xmlns="'+$ns+'" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets>'
  $rels='<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  $number=0
  foreach($sheet in $sheets){
   $number++;$lastRow=@($sheet.Rows).Count+1;$lastCol=[char](64+$sheet.Columns.Count)
   $types+='<Override PartName="/xl/worksheets/sheet'+$number+'.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
   $workbook+='<sheet name="'+(ConvertTo-FlapjacksXmlText $sheet.Name)+'" sheetId="'+$number+'" r:id="rId'+$number+'"/>'
   $rels+='<Relationship Id="rId'+$number+'" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet'+$number+'.xml"/>'
   $xml=[Text.StringBuilder]::new()
   [void]$xml.Append('<worksheet xmlns="'+$ns+'"><dimension ref="A1:'+$lastCol+$lastRow+'"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/><cols>')
   for($col=1;$col -le $sheet.Columns.Count;$col++){[void]$xml.Append('<col min="'+$col+'" max="'+$col+'" width="'+$sheet.Widths[$col-1]+'" customWidth="1"/>')}
   [void]$xml.Append('</cols><sheetData><row r="1" ht="32" customHeight="1">')
   for($col=1;$col -le $sheet.Columns.Count;$col++){
    $ref=([string][char](64+$col))+'1';$value=ConvertTo-FlapjacksXmlText $sheet.Columns[$col-1]
    [void]$xml.Append('<c r="'+$ref+'" s="1" t="inlineStr"><is><t xml:space="preserve">'+$value+'</t></is></c>')
   }
   [void]$xml.Append('</row>');$rn=1
   foreach($row in $sheet.Rows){
    $rn++;$lineCount=1
    for($col=0;$col -lt $sheet.Columns.Count;$col++){
     $v=[string](Get-AuditProperty $row $sheet.Columns[$col] '')
     # Generous automatic height estimate avoids clipping multi-line wrapped cells in Excel.
     $estimate=[int][Math]::Ceiling($v.Length/([double]$sheet.Widths[$col]*0.8))+1
     $lineCount=[Math]::Max($lineCount,$estimate)
    }
    $height=[Math]::Min(409,[Math]::Max(30,15*$lineCount))
    [void]$xml.Append('<row r="'+$rn+'" ht="'+$height+'" customHeight="1">')
    for($col=1;$col -le $sheet.Columns.Count;$col++){
     $ref=([string][char](64+$col))+$rn;$style=if($rn%2 -eq 0){2}else{3}
     if($sheet.Name -eq 'Controls' -and $col -eq 2){
      $style=switch([string]$row.Status){'Meets selected setting'{4};'Needs action'{5};default{6}}
     }
     $value=ConvertTo-FlapjacksXmlText (Get-AuditProperty $row $sheet.Columns[$col-1] '')
     [void]$xml.Append('<c r="'+$ref+'" s="'+$style+'" t="inlineStr"><is><t xml:space="preserve">'+$value+'</t></is></c>')
    }
    [void]$xml.Append('</row>')
   }
   [void]$xml.Append('</sheetData><autoFilter ref="A1:'+$lastCol+$lastRow+'"/><printOptions horizontalCentered="1"/><pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.2" footer="0.2"/><pageSetup paperSize="9" orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>')
   Entry ('xl/worksheets/sheet'+$number+'.xml') $xml.ToString()
  }
  $rels+='<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
  Entry '[Content_Types].xml' ($types+'</Types>')
  Entry '_rels/.rels' '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
  Entry 'xl/workbook.xml' ($workbook+'</sheets><definedNames><definedName name="_xlnm.Print_Titles" localSheetId="0">''Controls''!$1:$1</definedName><definedName name="_xlnm.Print_Titles" localSheetId="1">''Source coverage''!$1:$1</definedName></definedNames></workbook>')
  Entry 'xl/_rels/workbook.xml.rels' $rels
  Entry 'xl/styles.xml' @'
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="5"><font><sz val="11"/><color rgb="FF092036"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FF106C4D"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FF973F12"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FF555C65"/><name val="Calibri"/></font></fonts><fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF076B7A"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF0F6F8"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="7"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="49" fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="49" fontId="0" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="49" fontId="2" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="49" fontId="3" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="49" fontId="4" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>
'@
 }finally{if($null -ne $zip){$zip.Dispose()};$file.Dispose()}
}
function Write-FlapjacksPosturePdf {
 [CmdletBinding()]
 param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object[]]$Controls,[Parameter(Mandatory)][object[]]$Coverage,[Parameter(Mandatory)][string[]]$Notes,[Parameter(Mandatory)][string]$Summary,[Parameter(Mandatory)][string]$CoverageSummary,[bool]$Synthetic)
 # Portable landscape A4 PDF 1.4, built-in Helvetica, no renderer or embedded active content.
 $invariant=[Globalization.CultureInfo]::InvariantCulture
 function Num([double]$v){$v.ToString('0.###',$invariant)}
 function Escape([string]$s){$s.Replace('\','\\').Replace('(','\(').Replace(')','\)')}
 $widths=@(278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584)
 function TextWidth([string]$s,[double]$size,[bool]$bold=$false){$sum=0;foreach($ch in $s.ToCharArray()){$i=[int]$ch-32;if($i -ge 0 -and $i -lt $widths.Count){$sum+=$widths[$i]}else{$sum+=600}};return $sum*$size/1000*$(if($bold){1.08}else{1.0})}
 function Wrap([string]$s,[double]$width,[double]$size,[bool]$bold=$false){
  $lines=[Collections.Generic.List[string]]::new();$line=''
  foreach($word in ($s -split '\s+')){
   if(-not $word){continue}
   $proposed=if($line){$line+' '+$word}else{$word}
   if((TextWidth $proposed $size $bold) -le $width){$line=$proposed;continue}
   if($line){$lines.Add($line);$line=''}
   $piece='';foreach($ch in $word.ToCharArray()){
    if($piece -and (TextWidth ($piece+$ch) $size $bold) -gt $width){$lines.Add($piece);$piece=''}
    $piece+=$ch
   }
   $line=$piece
  }
  if($line -or $lines.Count -eq 0){$lines.Add($line)}
  return ,$lines.ToArray()
 }
 function Text($b,[double]$x,[double]$top,[string]$s,[double]$size=9,[bool]$bold=$false,[string]$color='0.035 0.12 0.21'){
  $font=if($bold){'F2'}else{'F1'}
  [void]$b.AppendLine("$color rg BT /$font $(Num $size) Tf $(Num $x) $(Num (595-$top-$size)) Td ($(Escape $s)) Tj ET")
 }
 function Rect($b,[double]$x,[double]$top,[double]$w,[double]$h,[string]$color){[void]$b.AppendLine("$color rg $(Num $x) $(Num (595-$top-$h)) $(Num $w) $(Num $h) re f")}
 function Paragraph($b,[double]$x,[double]$top,[double]$w,[string]$s,[double]$size=9,[bool]$bold=$false,[string]$color='0.32 0.38 0.43'){
  $lineY=$top;foreach($line in (Wrap $s $w $size $bold)){Text $b $x $lineY $line $size $bold $color;$lineY+=$size*1.25};return $lineY
 }
 $pages=[Collections.Generic.List[object]]::new()
 function Page([string]$title,[string]$subtitle){
  $b=[Text.StringBuilder]::new();Rect $b 0 0 842 80 '0.035 0.12 0.21';Text $b 30 15 $title 23 $true '1 1 1';Text $b 30 51 $subtitle 9.5 $false '0.65 0.87 0.89';return $b
 }
 $headers=@('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
 $xs=@(30,145,239,422,622,812);$font=8.3;$lineHeight=10.4;$pad=7
 function TableHeader($b,[double]$top){
  Rect $b 30 $top 782 32 '0.03 0.42 0.48'
  for($col=0;$col -lt 5;$col++){[void](Paragraph $b ($xs[$col]+$pad) ($top+6) ($xs[$col+1]-$xs[$col]-2*$pad) $headers[$col] 8.3 $true '1 1 1')}
 }
 $b=Page 'Posture Report' ('Saved Microsoft 365 evidence | '+$Controls.Count+' selected controls | No tenant changes')
 [void](Paragraph $b 30 92 782 $Summary 12 $true '0.035 0.12 0.21')
 $mode=if($Synthetic){'SYNTHETIC DEMONSTRATION. Invented data, not tenant evidence. '}else{'LOCAL SAVED-EVIDENCE REVIEW. Not a live recheck. '}
 [void](Paragraph $b 30 116 782 ($mode+'Meets applies only to the named setting, not effective protection or Microsoft/NIST compliance.') 9)
 $top=151;TableHeader $b $top;$top+=32;$rowNumber=0
 foreach($row in $Controls){
  $cells=@();$maxLines=0
  for($col=0;$col -lt 5;$col++){
   $lines=Wrap ([string](Get-AuditProperty $row $headers[$col] '')) ($xs[$col+1]-$xs[$col]-2*$pad) $font ($col -lt 2)
   $cells+=,@($lines);$maxLines=[Math]::Max($maxLines,$lines.Count)
  }
  $height=[Math]::Max(55,$maxLines*$lineHeight+2*$pad)
  if($height -gt 410){throw 'A display control row is too long for a readable PDF; shorten the static definition.'}
  if($top+$height -gt 542){
   $pages.Add($b);$b=Page 'Posture Report | controls' ('Continued | '+$Controls.Count+' selected controls | Unknown is never a pass')
   $top=95;TableHeader $b $top;$top+=32
  }
  $rowNumber++;Rect $b 30 $top 782 $height $(if($rowNumber%2){'0.94 0.965 0.975'}else{'1 1 1'})
  [void]$b.AppendLine('0.80 0.85 0.87 RG 0.4 w 30 '+(Num (595-$top-$height))+' m 812 '+(Num (595-$top-$height))+' l S')
  for($col=0;$col -lt 5;$col++){
   $color='0.035 0.12 0.21'
   if($col -eq 1){$color=switch($row.Status){'Meets selected setting'{'0.06 0.40 0.29'};'Needs action'{'0.59 0.25 0.06'};default{'0.32 0.38 0.43'}}}
   $y=$top+$pad;foreach($line in $cells[$col]){Text $b ($xs[$col]+$pad) $y $line $font ($col -lt 2) $color;$y+=$lineHeight}
  }
  $top+=$height
 }
 $pages.Add($b)
 # Coverage is always separate from controls, with safe catalog labels and typed counts only.
 $chunkSize=46
 for($start=0;$start -lt $Coverage.Count;$start+=$chunkSize){
  $b=Page 'Source coverage' 'Collection outcomes are separate from assessed settings | Identities and raw errors omitted'
  [void](Paragraph $b 30 94 782 $CoverageSummary 12 $true '0.035 0.12 0.21')
  [void](Paragraph $b 30 120 782 'A successful empty response is not missing access. Partial, denied, errored or unavailable sources remain unknown, never satisfied controls.' 9)
  for($col=0;$col -lt 2;$col++){
   $x=30+$col*398;Text $b $x 159 'SOURCE' 8 $true '0.03 0.42 0.48';Text $b ($x+216) 159 'COLLECTION STATE' 8 $true '0.03 0.42 0.48';Text $b ($x+350) 159 'ROWS' 8 $true '0.03 0.42 0.48'
   for($n=0;$n -lt 23;$n++){
    $index=$start+$col*23+$n;if($index -ge $Coverage.Count){break};$item=$Coverage[$index];$y=180+$n*14
    Text $b $x $y ([string]$item.Source) 7.5;Text $b ($x+216) $y ([string]$item.'Collection state') 7.5;Text $b ($x+350) $y ([string]$item.'Returned records') 7.5
   }
  }
  [void](Paragraph $b 30 518 782 'Collection success does not prove a control is enabled or effective. Licensing and operator access are not independently certified.' 9)
  $pages.Add($b)
 }
 $b=Page 'Scope and limitations' 'Read this report with the detailed local evidence bundle'
 $y=99
 foreach($note in $Notes){
  $noteLines=Wrap $note 760 10 $false;$height=$noteLines.Count*12.5+12
  if($y+$height -gt 540){$pages.Add($b);$b=Page 'Scope and limitations' 'Continued';$y=99}
  Text $b 31 $y '-' 10 $true;$y=Paragraph $b 47 $y 760 $note 10;$y+=12
 }
 $pages.Add($b)
 $objects=[Collections.Generic.List[string]]::new();$objects.Add('<< /Type /Catalog /Pages 2 0 R >>');$objects.Add('');$objects.Add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');$objects.Add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>')
 $kids=[Collections.Generic.List[string]]::new();$pageNumber=0
 foreach($page in $pages){
  $pageNumber++;Text $page 30 567 'FLAPJACKS | Redacted display summary | Detailed evidence stays local' 8 $false '0.32 0.38 0.43';Text $page 755 567 ('Page '+$pageNumber+' / '+$pages.Count) 8 $false '0.32 0.38 0.43'
  $pageId=$objects.Count+1;$contentId=$pageId+1;$kids.Add("$pageId 0 R")
  $objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents $contentId 0 R >>")
  $content=$page.ToString();$length=[Text.Encoding]::ASCII.GetByteCount($content);$objects.Add("<< /Length $length >>`nstream`n$content"+"endstream")
 }
 $objects[1]='<< /Type /Pages /Count '+$pages.Count+' /Kids ['+($kids -join ' ')+'] >>'
 $buffer=[Text.StringBuilder]::new();[void]$buffer.Append("%PDF-1.4`n");$offsets=[Collections.Generic.List[int]]::new();$offsets.Add(0)
 for($n=0;$n -lt $objects.Count;$n++){$offsets.Add([Text.Encoding]::ASCII.GetByteCount($buffer.ToString()));[void]$buffer.Append("$($n+1) 0 obj`n$($objects[$n])`nendobj`n")}
 $xref=[Text.Encoding]::ASCII.GetByteCount($buffer.ToString());[void]$buffer.Append("xref`n0 $($objects.Count+1)`n0000000000 65535 f `n")
 foreach($offset in @($offsets|Select-Object -Skip 1)){[void]$buffer.Append($offset.ToString('0000000000')+" 00000 n `n")}
 [void]$buffer.Append("trailer`n<< /Size $($objects.Count+1) /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n")
 $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$bytes=[Text.Encoding]::ASCII.GetBytes($buffer.ToString());$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()}
 return $pages.Count
}
function ConvertFrom-FlapjacksEvidenceJson {
 # ConvertFrom-Json on PowerShell 7.4 coerces ISO date strings to DateTime and loses
 # the original text/offset. System.Text.Json is included with PowerShell's .NET
 # runtime and preserves JSON strings without installing a parser dependency.
 param([Parameter(Mandatory)][string]$Json)
 $options=[Text.Json.JsonDocumentOptions]::new();$options.MaxDepth=100
 $document=[Text.Json.JsonDocument]::Parse($Json,$options)
 function Element([Text.Json.JsonElement]$Node){
  switch($Node.ValueKind){
   'Object' {
    $properties=[ordered]@{};$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($property in $Node.EnumerateObject()){
     if(-not $names.Add($property.Name)){throw 'Duplicate JSON property name refused; no output created.'}
     $properties[$property.Name]=Element $property.Value
    }
    return [pscustomobject]$properties
   }
   'Array' {$items=[Collections.Generic.List[object]]::new();foreach($item in $Node.EnumerateArray()){$items.Add((Element $item))};return ,$items.ToArray()}
   'String' {return $Node.GetString()}
   'Number' {
    $integer=[long]0
    if($Node.TryGetInt64([ref]$integer)){return $integer}
    $number=[decimal]0
    if($Node.TryGetDecimal([ref]$number)){return $number}
    $double=$Node.GetDouble();if([double]::IsNaN($double) -or [double]::IsInfinity($double)){throw 'Non-finite JSON number refused.'};return $double
   }
   'True' {return $true}
   'False' {return $false}
   'Null' {return $null}
   default {throw 'Unsupported JSON value; no output created.'}
  }
 }
 try{return Element $document.RootElement}finally{$document.Dispose()}
}
function Export-FlapjacksPostureBundle {
 [CmdletBinding(DefaultParameterSetName='File')]
 param(
  [Parameter(Mandatory,ParameterSetName='File')][string]$InputJson,
  [Parameter(Mandatory,ParameterSetName='Object')]$Result,
  [Parameter(Mandatory)][string]$OutputDirectory
 )
 $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
 function Value($o,[string]$n,$default=$null){$v=Get-AuditProperty $o $n $default;return $v}
 function NoLinks([string]$path){for($p=[IO.Path]::GetFullPath($path);$p;$p=[IO.Path]::GetDirectoryName($p)){if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Symlink/reparse path refused.'}}}
 if($PSCmdlet.ParameterSetName -eq 'File'){NoLinks $InputJson;$Result=ConvertFrom-FlapjacksEvidenceJson -Json (Get-Content -LiteralPath $InputJson -Raw)}
 $metadata=Value $Result 'Metadata';if($null -eq $metadata){throw 'Audit Metadata required.'}
 $rows=@(Value $Result 'Evidence' @());if(-not $rows.Count){$rows=@(Value $Result 'Coverage' @())}
 if(-not $rows.Count){throw 'Full source Evidence or Coverage required; no sources supplied.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($r in $rows){
  $id=[string](Value $r 'SourceId' '')
  if($id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or -not $seen.Add($id)){throw 'Invalid or duplicate source ID; no output created.'}
  $count=Value $r 'Count'
  if($count -isnot [int] -and $count -isnot [long]){throw 'Source Count must be an integer.'}
  if($count -lt 0 -or $count -ne @(Value $r 'Items' @()).Count){throw 'Source Count does not match Items.'}
  if($null -eq $r.PSObject.Properties['Items'] -and -not ($r -is [Collections.IDictionary] -and $r.Contains('Items'))){throw 'Summary-only source lacks Items; supply full Evidence/audit.json.'}
 }
 $observations=@(Value $Result 'Observations' @())
 $checks=if(Get-Command Get-FlapjacksAllPostureChecks -ErrorAction SilentlyContinue){@(Get-FlapjacksAllPostureChecks -Result $Result)}else{@(Get-FlapjacksPostureChecks -Result $Result)}
 if(-not $checks.Count){throw 'No posture controls were produced; no output created.'}
 $controlIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($c in $checks){
  if([string]$c.ControlId -cnotmatch '^[A-Z][A-Z0-9-]{1,99}$' -or -not $controlIds.Add([string]$c.ControlId) -or $c.Status -cnotin @('Meets selected setting','Needs action','Not assessed','N/A')){throw 'Invalid or duplicate posture control; no output created.'}
 }
 $display=@(Get-FlapjacksControlDisplayRows -Checks $checks)
 $out=[IO.Path]::GetFullPath($OutputDirectory);NoLinks $out
 if(Test-Path -LiteralPath $out){throw 'Output directory exists; overwrite refused.'}
 if(-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($out)) -PathType Container)){throw 'An existing output parent directory is required.'}
 $selectedGroups=@(Value $metadata 'SelectedGroups' @())
 $catalog=@(Get-AuditSourceCatalog)
 if(Get-Command Get-FlapjacksWorkbookSources -ErrorAction SilentlyContinue){$catalog+=@(Get-FlapjacksWorkbookSources)}
 if($selectedGroups.Count){
  $knownGroups=@('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')
  if(@($selectedGroups|Where-Object {$_ -isnot [string] -or $_ -cnotin $knownGroups}).Count){throw 'Unrecognized selected source group; no output created.'}
  $plan=Get-M365AuditPlan -Include @($selectedGroups|Where-Object {$_ -cne 'Core'})
 }else{$plan=Get-M365OrganizationAuditPlan}
 $known=@{};foreach($c in $catalog){$known[$c.Id]=$true}
 $coverage=@();$index=0
 foreach($r in $rows){
  $index++;$id=[string]$r.SourceId;$label=if($known.ContainsKey($id)){$id}else{'source-'+$index.ToString('000')}
  $coverage+=[pscustomobject][ordered]@{'Source'=$label;'Collection state'=Get-FlapjacksCoverageOutcome ([string]$r.Status) ([long]$r.Count);'Returned records'=[long]$r.Count}
 }
 $synthetic=([string](Value $metadata 'Mode' 'Unknown')) -ceq 'Synthetic'
 $read=@($rows|Where-Object {$_.Status -ceq 'Collected'});$empty=@($read|Where-Object {[long]$_.Count -eq 0})
 $gaps=@($rows|Where-Object {$_.Status -cnotin @('Collected','NotSelected')});$notSelected=@($rows|Where-Object {$_.Status -ceq 'NotSelected'})
 $meets=@($checks|Where-Object Status -eq 'Meets selected setting').Count;$action=@($checks|Where-Object Status -eq 'Needs action').Count;$unassessed=@($checks|Where-Object Status -eq 'Not assessed').Count;$na=@($checks|Where-Object Status -eq 'N/A').Count
 $summary="$meets meet selected setting  /  $action need action  /  $unassessed not assessed  /  $na N/A"
 $coverageSummary="$($rows.Count) source entries  /  $($read.Count) successful reads  /  $($empty.Count) empty reads  /  $($gaps.Count) gaps"
 $notes=@(
  $(if($synthetic){'SYNTHETIC DEMONSTRATION: all results are invented examples, not tenant evidence.'}else{'LOCAL SAVED-EVIDENCE REVIEW: source data is not independently verified and this is not a live recheck.'}),
  ($summary+'. '+$checks.Count+' named control rows, not a tenant-wide compliance score.'),
  'The PDF, Controls worksheet and Posture-Report.csv use the same control rows. Source coverage is reported separately and is not a list of passed controls.',
  'Meets selected setting is limited to the exact setting and saved evidence. Policy presence is not effective user/device/recipient protection. Needs action is a selected-baseline result, not proof of compromise.',
  'Not assessed means evidence is missing, incomplete, unsupported or insufficient. No missing permission, empty response, unselected source or collection error is treated as a pass, failure or N/A.',
  'A successful empty response is a completed read with zero returned records. HTTP 400 on PIM/role eligibility does NOT establish that PIM is not configured.',
  'Current configuration is not an atomic snapshot or historical reconstruction. Applicability, licensing and operator roles require independent review. Prerequisites are context, not a request to grant permissions.',
  'Rows explicitly labeled Microsoft recommendation show the expected setting and Microsoft Learn reference in Rationale. Other selected settings are not relabeled as Microsoft recommendations. Guidance and analyst-selected NIST CSF 2.0 mappings do not prove compliance, CSF outcome attainment or certification. Full references and limitations are in checks.csv/json.',
  'This workbook does not establish effective Conditional Access, complete user/admin MFA coverage, historical activity, incident-response readiness, tested recovery or protection of every mailbox/device. Collection scope is documented in collection-plan.json.',
  'This redacted display excludes tenant/user/object identities, evidence URLs, raw policies and raw errors. Static Microsoft Learn recommendation URLs are inert reference text, not fetched evidence. Detailed local CSV/JSON may contain sensitive data. Do not upload real evidence.',
  'coverage.csv preserves exact source status/reason; inventory.csv and evidence/*.json retain source-tagged data; observations.csv retains supplied findings. A source read or observation is not a tested control.',
  'CSV formula-leading cells are neutralized. XLSX cells are literal text with no formulas, macros or external links. JSON preserves original evidence values.',
  'No authentication, collection, installation, remediation or tenant change is performed by export. Hashes detect later file changes; they do not certify evidence provenance or accuracy.'
 )
 if('WorkbookExchange' -cin $selectedGroups){
  $savedBaseline=Value $metadata 'WorkbookAntiPhishBaseline'
  $profile=if($savedBaseline -is [string] -and $savedBaseline -cin @('Standard','Strict')){$savedBaseline}else{'Not selected (None, missing or unsupported saved value)'}
  $notes=@($notes[0],('Saved Microsoft mail recommendation profile: '+$profile+'. A selected profile is a comparison choice, not proof that Microsoft preset policies are enabled.'))+@($notes|Select-Object -Skip 1)
 }
 # Nothing above creates a file. The explicitly requested export is the only write boundary.
 [void](New-Item -ItemType Directory -Path $out -ErrorAction Stop)
 Export-AuditReport -Path $out -Metadata $metadata -Results $rows -Observations $observations -Catalog $catalog -Plan $plan
 $checkColumns=@('ControlId','Control','Status','SourceId','Field','SourceStatus','EvidenceIds','EvidenceTime','Observed','StatusDetailsSafe','Expected','RecommendationAuthority','Rationale','Limitation','AccessPrerequisites','Reference','ProfileVersion','NistCsf20EvidenceMapping','NistFramework','NistReference','NistMappingNote')
 Write-AuditCsv (Join-Path $out 'checks.csv') $checks $checkColumns
 Write-AuditJson (Join-Path $out 'checks.json') $checks
 Write-AuditCsv (Join-Path $out 'Posture-Report.csv') $display @('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
 Write-FlapjacksPostureWorkbook -Path (Join-Path $out 'Posture-Report.xlsx') -Controls $display -Coverage $coverage -Notes $notes
 $pdfPages=Write-FlapjacksPosturePdf -Path (Join-Path $out 'Posture-Report.pdf') -Controls $display -Coverage $coverage -Notes $notes -Summary $summary -CoverageSummary $coverageSummary -Synthetic $synthetic
 # Existing menu/test consumers can continue using review.pdf; it is an exact compatibility copy.
 [IO.File]::Copy((Join-Path $out 'Posture-Report.pdf'),(Join-Path $out 'review.pdf'),$false)
 $files=@(Get-ChildItem -LiteralPath $out -File -Recurse|Where-Object Name -ne 'manifest.json'|Sort-Object FullName|ForEach-Object {[pscustomobject]@{Path=[IO.Path]::GetRelativePath($out,$_.FullName).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
 Write-AuditJson (Join-Path $out 'manifest.json') ([ordered]@{SchemaVersion='1.0';GeneratedAtUtc=[DateTime]::UtcNow.ToString('o');Algorithm='SHA256';Files=$files})
 [pscustomobject]@{OutputDirectory=$out;Sources=$rows.Count;SuccessfulReads=$read.Count;EmptyReads=$empty.Count;Gaps=$gaps.Count;NotSelected=$notSelected.Count;Observations=$observations.Count;PdfPages=$pdfPages;PostureChecks=$checks.Count;Synthetic=$synthetic;Pdf='Posture-Report.pdf';Workbook='Posture-Report.xlsx';Csv='Posture-Report.csv'}
}
