#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Parser=Import-Module (Join-Path $PSScriptRoot 'FlapjacksJsonParser.psm1') -PassThru -DisableNameChecking
function Parse-Local([string]$s,[long]$maximum){
 if([string]::IsNullOrWhiteSpace($s) -or [Text.Encoding]::UTF8.GetByteCount($s) -gt $maximum){throw 'Passive JSON bound.'}
 return & $script:Parser {param($t)ConvertFrom-FjcJson $t} $s
}

function Utc($v){
 $t=[datetimeoffset]::MinValue
 if($v -is [string] -and $v -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$' -and [datetimeoffset]::TryParse($v,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$t)){return $t}
 return $null
}

function Walk-Passive($v,[int]$depth){
 $script:Nodes++
 if($script:Nodes -gt 8192 -or $depth -gt 20){throw 'Passive structure bound.'}
 if($v -is [Collections.IDictionary]){
  foreach($k in $v.Keys){
   if($k -match '@odata\.(nextLink|deltaLink)$' -or $k -in @('Timeline','Collections','CasePath','TargetUpn','mailbox_upn','MessageId','NetworkMessageId','signIns','Correlations','RunId','TenantId')){throw 'Incident, continuation or conflicting identity refused.'}
   Walk-Passive $v[$k] ($depth+1)
  }
 }elseif($v -is [array]){foreach($x in $v){Walk-Passive $x ($depth+1)}}
}
