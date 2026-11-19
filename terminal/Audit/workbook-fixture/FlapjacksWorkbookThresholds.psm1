#requires -Version 7.4
# Explicit, offline workbook-reference comparisons. No collectors or host registration.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:FjwtWorkbookHash='92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'

function ConvertFrom-FjwtJson([string]$Text){
 if([string]::IsNullOrWhiteSpace($Text) -or [Text.Encoding]::UTF8.GetByteCount($Text) -gt 65536){throw 'Supply bounded passive JSON.'}
 $options=[Text.Json.JsonDocumentOptions]::new();$options.MaxDepth=16
 $document=$null
 function Read-Node([Text.Json.JsonElement]$Node){
  switch($Node.ValueKind){
   'Object' {
    $map=[ordered]@{};$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($property in $Node.EnumerateObject()){
     if(-not $names.Add($property.Name)){throw 'Ambiguous JSON keys.'}
     $map.Add($property.Name,(Read-Node $property.Value))
    }
    return ,$map
   }
   'Array' {$list=[Collections.Generic.List[object]]::new();foreach($value in $Node.EnumerateArray()){$list.Add((Read-Node $value))};return ,$list.ToArray()}
   'String' {return $Node.GetString()}
   'Number' {$integer=[long]0;if($Node.TryGetInt64([ref]$integer)){return $integer};return $Node.GetDouble()}
   'True' {return $true}
   'False' {return $false}
   'Null' {return $null}
   default {throw 'Unsupported JSON value.'}
  }
 }
 try{$document=[Text.Json.JsonDocument]::Parse($Text,$options);return Read-Node $document.RootElement}
 catch{throw 'Invalid passive JSON.'}
 finally{if($null -ne $document){$document.Dispose()}}
}

function Get-FjwtValue($Object,[string]$Key){
 if($Object -is [Collections.IDictionary] -and $Object.Contains($Key)){
  if($Key -cnotin @($Object.Keys)){return $null}
  return ,$Object[$Key]
 }
 return $null
}

function Assert-FjwtKeys($Object,[string[]]$Allowed,[string[]]$Required){
 if($Object -isnot [Collections.IDictionary]){throw 'Expected a passive object.'}
 foreach($key in $Object.Keys){if($key -cnotin $Allowed){throw 'Unsupported contract key.'}}
 foreach($key in $Required){if($key -cnotin @($Object.Keys)){throw 'Missing contract key.'}}
}

function Test-FjwtText($Value,[string]$Expected){return ($Value -is [string] -and $Value -ceq $Expected)}

function Get-FlapjacksWorkbookThresholdComparison {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)][AllowEmptyString()][string]$EvidenceJson,
  [Parameter(Mandatory)][string]$ExpectedWorkbookSha256,
  [switch]$EnableExactWorkbookComparison
 )
 if(-not $EnableExactWorkbookComparison){throw 'Explicit workbook-reference opt-in is required.'}
 if($ExpectedWorkbookSha256 -cne $script:FjwtWorkbookHash){throw 'Exact workbook reference does not match.'}
 try{
  $snapshot=ConvertFrom-FjwtJson $EvidenceJson
  Assert-FjwtKeys $snapshot @('SchemaVersion','Metadata','Evidence') @('SchemaVersion','Metadata','Evidence')
  if(-not (Test-FjwtText (Get-FjwtValue $snapshot 'SchemaVersion') 'FlapjacksWorkbookThresholdEvidence/1')){throw 'Unsupported evidence schema.'}
  $meta=Get-FjwtValue $snapshot 'Metadata'
  Assert-FjwtKeys $meta @('Mode','TenantId','RunId','ReferenceWorkbookSha256') @('Mode','TenantId','RunId','ReferenceWorkbookSha256')
  if(-not (Test-FjwtText (Get-FjwtValue $meta 'Mode') 'Synthetic') -or -not (Test-FjwtText (Get-FjwtValue $meta 'ReferenceWorkbookSha256') $script:FjwtWorkbookHash)){throw 'Unsupported mode or reference.'}
  $tenant=Get-FjwtValue $meta 'TenantId';$run=Get-FjwtValue $meta 'RunId';$guid=[guid]::Empty
  if($tenant -isnot [string] -or -not [guid]::TryParseExact($tenant,'D',[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Invalid synthetic tenant binding.'}
  if($run -isnot [string] -or $run -cnotmatch '^synthetic-[a-z0-9-]{1,64}$'){throw 'Invalid synthetic run binding.'}
  $sources=Get-FjwtValue $snapshot 'Evidence'
  if($sources -isnot [array] -or $sources.Count -gt 2){throw 'Expected at most two fixed sources.'}
  $byId=@{}
  foreach($source in $sources){
   Assert-FjwtKeys $source @('SourceId','Provider','Target','TenantId','RunId','Status','CompletenessClaim','Count','MissingFields','Items') @('SourceId')
   $id=Get-FjwtValue $source 'SourceId'
   if($id -isnot [string] -or $id -cnotin @('exchange-antiphish-policies','exchange-antispam-policies') -or $byId.ContainsKey($id)){throw 'Unknown or duplicate source.'}
   $byId[$id]=$source
  }
 }catch{throw 'Workbook evidence contract refused; no source interaction occurred.'}

 $definitions=@(
  @{Id='WB-REF-92B9-ROW-031';Row=31;Title='Workbook row 31: phishing threshold';Source='exchange-antiphish-policies';Target='Get-AntiPhishPolicy';Field='PhishThresholdLevel';Minimum=1;Maximum=4;Operator='AtLeast';Threshold=2;Predicate='PhishThresholdLevel >= 2'},
  @{Id='WB-REF-92B9-ROW-069';Row=69;Title='Workbook row 69: bulk complaint threshold';Source='exchange-antispam-policies';Target='Get-HostedContentFilterPolicy';Field='BulkThreshold';Minimum=1;Maximum=9;Operator='AtMost';Threshold=6;Predicate='BulkThreshold <= 6'}
 )
 $rows=[Collections.Generic.List[object]]::new();$display=[Collections.Generic.List[object]]::new()
 foreach($definition in $definitions){
  $source=$byId[$definition.Source]
  $comparison='Unknown';$reason='SourceMissing';$count=$null;$compared=$null;$matching=$null
  if($null -ne $source){
   $items=Get-FjwtValue $source 'Items';$suppliedCount=Get-FjwtValue $source 'Count';$missing=Get-FjwtValue $source 'MissingFields'
   if(-not (Test-FjwtText (Get-FjwtValue $source 'Provider') 'Exchange') -or -not (Test-FjwtText (Get-FjwtValue $source 'Target') $definition.Target)){$reason='SourceContractMismatch'}
   elseif(-not (Test-FjwtText (Get-FjwtValue $source 'TenantId') $tenant) -or -not (Test-FjwtText (Get-FjwtValue $source 'RunId') $run)){$reason='RunOrTenantMismatch'}
   elseif(-not (Test-FjwtText (Get-FjwtValue $source 'Status') 'Collected') -or -not (Test-FjwtText (Get-FjwtValue $source 'CompletenessClaim') 'Complete')){$reason='IncompleteSource'}
   elseif($items -isnot [array] -or $items.Count -gt 512 -or $suppliedCount -isnot [long] -or $suppliedCount -lt 0 -or $suppliedCount -ne $items.Count){$reason='InvalidCountOrItems'}
   elseif($missing -isnot [array] -or $missing.Count -ne 0){$reason='MissingFields'}
   elseif($items.Count -eq 0){$count=0;$reason='EmptySource'}
   else{
    $count=$suppliedCount;$valid=$true;$matches=0
    $identities=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in $items){
     if($item -isnot [Collections.IDictionary]){$valid=$false;$reason='InvalidPolicyRecord';break}
     if(@($item.Keys | Where-Object {$_ -cnotin @('Identity',$definition.Field)}).Count){$valid=$false;$reason='UnsupportedPolicyFields';break}
     $identity=Get-FjwtValue $item 'Identity';$value=Get-FjwtValue $item $definition.Field
     if($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or $identity.Length -gt 256 -or $identity.Trim() -cne $identity -or -not $identities.Add($identity)){$valid=$false;$reason='MissingOrDuplicatePolicyIdentity';break}
     if($value -isnot [long] -or $value -lt $definition.Minimum -or $value -gt $definition.Maximum){$valid=$false;$reason='MissingMalformedOrOutOfRangeValue';break}
     $meets=if($definition.Operator -ceq 'AtLeast'){$value -ge $definition.Threshold}else{$value -le $definition.Threshold}
     if($meets){$matches++}
    }
    if($valid){
     $compared=$items.Count;$matching=$matches
     $comparison=if($matches -eq $items.Count){'MatchesWorkbookPredicate'}else{'DiffersFromWorkbookPredicate'}
     $reason='CompleteSuppliedSyntheticValuesCompared'
    }
   }
  }
  $details='Synthetic stored-setting comparison: '+$comparison+'. '+$definition.Predicate+'. Evidence condition: '+$reason+'.'
  $limit='Owner-supplied workbook reference only. No Microsoft Standard/Strict claim. Supplier completeness, tenant and run labels are unverified. No rule targeting, precedence, effective recipient coverage, live validation or compliance conclusion.'
  $rows.Add([pscustomobject][ordered]@{
   ControlId=$definition.Id;Control=$definition.Title;Status='Not assessed';Comparison=$comparison;ReasonCode=$reason
   ReferenceWorkbookSha256=$script:FjwtWorkbookHash;Worksheet='Sheet1';PhysicalRow=$definition.Row;ReferenceCells=@(('A'+$definition.Row),('D'+$definition.Row))
   SourceId=$definition.Source;ReadContract=$definition.Target;Field=$definition.Field;Predicate=$definition.Predicate
   ValidMinimum=$definition.Minimum;ValidMaximum=$definition.Maximum;ReturnedRecords=$count;ComparedRecords=$compared;MatchingRecords=$matching
   ComparisonAuthority='Owner-supplied workbook reference';ComparisonProfile='Exact workbook thresholds v1';Limitation=$limit
  })
  $display.Add([pscustomobject][ordered]@{
   Control=$definition.Title;Status='Not assessed';'Status details'=$details;Rationale=$limit
   'M365 access/licensing/prerequisites'='No source interaction. Existing read-only configuration fields only; actual permissions, license and source completeness remain unverified.'
  })
 }
 $bytes=[Text.Encoding]::UTF8.GetBytes($EvidenceJson)
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
 [pscustomobject][ordered]@{
  SchemaVersion='FlapjacksWorkbookThresholdComparison/1'
  Metadata=[pscustomobject][ordered]@{
   Mode='Synthetic';Status='Not assessed';EvidenceSha256=$hash;SourceAuthenticityVerified=$false
   ReferenceWorkbookSha256=$script:FjwtWorkbookHash;LocalPredicateImplementationMatches=2
   OverallWorkbookMappingNumerator=$null;ProductionMappingsAdded=0;LiveControlValidationCount=0
   DefaultAWChanged=$false;MicrosoftBaselineChanged=$false;ProductionHostIntegrated=$false
  }
  ComparisonRows=$rows.ToArray();DisplayRows=$display.ToArray()
  Notes=@('Opt-in offline workbook-reference comparison only. Raw input remains with the caller; this module does not read, save or upload files.',
          'Matching a numeric field does not establish full workbook-row outcomes or tenant compliance. Every displayed assessment remains Not assessed.',
          'These two implemented predicates do not reverify the historical 43/134 claim or add two to its numerator.')
 }
}
Export-ModuleMember -Function Get-FlapjacksWorkbookThresholdComparison
