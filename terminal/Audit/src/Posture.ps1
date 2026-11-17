#requires -Version 7.4
# This evaluator consumes supplied saved evidence only. No collection, authentication,
# module import, file export or remediation is performed here.
function Get-FlapjacksPostureChecks {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)]$Result,
  [System.Collections.IDictionary]$NotApplicable=@{}
 )
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Has($o,[string]$n){if($null -eq $o){return $false};if($o -is [Collections.IDictionary]){return $o.Contains($n)};return $null -ne $o.PSObject.Properties[$n]}
function Val($o,[string]$n,$fallback=$null){if(Has $o $n){return ,($o.$n)};return ,$fallback}
$rows=Val $Result 'Evidence' @()
if($null -eq $rows -or -not @($rows).Count){$rows=Val $Result 'Coverage' @()}
if($null -eq $rows -or -not @($rows).Count){throw 'Full saved Evidence or Coverage source records are required; no tenant reads will be performed.'}
$byId=@{}
foreach($r in $rows){
 $id=[string](Val $r 'SourceId' '')
 if($id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or $byId.ContainsKey($id)){throw 'Invalid or duplicate source ID; combining runs requires an explicit provenance-aware report.'}
 $byId[$id]=$r
}
$csf=@{
 'EXO-AUDIT'='PR.PS-04';'EXO-DIRECT-SEND'='PR.PS-01';'EXO-SMTP-AUTH'='PR.AA-03';
 'ENTRA-APP-REG'='PR.AA-05';'EOP-FILE-FILTER'='PR.PS-01'
}
$organizationRef='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig?view=exchange-ps'
$defs=@(
 @{Id='EXO-AUDIT';Name='Organization mailbox auditing switch';Source='exchange-organization';Field='AuditDisabled';Desired=$false;Single=$true;Why='The organization-level mailbox auditing disable switch should be off for this selected baseline.';Limit='Does not verify per-mailbox auditing overrides, audited operations, licensing, log delivery or historical coverage.';Ref=$organizationRef},
 @{Id='EXO-DIRECT-SEND';Name='Reject Direct Send organization switch';Source='exchange-organization';Field='RejectDirectSend';Desired=$true;Single=$true;Why='This selected baseline rejects Direct Send; confirm approved device and application mail flows before any configuration change.';Limit='The stored flag does not prove every inbound message is blocked or all connector and mail-flow paths are secure. A business exception needs documented review.';Ref=$organizationRef},
 @{Id='EXO-SMTP-AUTH';Name='Organization SMTP AUTH default';Source='exchange-transport';Field='SmtpClientAuthenticationDisabled';Desired=$true;Single=$true;Why='This selected baseline disables SMTP AUTH at the organization default.';Limit='Mailbox overrides, authentication policies and Conditional Access can alter effective access. This is not proof that SMTP AUTH is disabled for every mailbox.';Ref='https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission'},
 @{Id='ENTRA-APP-REG';Name='Default users application registration';Source='authorization-policy';Field='defaultUserRolePermissions.allowedToCreateApps';Desired=$false;Single=$true;Why='This selected baseline restricts application creation by the default user role; use an approved delegated application-management process.';Limit='Does not evaluate explicit role assignments, existing applications, consent grants, credentials or application risk.';Ref='https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'},
 @{Id='EOP-FILE-FILTER';Name='Common attachment filter in returned malware policies';Source='exchange-malware-policies';Field='EnableFileFilter';Desired=$true;Single=$false;Why='This selected baseline enables the common attachment filter in every returned malware policy.';Limit='Stored policies only. Rule enablement, priority, recipient targeting, file types, exceptions and effective message protection are not evaluated.';Ref='https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure'}
)
foreach($key in $NotApplicable.Keys){if($key -notin $defs.Id -or [string]::IsNullOrWhiteSpace([string]$NotApplicable[$key])){throw 'N/A requires a known control ID and an explicit operator applicability reason.'}}
foreach($d in $defs){
 $source=$byId[$d.Source]
 $rawStatus=Val $source 'Status' 'Missing'
 $sourceStatus=if($rawStatus -is [string]){$rawStatus}else{'Unrecognized'}
 $evidenceIds=[Collections.Generic.List[string]]::new()
 $status='Not assessed';$observed='No saved source evidence was supplied.'
 $rationale=$d.Why
 $items=Val $source 'Items' @(); if($null -eq $items){$items=@()};$items=@($items)
 if($NotApplicable.Contains($d.Id)){
  $status='N/A';$observed='Excluded by explicit operator applicability decision, not inferred from collection results.'
  $rationale='Operator applicability reason: '+[string]$NotApplicable[$d.Id]
 }elseif($null -ne $source){
  if($sourceStatus -cne 'Collected'){$observed='Source status is '+$sourceStatus+'; a complete successful read is required.'}
  elseif(-not (Has $source 'Items')){$observed='Source contains summary-only coverage and no Items evidence.'}
  elseif(@( (Val $source 'MissingFields' @()) | ForEach-Object { $_ } ).Count -gt 0){$observed='Source reports missing fields; it cannot establish a complete setting assessment.'}
  elseif($items.Count -eq 0){$observed='Successful empty response; this does not establish applicability or a configured setting.'}
  elseif(-not (Has $source 'Count') -or ((Val $source 'Count') -isnot [int] -and (Val $source 'Count') -isnot [long]) -or (Val $source 'Count') -ne $items.Count){$observed='Source Count does not match its Items; evidence completeness is unresolved.'}
  elseif($d.Single -and $items.Count -ne 1){$observed='Expected exactly one organization policy record; multiple records are ambiguous.'}
  else {
   $values=[Collections.Generic.List[bool]]::new();$invalid=$false
   foreach($item in $items){
    $value=$item
    foreach($part in $d.Field.Split('.')){$value=Val $value $part}
    $identity=Val $item 'id' (Val $item 'Identity' (Val $item 'Name' ''))
    if(-not [string]::IsNullOrEmpty([string]$identity)){$evidenceIds.Add([string]$identity)}
    if($value -isnot [bool]){$invalid=$true}else{$values.Add($value)}
   }
   if($invalid){$observed='At least one required field is missing, null or not a Boolean; false is never inferred.'}
   else {
    $matching=@($values | Where-Object {$_ -ceq $d.Desired}).Count
    if($matching -eq $values.Count){$status='Meets selected setting'}else{$status='Needs action'}
    if($d.Single){$observed=$d.Field+' = '+$values[0].ToString().ToLowerInvariant()+'.'}
    else{$observed=[string]$matching+' of '+$values.Count+' returned policies have '+$d.Field+' = '+$d.Desired.ToString().ToLowerInvariant()+'.'}
   }
  }
 }
 $stamp=Val $source 'CollectedAtUtc' ''
 if($stamp -is [datetime] -or $stamp -is [datetimeoffset]){$stamp=$stamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
 [pscustomobject][ordered]@{
  ControlId=$d.Id;Control=$d.Name;Status=$status;SourceId=$d.Source;Field=$d.Field;SourceStatus=$sourceStatus
  EvidenceIds=$evidenceIds.ToArray();EvidenceTime=[string]$stamp
  Observed=$observed;Expected=$d.Field+' = '+$d.Desired.ToString().ToLowerInvariant()+'.'
  Rationale=$rationale;Limitation=$d.Limit;Reference=$d.Ref
  ProfileVersion='Flapjacks pilot 0.1';NistCsf20EvidenceMapping=$csf[$d.Id]
  NistFramework='NIST CSF 2.0'
  NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
  NistMappingNote='Analyst-selected supporting evidence only; not proof of CSF outcome attainment or NIST certification.'
 }
}

}
