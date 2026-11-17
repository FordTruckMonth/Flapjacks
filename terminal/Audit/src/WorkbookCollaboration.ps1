#requires -Version 7.4
# Workbook contracts and saved-evidence evaluation. No function below authenticates, imports modules,
# reads a tenant, invokes a command supplied by evidence, or writes files.
function Get-FlapjacksWorkbookCollaborationSources {
 [CmdletBinding()]
 param()
 $teams='https://learn.microsoft.com/en-us/powershell/module/microsoftteams/'
 $spo='https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/'
 $definitions=@(
  @{Id='workbook-teams-federation';Target='Get-CsTenantFederationConfiguration';Module='MicrosoftTeams';Fields=@('Identity','AllowFederatedUsers','AllowTeamsConsumer','AllowTeamsConsumerInbound');Documentation=$teams+'get-cstenantfederationconfiguration?view=teams-ps';Access='Already-collected output of Get-CsTenantFederationConfiguration from an approved Teams administrator context. Get-CsTenant alone does not attest the signed-in account.'},
  @{Id='workbook-teams-client';Target='Get-CsTeamsClientConfiguration';Module='MicrosoftTeams';Fields=@('Identity','AllowGuestUser');Documentation=$teams+'get-csteamsclientconfiguration?view=teams-ps';Access='Already-collected output of Get-CsTeamsClientConfiguration from an approved Teams administrator context. A Graph session does not verify the separate Teams session.'},
  @{Id='workbook-spo-tenant';Target='Get-SPOTenant';Module='Microsoft.Online.SharePoint.PowerShell';Fields=@('SharingCapability','CoreSharingCapability','OneDriveSharingCapability','DefaultSharingLinkType','DefaultLinkPermission','CoreDefaultShareLinkScope','OneDriveDefaultShareLinkScope','CoreDefaultShareLinkRole','OneDriveDefaultShareLinkRole','CoreDefaultLinkToExistingAccess','OneDriveDefaultLinkToExistingAccess');Documentation=$spo+'get-spotenant?view=sharepoint-ps';Access='Already-collected Get-SPOTenant output from an approved SharePoint administrator context. The admin URL or operator-entered account is not session attestation.'}
 )
 foreach($d in $definitions){
  [pscustomobject][ordered]@{
   Id=$d.Id;Group='WorkbookCollaboration';Provider='OfflineSnapshot';Target=$d.Target
   Scopes=@();Shape='Singleton';Fields=$d.Fields;Documentation=$d.Documentation
   Notes='Offline snapshot only. Exact current tenant and account cannot be verified by this adapter. No live collector, authentication, installation, permission grant, or coverage pass.'
   NativeModule=$d.Module;AccessPrerequisites=$d.Access
  }
 }
 [pscustomobject][ordered]@{
  Id='workbook-sharepoint-settings';Group='WorkbookCollaboration';Provider='Graph'
  Target='/admin/sharepoint/settings?$select=sharingCapability,sharingDomainRestrictionMode,isRequireAcceptingUserToMatchInvitedUserEnabled,isResharingByExternalUsersEnabled'
  Scopes=@('SharePointTenantSettings.Read.All');Shape='Singleton'
  Fields=@('sharingCapability','sharingDomainRestrictionMode','isRequireAcceptingUserToMatchInvitedUserEnabled','isResharingByExternalUsersEnabled')
  Documentation='https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0'
  Notes='Selected tenant-level SharePoint and OneDrive settings only. No site permissions, links, content or per-OneDrive defaults. Does not verify the separate native SharePoint/Teams session or satisfy offline snapshot coverage.'
  AccessPrerequisites='Existing exact tenant/account-matching delegated Graph context, already-granted SharePointTenantSettings.Read.All, and Global Reader or SharePoint Administrator. No automatic sign-in, scope expansion, grant or role activation.'
 }
}

function Protect-FlapjacksWorkbookCollaborationItem {
 [CmdletBinding()]
 param([Parameter(Mandatory)]$Source,[Parameter(Mandatory)]$Item)
 # Called by the shared collector after its own approved exact Graph context gate.
 # Ignore caller-provided Fields: the projection is fixed here, not report-driven.
 if($Source.Id -cne 'workbook-sharepoint-settings'){return $Item}
 $safe=[ordered]@{}
 foreach($name in @('sharingCapability','sharingDomainRestrictionMode','isRequireAcceptingUserToMatchInvitedUserEnabled','isResharingByExternalUsersEnabled')){
  $has=if($Item -is [Collections.IDictionary]){$Item.Contains($name)}else{$null -ne $Item.PSObject.Properties[$name]}
  if($has){$v=$Item.$name;$safe[$name]=if($null -eq $v -or $v -is [bool] -or $v -is [string]){$v}else{$null}}
 }
 return [pscustomobject]$safe
}

function ConvertTo-FlapjacksWorkbookCollaborationSnapshot {
 <#
 .SYNOPSIS
 Projects explicitly supplied already-collected source records, without trusting their scope.
 .DESCRIPTION
 Snapshot must have a Sources array. Each record uses SourceId, Status, Count,
 CollectedAtUtc and Items. Status=Collected is only the supplier's collection claim.
 All returned source statuses are OfflineSnapshot, never Collected. No supplied
 tenant/account/provenance/command is accepted as verification or executed.
 Missing fields, unsuccessful reads, malformed counts and absent UTC timestamps
 prevent even the informational snapshot comparison. Unknown/duplicate IDs throw.
 .EXAMPLE
 $rows = ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $parsedJson
 Get-FlapjacksWorkbookCollaborationChecks -Result @{ Evidence = @($rows) }
 # Read the JSON separately only after an operator explicitly chooses that file.
 # This converter performs no filesystem, network or session operations.
 #>
 [CmdletBinding()]
 param([Parameter(Mandatory)]$Snapshot)
 Set-StrictMode -Version Latest
 $ErrorActionPreference='Stop'
 function Has($o,[string]$n){if($null -eq $o){return $false};if($o -is [Collections.IDictionary]){return $o.Contains($n)};return $null -ne $o.PSObject.Properties[$n]}
 function Val($o,[string]$n,$fallback=$null){if(Has $o $n){return ,($o.$n)};return ,$fallback}
 $inputRows=Val $Snapshot 'Sources'
 if($null -eq $inputRows -or $inputRows -is [string] -or $inputRows -is [Collections.IDictionary] -or $inputRows -isnot [Collections.IEnumerable]){throw 'Snapshot requires a Sources array of explicitly selected workbook collaboration records.'}
 $catalog=@{};foreach($d in Get-FlapjacksWorkbookCollaborationSources | Where-Object Provider -eq 'OfflineSnapshot'){$catalog[$d.Id]=$d}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 # Validate all IDs before yielding any rows, so a later bad record cannot yield a partial import.
 foreach($source in $inputRows){
  $id=Val $source 'SourceId'
  if($id -isnot [string] -or $id -cnotin $catalog.Keys -or -not $seen.Add($id)){throw 'Unknown or duplicate workbook collaboration source ID; snapshots must not merge ambiguous runs.'}
 }
 foreach($source in $inputRows){
  $id=[string](Val $source 'SourceId');$d=$catalog[$id]
  $complete=$true;$issues=[Collections.Generic.List[string]]::new()
  $status=Val $source 'Status'
  if($status -isnot [string] -or $status -cnotin @('Collected','Partial','AccessDenied','Unauthorized','Unavailable','Unlicensed','NotConnected','NotSelected','Error')){$status='Unrecognized'}
  if($status -cne 'Collected'){$complete=$false;$issues.Add('The supplied original source status is not Collected.')}
  $items=Val $source 'Items';$count=Val $source 'Count'
  if($null -eq $items -or $items -is [string] -or $items -is [Collections.IDictionary] -or $items -isnot [Collections.IEnumerable]){
   $items=@();$complete=$false;$issues.Add('Items is absent or is not an array.')
  }
  $items=@($items)
  if(($count -isnot [int] -and $count -isnot [long]) -or $count -ne $items.Count -or $items.Count -ne 1){$complete=$false;$issues.Add('Exactly one item and a matching integer Count are required.')}
  $stamp=Val $source 'CollectedAtUtc';$parsed=[datetimeoffset]::MinValue
  if($stamp -is [datetime] -or $stamp -is [datetimeoffset]){$stamp=$stamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
  if($stamp -isnot [string] -or $stamp -cnotmatch '(Z|\+00:00)$' -or -not [datetimeoffset]::TryParse($stamp,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)){
   $stamp='';$complete=$false;$issues.Add('An explicit valid UTC CollectedAtUtc is required.')
  }
  $missing=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $projected=[Collections.Generic.List[object]]::new()
  foreach($item in $items){
   $safe=[ordered]@{}
   foreach($field in $d.Fields){
    if(-not (Has $item $field)){[void]$missing.Add($field);continue}
    $v=Val $item $field
    if($v -is [Enum]){$v=$v.ToString()}
    if($null -ne $v -and $v -isnot [bool] -and $v -isnot [string] -and $v -isnot [int] -and $v -isnot [long]){$v=$null;[void]$missing.Add($field)}
    $safe[$field]=$v
   }
   $projected.Add([pscustomobject]$safe)
  }
  if(@((Val $source 'MissingFields' @()) | ForEach-Object {$_}).Count -gt 0){$complete=$false;$issues.Add('Original source reports missing fields.')}
  [pscustomobject][ordered]@{
   SourceId=$id;Group='WorkbookCollaboration';Provider='OfflineSnapshot';Target=$d.Target
   Status='OfflineSnapshot';Reason='Unverified offline scope; never a successful tenant collection. '+($issues -join ' ')
   CollectedAtUtc=[string]$stamp;PageCount=0;RequestCount=0;Count=$projected.Count;Items=$projected.ToArray()
   MissingFields=@($missing | Sort-Object);Notes=$d.Notes;SnapshotComplete=$complete
   Provenance=[pscustomobject]@{Kind='AlreadyCollected';ScopeVerification='Unverified';OriginalStatus=$status;RequiredNativeCommand=$d.Target;Note='OriginalStatus and timestamp are supplier claims. RequiredNativeCommand is a requirement, not proof of execution. Tenant, account and freshness have not been verified.'}
  }
 }
}

function Get-FlapjacksWorkbookCollaborationChecks {
 [CmdletBinding()]
 param([Parameter(Mandatory)]$Result)
 Set-StrictMode -Version Latest
 $ErrorActionPreference='Stop'
 function Has($o,[string]$n){if($null -eq $o){return $false};if($o -is [Collections.IDictionary]){return $o.Contains($n)};return $null -ne $o.PSObject.Properties[$n]}
 function Val($o,[string]$n,$fallback=$null){if(Has $o $n){return ,($o.$n)};return ,$fallback}
 $rows=Val $Result 'Evidence' @();if($null -eq $rows -or @($rows).Count -eq 0){$rows=Val $Result 'Coverage' @()}
 $byId=@{}
 foreach($r in $rows){
  $id=Val $r 'SourceId'
  if($id -isnot [string] -or $id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or $byId.ContainsKey($id)){throw 'Invalid or duplicate source ID; do not combine runs without provenance review.'}
  $byId[$id]=$r
 }
 $catalog=@{};foreach($d in Get-FlapjacksWorkbookCollaborationSources){$catalog[$d.Id]=$d}
 $fed='workbook-teams-federation';$client='workbook-teams-client';$spo='workbook-spo-tenant'
 $teamsRef='https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration?view=teams-ps'
 $spoRef='https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/set-spotenant?view=sharepoint-ps'
 $defs=@(
  @{Id='WB-TEAMS-FEDERATION';Name='Teams external federation switch';Source=$fed;Field='AllowFederatedUsers';Type='Boolean';Desired=$false;Ref=$teamsRef;Limit='This conservative baseline disables federation; approved business federation requires a separate allow/block-domain and per-user external-access policy review. No effective user access is evaluated.'},
  @{Id='WB-TEAMS-CONSUMER';Name='Teams unmanaged consumer federation';Source=$fed;Field='AllowTeamsConsumer';Type='Boolean';Desired=$false;Ref=$teamsRef;Limit='Tenant switch only; external-access policies, allowed users and actual communication paths are not evaluated.'},
  @{Id='WB-TEAMS-CONSUMER-INBOUND';Name='Teams unmanaged consumer inbound initiation';Source=$fed;Field='AllowTeamsConsumerInbound';Type='Boolean';Desired=$false;Ref=$teamsRef;Limit='Stored switch only. Its effect depends on consumer federation and external-access policies.'},
  @{Id='WB-TEAMS-GUEST';Name='Teams organization guest access switch';Source=$client;Field='AllowGuestUser';Type='Boolean';Desired=$false;Ref='https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsclientconfiguration?view=teams-ps';Limit='A conservative no-guests baseline is not a universal recommendation. Approved guest collaboration, Entra cross-tenant settings, groups, meetings and actual guest access require separate review.'},
  @{Id='WB-SPO-SHARING';Name='SharePoint organization sharing capability';Source=$spo;Field='SharingCapability';Type='Sharing';Ref=$spoRef;Limit='Organization sharing ceiling only. CoreSharingCapability, site overrides, labels, existing permissions and existing links are not resolved.'},
  @{Id='WB-OD-SHARING';Name='OneDrive organization sharing capability';Source=$spo;Field='OneDriveSharingCapability';Type='Sharing';Ref=$spoRef;Limit='OneDrive organization setting only. SharePoint ceiling, individual OneDrive sites, labels, existing permissions and existing links are not resolved.'},
  @{Id='WB-SPO-DEFAULT-LINK';Name='SharePoint default sharing-link scope';Source=$spo;Field='CoreDefaultShareLinkScope';Type='Scope';Companion='CoreDefaultLinkToExistingAccess';Ref=$spoRef;Limit='Named default only, not a prohibition on other links. Existing-access default takes precedence. Missing or Uninitialized newer properties are not inferred from legacy DefaultSharingLinkType.'},
  @{Id='WB-OD-DEFAULT-LINK';Name='OneDrive default sharing-link scope';Source=$spo;Field='OneDriveDefaultShareLinkScope';Type='Scope';Companion='OneDriveDefaultLinkToExistingAccess';Ref=$spoRef;Limit='Named default only, not a prohibition on other links. Existing-access default takes precedence. Missing or Uninitialized newer properties are not inferred from legacy DefaultSharingLinkType.'},
  @{Id='WB-SPO-DEFAULT-ROLE';Name='SharePoint default sharing-link role';Source=$spo;Field='CoreDefaultShareLinkRole';Type='Role';Ref=$spoRef;Limit='Default role only. Existing-access defaults, site overrides and existing permissions are not evaluated. Missing newer properties are not inferred from legacy DefaultLinkPermission.'},
  @{Id='WB-OD-DEFAULT-ROLE';Name='OneDrive default sharing-link role';Source=$spo;Field='OneDriveDefaultShareLinkRole';Type='Role';Ref=$spoRef;Limit='Default role only. Existing-access defaults, site overrides and existing permissions are not evaluated. Missing newer properties are not inferred from legacy DefaultLinkPermission.'},
  @{Id='WB-SPO-GRAPH-SHARING';Name='SharePoint and OneDrive tenant sharing ceiling (Graph)';Source='workbook-sharepoint-settings';Field='sharingCapability';Type='GraphSharing';Ref='https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0';Limit='Stored tenant sharing capability only. Does not resolve per-site or per-OneDrive controls, labels, legacy/existing links, default-link type or actual external access.'},
  @{Id='WB-SPO-GRAPH-INVITATION';Name='Sharing invitation accepting-account match (Graph)';Source='workbook-sharepoint-settings';Field='isRequireAcceptingUserToMatchInvitedUserEnabled';Type='GraphBoolean';Desired=$true;Ref='https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0';Limit='Stored invitation-account setting only. Does not enumerate invitations or guests, or verify effective sharing and existing access.'},
  @{Id='WB-SPO-GRAPH-RESHARING';Name='Guest resharing of content they do not own (Graph)';Source='workbook-sharepoint-settings';Field='isResharingByExternalUsersEnabled';Type='GraphBoolean';Desired=$false;Ref='https://learn.microsoft.com/en-us/graph/api/resources/sharepointsettings?view=graph-rest-1.0';Limit='Stored guest resharing switch only. Does not assess direct permissions, ownership, site overrides or existing shared links.'}
 )
 foreach($d in $defs){
  $source=$byId[$d.Source];$definition=$catalog[$d.Source];$rawStatus=Val $source 'Status' 'Missing'
  $sourceStatus=if($rawStatus -is [string]){$rawStatus}else{'Unrecognized'}
  $checkStatus='Not assessed'
  $observed='No offline snapshot supplied. Live native collection is unsupported because exact workload tenant/account binding is not verified.'
  $expected=switch($d.Type){'Boolean'{$d.Field+' = false for this conservative selected baseline.'};'Sharing'{'A recognized sharing capability without anonymous guests.'};'Scope'{$d.Field+' = SpecificPeople, or an explicit existing-access default.'};'Role'{$d.Field+' = View for this selected default.'};'GraphBoolean'{$d.Field+' = '+$d.Desired.ToString().ToLowerInvariant()+'.'};'GraphSharing'{'A recognized sharing capability without anonymous guests.'}}
  $items=Val $source 'Items' @();$count=Val $source 'Count';$p=Val $source 'Provenance';$ids=@()
  if($null -ne $source){
   $observed='Source status is '+$sourceStatus+'. Only explicitly projected OfflineSnapshot evidence is considered; tenant/account coverage remains unverified.'
   if($sourceStatus -ceq 'OfflineSnapshot'){
    $observed='Offline snapshot is incomplete or malformed; no setting comparison. Tenant/account coverage remains unverified.'
    if((Val $source 'SnapshotComplete') -is [bool] -and (Val $source 'SnapshotComplete') -eq $true -and (Val $p 'Kind') -ceq 'AlreadyCollected' -and (Val $p 'ScopeVerification') -ceq 'Unverified' -and (Val $p 'OriginalStatus') -ceq 'Collected' -and (Val $p 'RequiredNativeCommand') -ceq $definition.Target -and $null -ne $items -and $items -is [Collections.IEnumerable] -and $items -isnot [string] -and $items -isnot [Collections.IDictionary] -and ($count -is [int] -or $count -is [long]) -and $count -eq 1 -and @($items).Count -eq 1){
     $item=@($items)[0];$v=Val $item $d.Field;$valid=$false;$matches=$false;$detail=''
     switch($d.Type){
      'Boolean'{if($v -is [bool]){$valid=$true;$matches=$v -eq $false;$detail=$d.Field+' = '+$v.ToString().ToLowerInvariant()+'.'}}
      'Sharing'{if($v -is [string] -and $v -cin @('Disabled','ExistingExternalUserSharingOnly','ExternalUserSharingOnly','ExternalUserAndGuestSharing')){$valid=$true;$matches=$v -cne 'ExternalUserAndGuestSharing';$detail=$d.Field+' = '+$v+'.'}}
      'Scope'{
       $override=Val $item $d.Companion
       if($v -is [string] -and $v -cin @('Anyone','Organization','SpecificPeople','Uninitialized') -and $override -is [bool]){
        $detail=$d.Field+' = '+$v+'; '+$d.Companion+' = '+$override.ToString().ToLowerInvariant()+'.'
        if($override -or $v -cne 'Uninitialized'){$valid=$true;$matches=$override -or $v -ceq 'SpecificPeople'}
       }
      }
      'Role'{if($v -is [string] -and $v -cin @('None','View','Edit','Review','RestrictedView')){$valid=$true;$matches=$v -ceq 'View';$detail=$d.Field+' = '+$v+'.'}}
     }
     if($valid){
      $comparison=if($matches){'matches'}else{'does not match'}
      $observed='Unverified offline snapshot only: '+$detail+' Snapshot value '+$comparison+' the selected setting; this is not a tenant assessment or coverage pass.'
     }else{$observed='Unverified offline snapshot only: required value is absent, null, mistyped, unrecognized or unresolved. '+$detail+' No setting comparison.'}
     $identity=Val $item 'Identity';if($identity -is [string] -and $identity){$ids=@($identity)}
    }
   }
  }
  if($definition.Provider -ceq 'Graph'){
   $observed='No complete saved Graph source evidence. A collected response through the approved exact Graph context is required.'
   if($null -ne $source){
    $observed='Source status is '+$sourceStatus+'; complete Graph evidence is required. Offline snapshots are not a substitute.'
    if($sourceStatus -ceq 'Collected' -and (Val $source 'Provider') -ceq 'Graph' -and (Val $source 'Target') -ceq $definition.Target){
     $observed='Graph source is empty, incomplete, summary-only or malformed; a singleton and matching integer Count are required.'
     if($null -ne $items -and $items -is [Collections.IEnumerable] -and $items -isnot [string] -and $items -isnot [Collections.IDictionary] -and ($count -is [int] -or $count -is [long]) -and $count -eq 1 -and @($items).Count -eq 1 -and @((Val $source 'MissingFields' @()) | ForEach-Object {$_}).Count -eq 0){
      $v=Val @($items)[0] $d.Field;$valid=$false;$matches=$false
      if($d.Type -ceq 'GraphBoolean' -and $v -is [bool]){$valid=$true;$matches=$v -eq $d.Desired;$detail=$v.ToString().ToLowerInvariant()}
      if($d.Type -ceq 'GraphSharing' -and $v -is [string] -and $v -cin @('disabled','externalUserSharingOnly','existingExternalUserSharingOnly','externalUserAndGuestSharing')){$valid=$true;$matches=$v -cne 'externalUserAndGuestSharing';$detail=$v}
      if($valid){$checkStatus=if($matches){'Meets selected setting'}else{'Needs action'};$observed=$d.Field+' = '+$detail+'. Stored tenant setting only.'}
      else{$observed='Required Graph field is missing, null, mistyped or unrecognized; no default is inferred.'}
     }
    }
   }
  }
  $stamp=Val $source 'CollectedAtUtc' ''
  if($stamp -is [datetime] -or $stamp -is [datetimeoffset]){$stamp=$stamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
  if($stamp -isnot [string]){$stamp=''}
  [pscustomobject][ordered]@{
   ControlId=$d.Id;Control=$d.Name;Status=$checkStatus;SourceId=$d.Source;Field=$d.Field;SourceStatus=$sourceStatus
   EvidenceIds=$ids;EvidenceTime=$stamp;Observed=$observed;Expected=$expected
   Rationale='Review the saved current-setting claim against the explicitly selected workbook baseline; approve business exceptions separately.'
   Limitation=$(if($definition.Provider -ceq 'OfflineSnapshot'){'Unverified offline provenance: account, tenant, authenticity and freshness are not attested. '+$d.Limit}else{$d.Limit})
   Reference=$d.Ref;ProfileVersion='Flapjacks workbook collaboration 0.1';NistCsf20EvidenceMapping='PR.AA-05';NistFramework='NIST CSF 2.0'
   NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
   NistMappingNote='Analyst-selected supporting evidence only; not proof of CSF outcome attainment or NIST certification.'
   AccessPrerequisites=$definition.AccessPrerequisites
  }
 }
}
