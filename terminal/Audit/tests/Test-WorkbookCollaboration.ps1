#requires -Version 7.4
# Offline synthetic tests only. No account, network, module installation or exports.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../src/WorkbookCollaboration.ps1')
$script:Passed=0
function Check([string]$Name,[bool]$Condition){if(-not $Condition){throw "FAIL: $Name"};$script:Passed++}
function Throws([string]$Name,[scriptblock]$Action){$did=$false;try{& $Action|Out-Null}catch{$did=$true};Check $Name $did}
function By($Rows,[string]$Id){@($Rows|Where-Object ControlId -eq $Id)[0]}
function Source([string]$Id,$Item){[pscustomobject]@{SourceId=$Id;Status='Collected';Count=1;CollectedAtUtc='2026-01-01T00:00:00Z';Items=@($Item)}}
function Snapshot {
 [pscustomobject]@{Sources=@(
  (Source 'workbook-teams-federation' ([pscustomobject]@{Identity='Global';AllowFederatedUsers=$false;AllowTeamsConsumer=$true;AllowTeamsConsumerInbound=$false})),
  (Source 'workbook-teams-client' ([pscustomobject]@{Identity='Global';AllowGuestUser=$false})),
  (Source 'workbook-spo-tenant' ([pscustomobject]@{SharingCapability='ExternalUserSharingOnly';CoreSharingCapability='ExternalUserSharingOnly';OneDriveSharingCapability='ExternalUserAndGuestSharing';DefaultSharingLinkType='Direct';DefaultLinkPermission='View';CoreDefaultShareLinkScope='SpecificPeople';OneDriveDefaultShareLinkScope='Anyone';CoreDefaultShareLinkRole='View';OneDriveDefaultShareLinkRole='Edit';CoreDefaultLinkToExistingAccess=$false;OneDriveDefaultLinkToExistingAccess=$true}))
 )}
}
function Evaluate($Snapshot){$sources=@(ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $Snapshot);@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=$sources})}
function GraphSource {
 $d=@(Get-FlapjacksWorkbookCollaborationSources|Where-Object Provider -eq 'Graph')[0]
 [pscustomobject]@{SourceId=$d.Id;Provider='Graph';Target=$d.Target;Status='Collected';Count=1;MissingFields=@();CollectedAtUtc='2026-01-01T00:00:00Z';Items=@([pscustomobject]@{sharingCapability='existingExternalUserSharingOnly';sharingDomainRestrictionMode='allowList';isRequireAcceptingUserToMatchInvitedUserEnabled=$true;isResharingByExternalUsersEnabled=$false})}
}
$catalog=@(Get-FlapjacksWorkbookCollaborationSources)
Check 'Four optional contracts, three offline and one Graph' ($catalog.Count -eq 4 -and @($catalog|Where-Object Provider -eq 'OfflineSnapshot').Count -eq 3)
Check 'Optional group never pretends to be Exchange' (@($catalog|Where-Object {$_.Group -ne 'WorkbookCollaboration' -or $_.Provider -eq 'Exchange'}).Count -eq 0)
Check 'Native contracts are Get-only and offline' (@($catalog|Where-Object {$_.Provider -eq 'OfflineSnapshot' -and $_.Target -notmatch '^Get-'}).Count -eq 0)
$graph=@($catalog|Where-Object Provider -eq 'Graph')[0]
Check 'Graph is fixed v1 singleton with existing read scope' ($graph.Target -ceq '/admin/sharepoint/settings?$select=sharingCapability,sharingDomainRestrictionMode,isRequireAcceptingUserToMatchInvitedUserEnabled,isResharingByExternalUsersEnabled' -and $graph.Shape -eq 'Singleton' -and $graph.Scopes.Count -eq 1 -and $graph.Scopes[0] -ceq 'SharePointTenantSettings.Read.All')
Check 'No new grant or installation recommended' (@($catalog|Where-Object {$_.Notes -notmatch 'offline|Selected tenant-level'}).Count -eq 0)
$o=@(Get-FlapjacksWorkbookCollaborationChecks -Result @{})
Check 'All 13 rows returned even with no saved source' ($o.Count -eq 13)
Check 'Missing snapshots and Graph source never pass or N/A' (@($o|Where-Object Status -ne 'Not assessed').Count -eq 0)
$r=Snapshot;$original=$r|ConvertTo-Json -Depth 30;$sources=@(ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r)
Check 'Snapshot input not mutated' (($r|ConvertTo-Json -Depth 30) -ceq $original)
Check 'Source never marked successfully collected' (@($sources|Where-Object Status -ne 'OfflineSnapshot').Count -eq 0)
Check 'Zero request and page counts for offline sources' (@($sources|Where-Object {$_.PageCount -ne 0 -or $_.RequestCount -ne 0}).Count -eq 0)
Check 'Provenance explicitly unverified' (@($sources|Where-Object {$_.Provenance.ScopeVerification -cne 'Unverified' -or $_.Provenance.Kind -cne 'AlreadyCollected'}).Count -eq 0)
$o=Evaluate $r
Check 'Even matching offline settings stay Not assessed' (@($o|Where-Object Status -ne 'Not assessed').Count -eq 0)
Check 'False native Boolean comparison retained without tenant pass' ((By $o 'WB-TEAMS-FEDERATION').Observed -match 'AllowFederatedUsers = false.*Snapshot value matches.*not a tenant assessment')
Check 'True native consumer Boolean mismatch retained without tenant conclusion' ((By $o 'WB-TEAMS-CONSUMER').Observed -match 'does not match')
Check 'Nonanonymous sharing enum observed' ((By $o 'WB-SPO-SHARING').Observed -match 'Snapshot value matches')
Check 'Anonymous sharing enum mismatch observed' ((By $o 'WB-OD-SHARING').Observed -match 'does not match')
Check 'SpecificPeople named default observed' ((By $o 'WB-SPO-DEFAULT-LINK').Observed -match 'Snapshot value matches')
Check 'Explicit existing access overrides Anyone default for snapshot comparison' ((By $o 'WB-OD-DEFAULT-LINK').Observed -match 'OneDriveDefaultLinkToExistingAccess = true.*Snapshot value matches')
Check 'Edit role is not View baseline' ((By $o 'WB-OD-DEFAULT-ROLE').Observed -match 'does not match')
Check 'Original timestamp retained' ((By $o 'WB-TEAMS-FEDERATION').EvidenceTime -eq '2026-01-01T00:00:00Z')
Check 'Full Coverage records also supported' (@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Coverage=$sources}).Count -eq 13)
foreach($value in @('false',$null,0)){
 $r=Snapshot;$r.Sources[0].Items[0].AllowFederatedUsers=$value
 Check 'No missing/string/numeric Boolean coercion' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'No setting comparison')
}
foreach($value in @('UnknownFutureValue','externalUserSharingOnly','',3)){
 $r=Snapshot;$r.Sources[2].Items[0].SharingCapability=$value
 Check 'Unrecognized or wrong-case native enum fails closed' ((By (Evaluate $r) 'WB-SPO-SHARING').Observed -match 'No setting comparison')
}
$r=Snapshot;$r.Sources[2].Items[0].CoreDefaultShareLinkScope='Uninitialized'
Check 'Uninitialized default is not inferred from legacy Direct' ((By (Evaluate $r) 'WB-SPO-DEFAULT-LINK').Observed -match 'No setting comparison')
$r.Sources[2].Items[0].CoreDefaultLinkToExistingAccess=$true
Check 'Explicit existing-access flag can be reported with uninitialized scope' ((By (Evaluate $r) 'WB-SPO-DEFAULT-LINK').Observed -match 'Snapshot value matches')
$r=Snapshot;$r.Sources[2].Items[0].PSObject.Properties.Remove('CoreDefaultLinkToExistingAccess')
Check 'Missing precedence flag blocks default-scope comparison' ((By (Evaluate $r) 'WB-SPO-DEFAULT-LINK').Observed -match 'No setting comparison')
foreach($status in @('Partial','AccessDenied','Unauthorized','NotConnected','NotSelected','Error','collected',17)){
 $r=Snapshot;$r.Sources[0].Status=$status
 Check 'Unsuccessful collection not treated as settings evidence' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
}
foreach($count in @($true,'1',1.0,0,2,-1)){
 $r=Snapshot;$r.Sources[0].Count=$count
 Check 'Malformed count not repaired into comparison' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
}
$r=Snapshot;$r.Sources[0].Items=@();$r.Sources[0].Count=0
Check 'Empty success not pass or inferred false' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
$r=Snapshot;$r.Sources[0].Items+=$r.Sources[0].Items[0];$r.Sources[0].Count=2
Check 'Multiple singleton records do not compare' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
$r=Snapshot;$r.Sources[0].Items=$null
Check 'Null items not compared' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
foreach($stamp in @('yesterday','2026-01-01T00:00:00','2026-01-01T00:00:00+02:00','')){
 $r=Snapshot;$r.Sources[0].CollectedAtUtc=$stamp
 Check 'Missing/malformed/ambiguous UTC capture time not accepted' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
}
$r=Snapshot;$r.Sources[0]|Add-Member MissingFields @('AllowFederatedUsers')
Check 'Original MissingFields retained as incomplete flag' ((By (Evaluate $r) 'WB-TEAMS-FEDERATION').Observed -match 'incomplete or malformed')
$r=Snapshot;$r.Sources[0]|Add-Member TenantId '11111111-1111-1111-1111-111111111111';$r.Sources[0]|Add-Member Account 'operator@example.invalid';$r.Sources[0]|Add-Member Provenance @{ScopeVerification='Verified';Command='Set-SPOTenant'};$r.Sources[0].Items[0]|Add-Member AccessToken 'never-retain-me'
$projected=@(ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r)
Check 'Supplied identity/provenance/unknown fields are not trusted or exported' (($projected|ConvertTo-Json -Depth 20) -notmatch 'operator@example|11111111|Set-SPOTenant|never-retain-me|AccessToken')
$r=Snapshot;$r.Sources[0].Items[0].AllowFederatedUsers=@{NestedSecret='never-retain-me'}
$projected=@(ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r)
Check 'Nested field objects cannot smuggle extra data into evidence' (($projected|ConvertTo-Json -Depth 20) -notmatch 'NestedSecret|never-retain-me')
$r=Snapshot;$r.Sources+=$r.Sources[0];Throws 'Duplicate snapshot source rejected atomically' {ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r}
$r=Snapshot;$r.Sources[0].SourceId='workbook-sharepoint-settings';Throws 'Native snapshot cannot populate live Graph source' {ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r}
$r=Snapshot;$r.Sources[0].SourceId='arbitrary-command';Throws 'Unknown source ID rejected' {ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $r}
Throws 'Summary-only envelope rejected' {ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot @{Sources=@{SourceId='workbook-teams-client'}}}
Check 'Empty chosen snapshot yields no invented sources' (@(ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot @{Sources=@()}).Count -eq 0)
$r=Snapshot|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20 -AsHashtable
Check 'JSON dictionary deserialization supported' ((By (Evaluate $r) 'WB-TEAMS-GUEST').Observed -match 'Snapshot value matches')
$r=GraphSource;$o=@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)})
Check 'Three complete Graph values meet selected settings' (@($o|Where-Object {$_.SourceId -eq 'workbook-sharepoint-settings' -and $_.Status -eq 'Meets selected setting'}).Count -eq 3)
Check 'Graph does not fill native snapshot coverage' (@($o|Where-Object {$_.SourceId -ne 'workbook-sharepoint-settings' -and $_.Status -ne 'Not assessed'}).Count -eq 0)
$roundTrip=@{Evidence=@($r)}|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20
Check 'Graph JSON roundtrip preserves UTC evidence time' ((By @(Get-FlapjacksWorkbookCollaborationChecks -Result $roundTrip) 'WB-SPO-GRAPH-SHARING').EvidenceTime -match '^2026-01-01T00:00:00')
$r=GraphSource;$r.Items[0].sharingCapability='externalUserAndGuestSharing';$r.Items[0].isRequireAcceptingUserToMatchInvitedUserEnabled=$false;$r.Items[0].isResharingByExternalUsersEnabled=$true
$o=@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)})
Check 'Graph anonymous sharing, unmatched invitation and resharing need action' (@($o|Where-Object Status -eq 'Needs action').Count -eq 3)
foreach($status in @('Partial','AccessDenied','Unavailable','OfflineSnapshot','IdentityMismatch','TenantMismatch','NotConnected','MissingScope','CollectedWithWarnings')){
 $r=GraphSource;$r.Status=$status;$o=@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)})
 Check 'Noncollected Graph source cannot pass' (@($o|Where-Object Status -ne 'Not assessed').Count -eq 0)
}
foreach($value in @('true',1,$null)){
 $r=GraphSource;$r.Items[0].isRequireAcceptingUserToMatchInvitedUserEnabled=$value
 Check 'Graph Boolean rejects coercion' ((By @(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}) 'WB-SPO-GRAPH-INVITATION').Status -eq 'Not assessed')
}
$r=GraphSource;$r.Items[0].sharingCapability='unknownFutureValue'
Check 'Future Graph sharing enum remains unknown' ((By @(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}) 'WB-SPO-GRAPH-SHARING').Status -eq 'Not assessed')
$r=GraphSource;$r.Count='1';Check 'Graph Count remains strict' (@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}|Where-Object Status -ne 'Not assessed').Count -eq 0)
$r=GraphSource;$r.MissingFields=@('sharingCapability');Check 'Graph incomplete source cannot pass other fields' (@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}|Where-Object Status -ne 'Not assessed').Count -eq 0)
$r=GraphSource;$r.Provider='OfflineSnapshot';Check 'Graph provider mismatch cannot pass' (@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}|Where-Object Status -ne 'Not assessed').Count -eq 0)
$r=GraphSource;$r.Target='/users';Check 'Graph target mismatch cannot pass' (@(Get-FlapjacksWorkbookCollaborationChecks -Result @{Evidence=@($r)}|Where-Object Status -ne 'Not assessed').Count -eq 0)
$item=@{sharingCapability='disabled';sharingDomainRestrictionMode='none';isRequireAcceptingUserToMatchInvitedUserEnabled=$true;isResharingByExternalUsersEnabled=$false;Secret='never-retain-me';sharingAllowedDomainList=@('example.invalid')}
$safe=Protect-FlapjacksWorkbookCollaborationItem -Source $graph -Item $item
Check 'Graph projection is fixed and excludes unexpected fields/domain lists' ($safe.PSObject.Properties.Name.Count -eq 4 -and ($safe|ConvertTo-Json) -notmatch 'Secret|never-retain-me|sharingAllowedDomainList')
$item.isRequireAcceptingUserToMatchInvitedUserEnabled=@{Secret='never-retain-me'};$safe=Protect-FlapjacksWorkbookCollaborationItem -Source $graph -Item $item
Check 'Graph projection never serializes unexpected nested objects' ($null -eq $safe.isRequireAcceptingUserToMatchInvitedUserEnabled -and ($safe|ConvertTo-Json) -notmatch 'Secret')
Check 'Absent Graph properties remain absent' (@((Protect-FlapjacksWorkbookCollaborationItem -Source $graph -Item @{}).PSObject.Properties).Count -eq 0)
$o=@(Get-FlapjacksWorkbookCollaborationChecks -Result @{})
foreach($row in $o){
 $missingFields=@(@('ControlId','Control','Status','SourceId','Field','SourceStatus','EvidenceIds','EvidenceTime','Observed','Expected','Rationale','Limitation','Reference','ProfileVersion','NistCsf20EvidenceMapping','NistFramework','NistReference','NistMappingNote')|Where-Object {$_ -notin $row.PSObject.Properties.Name})
 Check ('Standard posture fields '+$row.ControlId) ($missingFields.Count -eq 0)
 Check ('Official refs and noncertification scope '+$row.ControlId) ($row.Reference -like 'https://learn.microsoft.com/*' -and $row.NistReference -like 'https://csrc.nist.gov/*' -and $row.NistMappingNote -match 'not proof' -and $row.AccessPrerequisites)
}
# AST guard checks all executable commands, not documentation strings.
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../src/WorkbookCollaboration.ps1'),[ref]$tokens,[ref]$errors)
Check 'Implementation parses' ($errors.Count -eq 0)
$commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
Check 'No live/auth/install/write or arbitrary invocation in extension' (@($commands|Where-Object {$_ -match '^(Connect-|Install-|Set-Mg|Set-Cs|Set-SPO|Invoke-|Import-Module|Grant-|Export-|Out-File|Set-Content|Add-Content)' -or $null -eq $_}).Count -eq 0)
Write-Output ("PASS: "+$script:Passed+" offline workbook collaboration assertions; no tenant calls or authentication.")
