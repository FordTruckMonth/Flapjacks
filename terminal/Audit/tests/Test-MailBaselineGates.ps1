#requires -Version 7.4
# Independent offline regression gates for the Microsoft mail-settings benchmark.
# Invented fixtures and intercepted transports only. No tenant, sign-in, upload or Git.
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:AuditRoot=Split-Path $PSScriptRoot -Parent
foreach($file in Get-ChildItem -LiteralPath (Join-Path $script:AuditRoot 'src') -Filter '*.ps1'|Sort-Object Name){. $file.FullName}
$script:Assertions=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Condition){
 $script:Assertions.Add([pscustomobject]@{Name=$Name;Passed=$Condition})
 if(-not $Condition){throw "FAIL: $Name"}
}
function Rejects([scriptblock]$Action){try{& $Action|Out-Null;return $false}catch{return $true}}
function Copy-Result($Value){$Value|ConvertTo-Json -Depth 100|ConvertFrom-Json -Depth 100}
function By($Rows,[string]$Id){@($Rows|Where-Object ControlId -ceq $Id)[0]}
function Read-Zip([string]$Path){
 $zip=[IO.Compression.ZipFile]::OpenRead($Path);$entries=@{}
 try{foreach($entry in $zip.Entries){$reader=[IO.StreamReader]::new($entry.Open());try{$entries[$entry.FullName]=$reader.ReadToEnd()}finally{$reader.Dispose()}}}finally{$zip.Dispose()}
 return $entries
}

# The exact pre-mail-benchmark source inventory, routes and permission contracts.
# Projected setting fields may expand; source IDs, target calls and scopes may not.
$expectedContracts=@'
conditional-access|Core|Graph|/identity/conditionalAccess/policies|Policy.Read.All|
named-locations|Core|Graph|/identity/conditionalAccess/namedLocations|Policy.Read.All|
security-defaults|Core|Graph|/policies/identitySecurityDefaultsEnforcementPolicy|Policy.Read.All|
authorization-policy|Core|Graph|/policies/authorizationPolicy|Policy.Read.All|
admin-consent-policy|Core|Graph|/policies/adminConsentRequestPolicy|Policy.Read.All|
cross-tenant-default|Core|Graph|/policies/crossTenantAccessPolicy/default|Policy.Read.All|
cross-tenant-partners|Core|Graph|/policies/crossTenantAccessPolicy/partners|Policy.Read.All|
authentication-methods-policy|Authentication|Graph|/policies/authenticationMethodsPolicy|Policy.Read.AuthenticationMethod,Policy.Read.All|
authentication-strengths|Authentication|Graph|/policies/authenticationStrengthPolicies|Policy.Read.AuthenticationMethod,Policy.Read.All|
permission-grant-policies|Consent|Graph|/policies/permissionGrantPolicies|Policy.Read.PermissionGrant|
role-definitions|Administration|Graph|/roleManagement/directory/roleDefinitions|RoleManagement.Read.Directory|
role-assignments|Administration|Graph|/roleManagement/directory/roleAssignments|RoleManagement.Read.Directory|
role-eligibility-instances|Administration|Graph|/roleManagement/directory/roleEligibilityScheduleInstances|RoleEligibilitySchedule.Read.Directory,RoleManagement.Read.Directory|
tenant-domains|TenantInventory|Graph|/domains|Domain.Read.All|
tenant-subscriptions|TenantInventory|Graph|/subscribedSkus|LicenseAssignment.Read.All|
intune-compliance-policy-metadata|Intune|Graph|/deviceManagement/deviceCompliancePolicies?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version|DeviceManagementConfiguration.Read.All|
intune-configuration-policy-metadata|Intune|Graph|/deviceManagement/deviceConfigurations?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version|DeviceManagementConfiguration.Read.All|
exchange-organization|Exchange|Exchange|Get-OrganizationConfig||
exchange-transport|Exchange|Exchange|Get-TransportConfig||
exchange-authentication-policies|Exchange|Exchange|Get-AuthenticationPolicy||
exchange-accepted-domains|Exchange|Exchange|Get-AcceptedDomain||
exchange-remote-domains|Exchange|Exchange|Get-RemoteDomain||
exchange-dkim|Exchange|Exchange|Get-DkimSigningConfig||
exchange-inbound-connectors|Exchange|Exchange|Get-InboundConnector||
exchange-outbound-connectors|Exchange|Exchange|Get-OutboundConnector||
exchange-transport-rules|Exchange|Exchange|Get-TransportRule||
exchange-antispam-policies|Exchange|Exchange|Get-HostedContentFilterPolicy||
exchange-antispam-rules|Exchange|Exchange|Get-HostedContentFilterRule||
exchange-outbound-spam-policies|Exchange|Exchange|Get-HostedOutboundSpamFilterPolicy||
exchange-outbound-spam-rules|Exchange|Exchange|Get-HostedOutboundSpamFilterRule||
exchange-antiphish-policies|Exchange|Exchange|Get-AntiPhishPolicy||
exchange-antiphish-rules|Exchange|Exchange|Get-AntiPhishRule||
exchange-malware-policies|Exchange|Exchange|Get-MalwareFilterPolicy||
exchange-malware-rules|Exchange|Exchange|Get-MalwareFilterRule||
exchange-safe-links-policies|Exchange|Exchange|Get-SafeLinksPolicy||
exchange-safe-links-rules|Exchange|Exchange|Get-SafeLinksRule||
exchange-safe-attachments-policies|Exchange|Exchange|Get-SafeAttachmentPolicy||
exchange-safe-attachments-rules|Exchange|Exchange|Get-SafeAttachmentRule||
exchange-atp-organization|Exchange|Exchange|Get-AtpPolicyForO365||
exchange-preset-eop-rules|Exchange|Exchange|Get-EOPProtectionPolicyRule||
exchange-preset-atp-rules|Exchange|Exchange|Get-ATPProtectionPolicyRule||
exchange-built-in-protection-rule|Exchange|Exchange|Get-ATPBuiltInProtectionRule||
purview-dlp-policies|Purview|Purview|Get-DlpCompliancePolicy||
purview-dlp-rule-metadata|Purview|Purview|Get-DlpComplianceRule||
purview-retention-policies|Purview|Purview|Get-RetentionCompliancePolicy||
purview-retention-rules|Purview|Purview|Get-RetentionComplianceRule||
workbook-identity-registration|WorkbookIdentity|Graph|/reports/authenticationMethods/userRegistrationDetails?$select=id,isAdmin,isMfaRegistered,isSsprEnabled,isSsprRegistered,isSsprCapable,lastUpdatedDateTime|AuditLog.Read.All|
workbook-identity-users|WorkbookIdentity|Graph|/users?$select=id,accountEnabled,signInActivity|User.Read.All,Directory.Read.All|AuditLog.Read.All
exchange-unified-audit-config|WorkbookExchange|Exchange|Get-AdminAuditLogConfig||
exchange-external-sender-tagging|WorkbookExchange|Exchange|Get-ExternalInOutlook||
exchange-connection-filter-policies|WorkbookExchange|Exchange|Get-HostedConnectionFilterPolicy||
workbook-teams-federation|WorkbookCollaboration|OfflineSnapshot|Get-CsTenantFederationConfiguration||
workbook-teams-client|WorkbookCollaboration|OfflineSnapshot|Get-CsTeamsClientConfiguration||
workbook-spo-tenant|WorkbookCollaboration|OfflineSnapshot|Get-SPOTenant||
workbook-sharepoint-settings|WorkbookCollaboration|Graph|/admin/sharepoint/settings?$select=sharingCapability,sharingDomainRestrictionMode,isRequireAcceptingUserToMatchInvitedUserEnabled,isResharingByExternalUsersEnabled|SharePointTenantSettings.Read.All|
'@ -split '\r?\n'
$catalog=@(Get-AuditSourceCatalog)+@(Get-FlapjacksWorkbookSources)
$actualContracts=@($catalog|ForEach-Object {
 '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.Id,$_.Group,$_.Provider,$_.Target,($_.Scopes -join ','),((Get-AuditProperty $_ 'RequiredScopes' @()) -join ',')
})
Check 'Exact original 55 source/route/provider/scope contracts retained' (($actualContracts -join "`n") -ceq ($expectedContracts -join "`n"))
Check 'No extra default source or Workbook source' (@(Get-AuditSourceCatalog).Count -eq 46 -and @(Get-FlapjacksWorkbookSources).Count -eq 9)
$defaultPlan=Get-M365OrganizationAuditPlan
$workbookPlan=Get-M365OrganizationAuditPlan -Workbook
Check 'Default source plan still has exactly 46 source IDs' (($defaultPlan.Sources.Id -join ',') -ceq (@(Get-AuditSourceCatalog).Id -join ','))
Check 'Workbook source plan still has exactly 55 source IDs' (($workbookPlan.Sources.Id -join ',') -ceq ($catalog.Id -join ','))
Check 'Default Graph scope set stays unchanged' (($defaultPlan.GraphReadPermissions -join ',') -ceq 'DeviceManagementConfiguration.Read.All,Domain.Read.All,LicenseAssignment.Read.All,Policy.Read.All,Policy.Read.PermissionGrant,RoleManagement.Read.Directory')
Check 'Workbook Graph scope set stays unchanged' (($workbookPlan.GraphReadPermissions -join ',') -ceq 'AuditLog.Read.All,DeviceManagementConfiguration.Read.All,Domain.Read.All,LicenseAssignment.Read.All,Policy.Read.All,Policy.Read.PermissionGrant,RoleManagement.Read.Directory,SharePointTenantSettings.Read.All,User.Read.All')

# These pure modules have no network, authentication, collection, export or
# dynamic-command seam. Review additions deliberately instead of allowing an
# unexpected qualified command to evade the runtime traps below.
$pureCommands=@('Set-StrictMode','Get-AuditProperty','Get-AuditSourceCatalog','Get-FlapjacksMailBaselineDefinitions','Get-FlapjacksMailBaselineAntiphishDefinitions','Get-FlapjacksMailBaselineSpamDefinitions','Get-FlapjacksMailBaselineProtectionDefinitions','Get-FlapjacksMailBaselineFileTypesDefinitions','IsList','IsInteger','ForEach-Object','Where-Object','Sort-Object','Measure-Object')
foreach($file in Get-ChildItem -LiteralPath (Join-Path $script:AuditRoot 'src') -Filter 'MailBaseline*.ps1'){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 Check ('Mail PowerShell parses '+$file.Name) ($errors.Count -eq 0)
 $commands=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true))
 Check ('Mail module has only reviewed pure command calls '+$file.Name) (@($commands|Where-Object {$_.GetCommandName() -cnotin $pureCommands}).Count -eq 0)
}


# Trap provider/session/HTTP entry points before invoking synthetic collection or
# pure comparison. Any accidental attempt is an explicit gate failure.
$script:ExternalCalls=0
foreach($name in @('Get-AuditGraphContext','Get-AuditCommandSession','Read-AuditGraphSource','Read-AuditCommandSource','Invoke-MgGraphRequest','Invoke-WebRequest','Invoke-RestMethod')+@($catalog|Where-Object Provider -ne 'Graph'|ForEach-Object Target|Sort-Object -Unique)){
 Set-Item -LiteralPath ('Function:script:'+$name) -Value {$script:ExternalCalls++;throw 'MAIL_QA: provider or network invocation is forbidden'}
}

$default=Invoke-M365OrganizationAudit -Mode Synthetic
$workbook=Invoke-M365OrganizationAudit -Mode Synthetic -Workbook -WorkbookMailBaseline Standard
Check 'Default A collection remains 46 sources' ($default.SelectedCount -eq 46 -and $default.Evidence.Count -eq 46)
Check 'Workbook mail benchmark adds no sources or requests' ($workbook.SelectedCount -eq 55 -and $workbook.Evidence.Count -eq 55 -and @($workbook.Evidence|Where-Object RequestCount -ne 0).Count -eq 0)
Check 'No implicit output or real session checks' (-not $default.OutputPath -and -not $workbook.OutputPath -and $script:ExternalCalls -eq 0)
Check 'Default A remains exactly the original five pilot controls' ((@(Get-FlapjacksAllPostureChecks -Result $default).ControlId -join ',') -ceq 'EXO-AUDIT,EXO-DIRECT-SEND,EXO-SMTP-AUTH,ENTRA-APP-REG,EOP-FILE-FILTER')
Check 'Direct API refuses profile without Workbook opt-in' (Rejects {Invoke-M365OrganizationAudit -Mode Synthetic -WorkbookMailBaseline Standard})

$definitions=@(Get-FlapjacksMailBaselineDefinitions)
Check 'Mail definitions exist with unique IDs' ($definitions.Count -gt 0 -and @($definitions.Id|Sort-Object -Unique).Count -eq $definitions.Count)
$globalExpected=[ordered]@{'MDO-ORG-COLLAB'=$true;'MDO-ORG-SAFEDOCS'=$true;'MDO-ORG-SAFEDOCS-OPEN'=$false}
$globalIds=@($globalExpected.Keys)
Check 'Wave3 has 51 mail rows and exactly three separate global recommendations' ($definitions.Count -eq 51 -and (@($definitions|Where-Object {$null -ne (Get-AuditProperty $_ 'Global')}|ForEach-Object Id) -join ',') -ceq ($globalIds -join ','))
foreach($id in $globalIds){
 $d=@($definitions|Where-Object Id -ceq $id)[0]
 Check ($id+' exact Microsoft global Boolean is separate from both preset profiles') ($d.Global -is [bool] -and $d.Global -ceq $globalExpected[$id] -and $null -eq $d.Standard -and $null -eq $d.Strict)
}
$optionalMailFields=@{
 'exchange-antiphish-policies'='TargetedUserProtectionAction,TargetedDomainProtectionAction,MailboxIntelligenceProtectionAction'
 'exchange-antispam-policies'='QuarantineRetentionPeriod,SpamZapEnabled,PhishZapEnabled'
}
foreach($source in $catalog){
 $optional=Get-AuditProperty $source 'OptionalFields' @()
 if($optionalMailFields.ContainsKey($source.Id)){
  Check ('Wave2 has exactly the reviewed optional fields '+$source.Id) (($optional -join ',') -ceq $optionalMailFields[$source.Id])
  Check ('Wave2 optional fields do not alter required source fields '+$source.Id) (@($source.Fields|Where-Object {$_ -in $optional}).Count -eq 0)
 }else{Check ('No unreviewed optional projection '+$source.Id) ($optional.Count -eq 0)}
}
foreach($d in $definitions){
 $source=@($catalog|Where-Object Id -ceq $d.SourceId)
 Check ('Mail definition uses fixed collected Exchange source '+$d.Id) ($source.Count -eq 1 -and $source[0].Provider -ceq 'Exchange' -and $source[0].Target -ceq $d.Target -and $d.Field -cin (@($source[0].Fields)+@((Get-AuditProperty $source[0] 'OptionalFields' @()))))
}

function Sample([string]$Baseline='Standard'){
 # Generated valid scaffolding isolates fail-closed gates. Numeric and enum
 # benchmark expectations are pinned independently below, not inferred here.
 $sample=Copy-Result $workbook
 foreach($sourceId in @($definitions.SourceId|Sort-Object -Unique)){
  $source=@($sample.Evidence|Where-Object SourceId -ceq $sourceId)[0]
  $item=[ordered]@{Identity='MAIL_QA_RAW_ID';Name='MAIL_QA_RAW_NAME';IsBuiltInProtection=$false}
  foreach($d in @($definitions|Where-Object SourceId -ceq $sourceId)){
   $value=Get-AuditProperty $d $Baseline
   if($d.Id -cin $globalIds){$value=$globalExpected[$d.Id]}
   if($d.Kind -ceq 'EmptyList'){$value=@()}
   $item[$d.Field]=$value
  }
  $source.Status='Collected';$source.Count=1;$source.Items=@([pscustomobject]$item);$source.MissingFields=@()
 }
 return $sample
}
function Mail($Result,[string]$Baseline='Standard'){@(Get-FlapjacksMailBaselineChecks -Result $Result -Baseline $Baseline)}
function All-Unknown($Result,[string]$SourceId){
 $rows=@(Mail $Result|Where-Object SourceId -ceq $SourceId)
 return ($rows.Count -gt 0 -and @($rows|Where-Object Status -cne 'Not assessed').Count -eq 0)
}

$good=Sample
$before=$good|ConvertTo-Json -Depth 100
$rows=@(Mail $good)
Check 'One output row per definition and no duplicate controls' ($rows.Count -eq $definitions.Count -and @($rows.ControlId|Sort-Object -Unique).Count -eq $rows.Count)
Check 'Only the separate global rows have no Standard/Strict expectation' ((@($definitions|Where-Object {$null -eq (Get-AuditProperty $_ 'Standard')}|ForEach-Object Id) -join ',') -ceq ($globalIds -join ','))
Check 'Complete correctly typed fixture meets selected Standard and global settings' (@($rows|Where-Object Status -cne 'Meets selected setting').Count -eq 0)
foreach($baseline in @('None','Standard','Strict')){
 $globalRows=@(Mail $good $baseline|Where-Object ControlId -cin $globalIds)
 Check ('All three global recommendations assess independently of '+$baseline) ($globalRows.Count -eq 3 -and @($globalRows|Where-Object Status -cne 'Meets selected setting').Count -eq 0)
 foreach($row in $globalRows){
  Check ($row.ControlId+' labels global rather than '+$baseline+' recommendation') ($row.Expected -cmatch '^Microsoft global recommendation: ' -and $row.ProfileVersion -ceq 'Flapjacks Microsoft global mail policy 0.1' -and ($row.Expected+' '+$row.Observed+' '+$row.StatusDetailsSafe+' '+$row.ProfileVersion) -notmatch 'Standard|Strict')
 }
}
Check 'No selection leaves preset rows unknown without suppressing global checks' (@(Mail $good None|Where-Object {$_.ControlId -cnotin $globalIds -and $_.Status -cne 'Not assessed'}).Count -eq 0)
$unspecified=@(Get-FlapjacksMailBaselineChecks -Result $good)
Check 'Pure evaluator default is None, not implicit Standard, while global checks remain assessable' (@($unspecified|Where-Object {$_.ControlId -cnotin $globalIds -and $_.Status -cne 'Not assessed'}).Count -eq 0 -and @($unspecified|Where-Object {$_.ControlId -cin $globalIds -and $_.Status -ceq 'Meets selected setting'}).Count -eq 3)
$noWorkbook=Copy-Result $good;$noWorkbook.Metadata.SelectedGroups=@($default.Metadata.SelectedGroups)
Check 'Complete saved mail evidence never opts aggregate reporting into Workbook' (@(Get-FlapjacksAllPostureChecks -Result $noWorkbook).Count -eq 5)
$globalOnly=Copy-Result $good;$globalOnly.Metadata.WorkbookAntiPhishBaseline='None'
$globalOnlyRows=@(Get-FlapjacksAllPostureChecks -Result $globalOnly)
Check 'Workbook None retains 81 aggregate rows with exactly three assessed global mail recommendations' ($globalOnlyRows.Count -eq 81 -and @($globalOnlyRows|Where-Object {$_.ControlId -cin $globalIds -and $_.Status -ceq 'Meets selected setting'}).Count -eq 3 -and @($globalOnlyRows|Where-Object {$_.ControlId -cin $definitions.Id -and $_.ControlId -cnotin $globalIds -and $_.Status -cne 'Not assessed'}).Count -eq 0)
Check 'Evaluator is pure and never mutates evidence' (($good|ConvertTo-Json -Depth 100) -ceq $before -and $script:ExternalCalls -eq 0)
foreach($row in $rows){
 Check ('Closed status and bounded recommendation claim '+$row.ControlId) ($row.Status -cin @('Meets selected setting','Needs action','Not assessed') -and $row.Limitation -match 'effective' -and $row.Reference -like 'https://learn.microsoft.com/*')
 Check ('Microsoft recommendation distinct from NIST mapping '+$row.ControlId) ($row.RecommendationAuthority -match 'Microsoft' -and $row.NistMappingNote -match 'not proof|not.*compliance|not.*certification|not NIST outcome attainment')
 Check ('Observed/display contains no raw policy identity '+$row.ControlId) (($row.Observed+' '+$row.StatusDetailsSafe) -notmatch 'MAIL_QA_RAW_')
}

# Each source must independently fail closed. A good sibling source must never
# fill an unknown value or convert an unsupported result into a pass or failure.
foreach($sourceId in @($definitions.SourceId|Sort-Object -Unique)){
 foreach($state in @('Partial','AccessDenied','Unauthorized','NotConnected','Error','Unlicensed','NotSelected','ModuleUnavailable','NotProvided','Throttled','Unavailable','InsufficientPermissions','collected','unexpected',$null,@('Collected'),1,$true)){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Status=$state
  Check ($sourceId+' '+$state+' remains Not assessed') (All-Unknown $r $sourceId)
 }
 foreach($provider in @('Graph','Purview','exchange','',$null,@('Exchange'),@{},$true)){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Provider=$provider
  Check ($sourceId+' wrong provider remains Not assessed '+[string]$provider) (All-Unknown $r $sourceId)
 }
 foreach($target in @('Get-OrganizationConfig','Invoke-Expression','https://sensitive.invalid/MAIL_QA_RAW_URL','',$null,@(@($catalog|Where-Object Id -ceq $sourceId)[0].Target),@{},$true)){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Target=$target
  Check ($sourceId+' wrong command remains Not assessed '+[string]$target) (All-Unknown $r $sourceId)
 }
 foreach($property in @('Provider','Target','Count','Items','MissingFields')){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.PSObject.Properties.Remove($property)
  Check ($sourceId+' absent '+$property+' remains Not assessed') (All-Unknown $r $sourceId)
 }
 foreach($count in @($null,$true,'1',1.0,-1,0,2)){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Count=$count
  Check ($sourceId+' invalid Count '+[string]$count+' remains Not assessed') (All-Unknown $r $sourceId)
 }
 foreach($items in @($null,'bad',@{Identity='MAIL_QA_RAW_ID'},[pscustomobject]@{Identity='MAIL_QA_RAW_ID'})){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Items=$items
  Check ($sourceId+' invalid Items shape remains Not assessed') (All-Unknown $r $sourceId)
 }
 foreach($missing in @($null,'',@{},@('UnexpectedField'))){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.MissingFields=$missing
  Check ($sourceId+' missing-field shape/completeness remains Not assessed') (All-Unknown $r $sourceId)
 }
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0];$e.Items=@();$e.Count=0
 Check ($sourceId+' successful empty is Not assessed, never N/A') (All-Unknown $r $sourceId)
 $r=Sample;$r.Evidence=@($r.Evidence|Where-Object SourceId -cne $sourceId)
 Check ($sourceId+' missing source is Not assessed') (All-Unknown $r $sourceId)
}

# Missing or malformed values must remain unknown, including in a mixed source
# containing another fully valid or explicitly nonmatching policy.
foreach($d in $definitions){
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].PSObject.Properties.Remove($d.Field)
 Check ($d.Id+' missing setting stays Not assessed') ((By (Mail $r) $d.Id).Status -ceq 'Not assessed')
 $invalid=switch($d.Kind){
  'Boolean' {@($null,'false','true',0,1,@($true),@{})}
  'Enumeration' {@($null,0,$true,'MAIL_QA_RAW_UNKNOWN_ENUM','',@('Quarantine'),@{})}
  'IntegerExact' {@($null,[string]$d.Standard,[double]$d.Standard,$true,-1,($d.Maximum+1),@($d.Standard),@{})}
  'EmptyList' {@($null,'MAIL_QA_RAW_ADDRESS@example.test',42,$true,@{},@(''),@(42),@($null))}
  'ContainsAllFileTypes' {@($null,'exe',42,$true,@{})}
  default {throw ('Unreviewed benchmark type: '+$d.Kind)}
 }
 foreach($value in $invalid){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=$value
  Check ($d.Id+' invalid '+$d.Kind+' stays Not assessed '+[string]$value) ((By (Mail $r) $d.Id).Status -ceq 'Not assessed')
  $e.Items+=@((Sample).Evidence|Where-Object SourceId -ceq $d.SourceId|ForEach-Object {$_.Items[0]});$e.Count=2
  Check ($d.Id+' valid sibling cannot hide malformed setting') ((By (Mail $r) $d.Id).Status -ceq 'Not assessed')
 }
 if($d.Kind -ceq 'Boolean'){
  $expected=if($d.Id -cin $globalIds){$globalExpected[$d.Id]}else{$d.Standard}
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=(-not [bool]$expected)
  Check ($d.Id+' explicit opposite Boolean needs action, never unknown') ((By (Mail $r) $d.Id).Status -ceq 'Needs action')
  if($d.Id -cin $globalIds){
   foreach($baseline in @('None','Standard','Strict')){
    Check ($d.Id+' global mismatch needs action independently of '+$baseline) ((By (Mail $r $baseline) $d.Id).Status -ceq 'Needs action')
   }
  }
 }
 if($d.Kind -ceq 'Enumeration'){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=([string]$d.Standard).ToLowerInvariant()
  Check ($d.Id+' recognized enum casing is semantically accepted') ((By (Mail $r) $d.Id).Status -ceq 'Meets selected setting')
 }
 if($d.Kind -ceq 'EmptyList'){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=@('MAIL_QA_RAW_EXCEPTION@example.test')
  $row=By (Mail $r) $d.Id
  Check ($d.Id+' populated exception list needs review with no address leak') ($row.Status -ceq 'Needs action' -and ($row.Observed+' '+$row.StatusDetailsSafe) -notmatch 'MAIL_QA_RAW_')
 }
 if(Get-AuditProperty $d 'ZeroMeansUnknown' $false){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=0
  Check ($d.Id+' service-default zero is Not assessed in Standard') ((By (Mail $r Standard) $d.Id).Status -ceq 'Not assessed')
  Check ($d.Id+' service-default zero is Not assessed in Strict') ((By (Mail $r Strict) $d.Id).Status -ceq 'Not assessed')
 }
 if(Get-AuditProperty $d 'ExcludeBuiltIn' $false){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].IsBuiltInProtection=$true
  Check ($d.Id+' built-in-only evidence cannot satisfy selected profile') ((By (Mail $r) $d.Id).Status -ceq 'Not assessed')
  foreach($flag in @($null,'true','false',0,1,@($false))){
   $e.Items[0].IsBuiltInProtection=$flag
   Check ($d.Id+' ambiguous built-in flag stays Not assessed') ((By (Mail $r) $d.Id).Status -ceq 'Not assessed')
  }
  $e.Items[0].IsBuiltInProtection=$true;$e.Items[0].($d.Field)=$null
  $e.Items+=@((Sample).Evidence|Where-Object SourceId -ceq $d.SourceId|ForEach-Object {$_.Items[0]});$e.Count=2
  Check ($d.Id+' explicit built-in skipped, valid custom policy retained') ((By (Mail $r) $d.Id).Status -ceq 'Meets selected setting')
 }
}
Check 'All correctly typed Strict and global settings meet their recommendations' (@(Mail (Sample Strict) Strict|Where-Object Status -cne 'Meets selected setting').Count -eq 0)
Check 'Invalid selected profile rejected' (Rejects {Get-FlapjacksMailBaselineChecks -Result $good -Baseline Custom})
Check 'No full evidence rows is rejected rather than fabricated' (Rejects {Get-FlapjacksMailBaselineChecks -Result @{Evidence=@()} -Baseline Standard})
$r=Sample;$r.Evidence+=@($r.Evidence[0])
Check 'Duplicate source IDs rejected instead of merging runs' (Rejects {Mail $r})
$r=Sample;$r.Evidence[0].SourceId='../MAIL_QA_RAW_TRAVERSAL'
Check 'Invalid source identity rejected' (Rejects {Mail $r})
$r=Sample;$r|Add-Member -NotePropertyName Coverage -NotePropertyValue $r.Evidence -Force;$r.PSObject.Properties.Remove('Evidence')
Check 'Full saved Coverage records are supported' (@(Mail $r|Where-Object Status -cne 'Meets selected setting').Count -eq 0)
$summary=@{Coverage=@($workbook.Coverage)}
Check 'Summary-only Coverage cannot substitute for raw source evidence' (@(Mail $summary|Where-Object Status -cne 'Not assessed').Count -eq 0)

# Independently pinned documented defaults. Keep this fixture distinct from the
# production registry so a mutually consistent omission cannot pass unnoticed.
# Source: Microsoft Learn common-attachments-filter-in-anti-malware-policies,
# reviewed 2026-11-17. This is not the workbook's custom dangerous-extension list.
$fileTypeId='EOP-MALWARE-FILE-TYPES'
$fileTypes='ace,ani,apk,app,appx,arj,bat,cab,cmd,com,deb,dex,dll,docm,elf,exe,hta,img,iso,jar,jnlp,kext,lha,lib,library,lnk,lzh,macho,msc,msi,msix,msp,mst,pif,ppa,ppam,reg,rev,scf,scr,sct,sys,uif,vb,vbe,vbs,vxd,wsc,wsf,wsh,xll,xz,z' -split ','
$fileDefinition=@($definitions|Where-Object Id -ceq $fileTypeId)[0]
Check 'Exactly one FileTypes completeness row, not 53 extension controls' (@($definitions|Where-Object Field -ceq 'FileTypes').Count -eq 1 -and $fileDefinition.Kind -ceq 'ContainsAllFileTypes' -and $fileDefinition.SourceId -ceq 'exchange-malware-policies' -and $fileDefinition.Target -ceq 'Get-MalwareFilterPolicy')
Check 'Both preset profiles pin the exact independent 53-type default list' ($fileTypes.Count -eq 53 -and ($fileDefinition.Standard -join ',') -ceq ($fileTypes -join ',') -and ($fileDefinition.Strict -join ',') -ceq ($fileTypes -join ','))
Check 'FileTypes comparison retains effective-protection and custom-workbook limitations' ($fileDefinition.Limitation -match 'effective recipient protection' -and $fileDefinition.Limitation -match '168.*partial' -and $fileDefinition.Limitation -match 'custom extension list' -and $fileDefinition.Limitation -match 'enabled-rule')
foreach($baseline in @('Standard','Strict')){
 foreach($case in @(
  [pscustomobject]@{Name='all documented defaults';Value=@($fileTypes)},
  [pscustomobject]@{Name='uppercase defaults';Value=@($fileTypes|ForEach-Object {$_.ToUpperInvariant()})},
  [pscustomobject]@{Name='uppercase dotted defaults';Value=@($fileTypes|ForEach-Object {'.'+$_.ToUpperInvariant()})},
  [pscustomobject]@{Name='reordered duplicate and additional valid tokens';Value=@($fileTypes|Sort-Object -Descending)+@('exe','.EXE','MAILQARAWEXTRA','7z')}
 )){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0];$e.Items[0].FileTypes=$case.Value
  $row=By (Mail $r $baseline) $fileTypeId
  Check ('FileTypes '+$case.Name+' meet '+$baseline) ($row.Status -ceq 'Meets selected setting')
  Check ('FileTypes '+$case.Name+' disclose only bounded counts in '+$baseline) ($row.Observed -match '53 of 53' -and ($row.Observed+' '+$row.StatusDetailsSafe) -notmatch 'MAILQARAWEXTRA|\.EXE|\b7z\b')
 }
 foreach($omitted in $fileTypes){
  $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0];$e.Items[0].FileTypes=@($fileTypes|Where-Object {$_ -cne $omitted})
  $row=By (Mail $r $baseline) $fileTypeId
  Check ('FileTypes known omission '+$omitted+' needs action in '+$baseline) ($row.Status -ceq 'Needs action' -and $row.Observed -match '52 of 53')
 }
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0];$e.Items[0].FileTypes=@()
 $row=By (Mail $r $baseline) $fileTypeId
 Check ('FileTypes typed empty list is a known gap in '+$baseline) ($row.Status -ceq 'Needs action' -and $row.Observed -match '0 of 53')
}
$badFileTypes=@(
 [pscustomobject]@{Name='missing token';Value=@($null)},
 [pscustomobject]@{Name='numeric token';Value=@(42)},
 [pscustomobject]@{Name='Boolean token';Value=@($false)},
 [pscustomobject]@{Name='object token';Value=@(@{Name='exe'})},
 [pscustomobject]@{Name='nested token list';Value=@((,@('exe','dll')))},
 [pscustomobject]@{Name='empty token';Value=@('')},
 [pscustomobject]@{Name='whitespace token';Value=@(' ')},
 [pscustomobject]@{Name='leading whitespace';Value=@(' exe')},
 [pscustomobject]@{Name='trailing whitespace';Value=@('exe ')},
 [pscustomobject]@{Name='trailing newline';Value=@("exe`n")},
 [pscustomobject]@{Name='embedded newline';Value=@("ex`ne")},
 [pscustomobject]@{Name='terminal escape';Value=@(([string][char]27+'[31mMAIL_QA_RAW_EXTENSION'))},
 [pscustomobject]@{Name='formula token';Value=@('=MAIL_QA_RAW_EXTENSION')},
 [pscustomobject]@{Name='HTML token';Value=@('<MAIL_QA_RAW_EXTENSION>')},
 [pscustomobject]@{Name='URL token';Value=@('https://sensitive.invalid/MAIL_QA_RAW_EXTENSION')},
 [pscustomobject]@{Name='path token';Value=@('../MAIL_QA_RAW_EXTENSION')},
 [pscustomobject]@{Name='wildcard token';Value=@('*.exe')},
 [pscustomobject]@{Name='double-dot token';Value=@('..exe')},
 [pscustomobject]@{Name='compound token';Value=@('exe.dll')},
 [pscustomobject]@{Name='joined tokens';Value=@('exe,dll')},
 [pscustomobject]@{Name='unsupported Unicode';Value=@('éxe')},
 [pscustomobject]@{Name='oversized token';Value=@('MAILQARAWEXTENSIONTOOLONG')}
)
foreach($case in $badFileTypes){
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0];$e.Items[0].FileTypes=$case.Value
 foreach($baseline in @('Standard','Strict')){
  $row=By (Mail $r $baseline) $fileTypeId
  Check ('FileTypes '+$case.Name+' remains unknown in '+$baseline) ($row.Status -ceq 'Not assessed')
  Check ('FileTypes '+$case.Name+' never leaks into display text') (($row.Observed+' '+$row.StatusDetailsSafe) -notmatch 'MAIL_QA_RAW_|MAILQARAW|sensitive.invalid')
 }
 $e.Items[0].FileTypes=@($fileTypes)+$case.Value
 Check ('FileTypes '+$case.Name+' poisons even an otherwise complete list') ((By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')
 $e.Items+=@((Sample).Evidence|Where-Object SourceId -ceq 'exchange-malware-policies'|ForEach-Object {$_.Items[0]});$e.Count=2
 Check ('FileTypes '+$case.Name+' is not hidden by a complete sibling policy') ((By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')
 $e.Items[1].FileTypes=@()
 Check ('FileTypes '+$case.Name+' remains unknown despite a known failing sibling') ((By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')
}
$r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0]
$e.Items+=@((Sample).Evidence|Where-Object SourceId -ceq 'exchange-malware-policies'|ForEach-Object {$_.Items[0]});$e.Count=2;$e.Items[1].FileTypes=@('exe')
Check 'Complete and incomplete valid policy lists fail rather than merging their coverage' ((By (Mail $r) $fileTypeId).Status -ceq 'Needs action')
$e.Items[0].FileTypes=@($fileTypes|Where-Object {$_ -cne 'exe'})
Check 'Separate partial policy lists cannot jointly satisfy per-policy file coverage' ((By (Mail $r) $fileTypeId).Status -ceq 'Needs action')
$e.Items[1].FileTypes=@('=MAIL_QA_RAW_EXTENSION')
Check 'A later malformed policy overrides an earlier known file-type mismatch' ((By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')
$e.Items[0].FileTypes=@($fileTypes)
Check 'A later malformed policy overrides an earlier complete file-type match' ((By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')

# Independently pinned Microsoft values prevent self-consistent but wrong profile
# definitions from passing the generated scaffolding checks above.
$profileDifferences=@(
 @('EOP-SPAM-BULK-THRESHOLD',6,5),
 @('EOP-SPAM-ACTION','MoveToJmf','Quarantine'),
 @('EOP-SPAM-BULK-ACTION','MoveToJmf','Quarantine'),
 @('EOP-SPAM-OUTBOUND-EXTERNAL-LIMIT',500,400),
 @('EOP-SPAM-OUTBOUND-INTERNAL-LIMIT',1000,800),
 @('EOP-SPAM-OUTBOUND-DAILY-LIMIT',1000,800),
 @('MDO-PHISH-SPOOF-ACTION','MoveToJmf','Quarantine'),
 @('MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION','MoveToJmf','Quarantine')
)
foreach($case in $profileDifferences){
 $d=@($definitions|Where-Object Id -ceq $case[0])[0]
 Check ($d.Id+' exact Standard/Strict recommendation pinned') ($d.Standard -ceq $case[1] -and $d.Strict -ceq $case[2])
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $d.SourceId)[0];$e.Items[0].($d.Field)=$case[1]
 Check ($d.Id+' Standard value matches Standard and deviates from Strict') ((By (Mail $r Standard) $d.Id).Status -ceq 'Meets selected setting' -and (By (Mail $r Strict) $d.Id).Status -ceq 'Needs action')
 $e.Items[0].($d.Field)=$case[2]
 Check ($d.Id+' Strict value matches Strict and deviates from exact Standard') ((By (Mail $r Strict) $d.Id).Status -ceq 'Meets selected setting' -and (By (Mail $r Standard) $d.Id).Status -ceq 'Needs action')
}
Check 'No duplicate legacy spoof-intelligence/threshold/file-filter controls' (@($definitions.Id|Where-Object {$_ -cin @('EOP-SPOOF-INTELLIGENCE','EOP-PHISH-THRESHOLD','EOP-FILE-FILTER')}).Count -eq 0)
Check 'Business-specific language, regional and block lists remain inventory only' (@($definitions|Where-Object Field -cin @('EnableLanguageBlockList','LanguageBlockList','EnableRegionBlockList','RegionBlockList','BlockedSenders','BlockedSenderDomains','TargetedUsersToProtect','TargetedDomainsToProtect')).Count -eq 0)
$wave2Values=@(
 @('MDO-PHISH-USER-ACTION','Quarantine'),
 @('MDO-PHISH-DOMAIN-ACTION','Quarantine'),
 @('EOP-SPAM-QUARANTINE-RETENTION',30),
 @('EOP-SPAM-PHISH-ZAP',$true),
 @('EOP-SPAM-ZAP',$true)
)
foreach($case in $wave2Values){
 $d=@($definitions|Where-Object Id -ceq $case[0])[0]
 Check ($d.Id+' independently pinned equal Standard/Strict recommendation') ($d.Standard -ceq $case[1] -and $d.Strict -ceq $case[1])
}
foreach($sourceId in $optionalMailFields.Keys){
 $r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq $sourceId)[0]
 $optional=$optionalMailFields[$sourceId] -split ','
 foreach($field in $optional){$e.Items[0].PSObject.Properties.Remove($field)}
 $checks=@(Mail $r|Where-Object SourceId -ceq $sourceId)
 Check ($sourceId+' old complete evidence leaves exactly three new fields unknown') (@($checks|Where-Object {$_.Field -in $optional -and $_.Status -ceq 'Not assessed'}).Count -eq 3)
 Check ($sourceId+' optional absence preserves all earlier complete setting assessments') (@($checks|Where-Object {$_.Field -notin $optional -and $_.Status -cne 'Meets selected setting'}).Count -eq 0)
}
$r=Sample;$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-outbound-spam-policies')[0];$e.Items[0].AutoForwardingMode='Automatic'
Check 'Automatic forwarding is not silently equated with Off' ((By (Mail $r) 'EOP-SPAM-OUTBOUND-FORWARDING').Status -ceq 'Needs action')
$e.Items[0].NotifyOutboundSpam=$false
Check 'Explicit false legacy notify switch remains valid exact baseline' ((By (Mail $r) 'EOP-SPAM-OUTBOUND-LEGACY-NOTIFY').Status -ceq 'Meets selected setting')

# Invalid user-controlled display text and raw identities stay in private source
# evidence only. The exporter must preserve typed false, not replace it by null.
$work=Join-Path (Split-Path $script:AuditRoot -Parent) ('test-output/mail-baseline-security-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$r=Sample
$r.Metadata.TenantId='MAIL_QA_RAW_TENANT'
foreach($e in $r.Evidence){$e.Reason='MAIL_QA_RAW_REASON'}
$e=@($r.Evidence|Where-Object SourceId -ceq 'exchange-antiphish-policies')[0]
$e.Items[0].Identity='=MAIL_QA_RAW_FORMULA';$e.Items[0].EnableFirstContactSafetyTips=$false
$e.Items[0].AuthenticationFailAction='MAIL_QA_RAW_UNKNOWN_ENUM'
$e.Items[0].ExcludedSenders=@('MAIL_QA_RAW_ADDRESS@example.test')
$e.Items[0]|Add-Member -NotePropertyName RawUrl -NotePropertyValue 'https://sensitive.invalid/MAIL_QA_RAW_URL'
$malware=@($r.Evidence|Where-Object SourceId -ceq 'exchange-malware-policies')[0]
$malware.Items[0].FileTypes=@($fileTypes)+@('=MAIL_QA_RAW_EXTENSION','<MAIL_QA_RAW_EXTENSION>','https://sensitive.invalid/MAIL_QA_RAW_EXTENSION')
$r.Metadata|Add-Member -NotePropertyName StatusDetailsSafe -NotePropertyValue 'MAIL_QA_RAW_METADATA'
$before=$r|ConvertTo-Json -Depth 100
$bundle=Export-FlapjacksPostureBundle -Result $r -OutputDirectory (Join-Path $work 'bundle')
Check 'Full bundle export never mutates input' (($r|ConvertTo-Json -Depth 100) -ceq $before)
Check 'Mail controls integrate additively into exactly 81 complete unique rows' ($bundle.PostureChecks -eq 81 -and $bundle.PostureChecks -eq @(Get-FlapjacksAllPostureChecks -Result $r).Count -and @((Get-FlapjacksAllPostureChecks -Result $r).ControlId|Sort-Object -Unique).Count -eq 81)
Check 'Bundle still includes exactly 55 source records' ($bundle.Sources -eq 55)
Check 'Full source-tagged artifact manifest validates' (Test-M365AuditManifest -Path $bundle.OutputDirectory).Valid
$saved=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'evidence/exchange-antiphish-policies.json') -Raw|ConvertFrom-Json -Depth 100
Check 'Private JSON retains exact raw identity, false Boolean and invalid original value' ($saved.Items[0].Identity -ceq '=MAIL_QA_RAW_FORMULA' -and $saved.Items[0].EnableFirstContactSafetyTips -is [bool] -and $saved.Items[0].EnableFirstContactSafetyTips -ceq $false -and $saved.Items[0].AuthenticationFailAction -ceq 'MAIL_QA_RAW_UNKNOWN_ENUM')
$savedMalware=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'evidence/exchange-malware-policies.json') -Raw|ConvertFrom-Json -Depth 100
Check 'Private JSON preserves hostile FileTypes without trusting or changing them' (($savedMalware.Items[0].FileTypes -join '|') -ceq ($malware.Items[0].FileTypes -join '|') -and (By (Mail $r) $fileTypeId).Status -ceq 'Not assessed')
$inventory=@(Import-Csv -LiteralPath (Join-Path $bundle.OutputDirectory 'inventory.csv'))
Check 'Private CSV preserves source attribution and neutralizes identity formula' (@($inventory|Where-Object {$_.SourceId -ceq 'exchange-antiphish-policies' -and $_.ObjectId -ceq "'=MAIL_QA_RAW_FORMULA"}).Count -gt 0)
$display=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'Posture-Report.csv') -Raw
$pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $bundle.OutputDirectory 'Posture-Report.pdf')))
$zip=Read-Zip (Join-Path $bundle.OutputDirectory 'Posture-Report.xlsx');$allXml=$zip.Values -join "`n"
Check 'CSV/PDF/XLSX display excludes raw policy identity/address/status/URL/extension markers' (($display+$pdf+$allXml) -notmatch 'MAIL_QA_RAW_')
Check 'PDF and workbook visibly label fixture-only demonstration' ($pdf -match 'SYNTHETIC DEMONSTRATION' -and $allXml -match 'SYNTHETIC DEMONSTRATION')
Check 'PDF has no active actions, URLs, scripts or attached raw files' ($pdf -notmatch '/(JavaScript|JS|Launch|URI|AcroForm|EmbeddedFile|OpenAction|AA)\b')
Check 'XLSX has no formulas, external links, macros or hyperlinks' ($allXml -notmatch '<f(?:\s|>)|vbaProject|externalLink|TargetMode="External"|<hyperlink')
Check 'Redacted report retains effective-protection limitation' ($display -match 'effective' -and $pdf -match 'not effective|not establish effective|not.*protection')
Check 'Export causes no provider/session/network calls' ($script:ExternalCalls -eq 0)

# Interactive W chooses Standard explicitly. A keeps its existing confirmation,
# five pilot controls and 46 sources; neither action creates files implicitly.
Import-Module (Join-Path (Split-Path $script:AuditRoot -Parent) 'M365Toolkit.psm1') -Force -DisableNameChecking
function New-QARuntime([string[]]$Answers){
 $state=@{Input=[Collections.Generic.Queue[string]]::new();Prompts=[Collections.Generic.List[string]]::new();Text=[Collections.Generic.List[string]]::new();ExternalCalls=0;Audits=[Collections.Generic.List[object]]::new()}
 foreach($answer in $Answers){$state.Input.Enqueue($answer)}
 return @{
  State=$state
  Read={param($Prompt)$state.Prompts.Add($Prompt);if(-not $state.Input.Count){throw 'Unexpected prompt'};$state.Input.Dequeue()}.GetNewClosure()
  Write={param($Text)$state.Text.Add([string]$Text)}.GetNewClosure()
  Connect={$state.ExternalCalls++;throw 'No authentication permitted'}.GetNewClosure()
  Local={$state.ExternalCalls++;throw 'No session inspection permitted'}.GetNewClosure()
  ReadCommand={$state.ExternalCalls++;throw 'No provider read permitted'}.GetNewClosure()
  AuditRun={param($Parameters)$state.Audits.Add($Parameters);Invoke-M365OrganizationAudit @Parameters}.GetNewClosure()
 }
}
foreach($wrong in @('','AUDIT','workbook')){
 $rt=New-QARuntime @('W',$wrong,'Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
 Check ('W wrong confirmation cancels before any work '+$wrong) ($history.Count -eq 0 -and $rt.State.Audits.Count -eq 0 -and $rt.State.ExternalCalls -eq 0)
}
$rt=New-QARuntime @('W','WORKBOOK','Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
Check 'W executes once with explicit workbook and Standard profile' ($history.Count -eq 1 -and $rt.State.Audits.Count -eq 1 -and $rt.State.Audits[0].Workbook -eq $true -and $history[0].Metadata.WorkbookAntiPhishBaseline -ceq 'Standard')
Check 'W preview identifies Standard and collection remains 55 sources' (($rt.State.Text -join ' ') -match 'Standard' -and $history[0].SelectedCount -eq 55 -and -not $history[0].OutputPath -and $rt.State.ExternalCalls -eq 0)
$rt=New-QARuntime @('A','AUDIT','Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
Check 'A keeps original collection and no workbook/profile parameter' ($history.Count -eq 1 -and $history[0].SelectedCount -eq 46 -and -not $rt.State.Audits[0].ContainsKey('Workbook') -and -not $rt.State.Audits[0].ContainsKey('WorkbookAntiPhishBaseline') -and -not $rt.State.Audits[0].ContainsKey('WorkbookMailBaseline') -and $rt.State.ExternalCalls -eq 0)
Check 'A keeps original five assessed controls and no implicit files' (@(Get-FlapjacksAllPostureChecks -Result $history[0]).Count -eq 5 -and -not $history[0].OutputPath)

$result=[pscustomobject]@{Passed=$true;Checks=$script:Assertions.Count;SyntheticOnly=$true;MailControls=$definitions.Count;EvaluableMailControls=$definitions.Count;GlobalMailControls=$globalIds.Count;WorkbookControls=$bundle.PostureChecks;EvidenceRoot=$work;NotExercised=@('Real tenant calls','Sign-in/consent','Live Microsoft SDK/RBAC/licensing','Actual policy delivery/enforcement','Windows acceptance');Assertions=$script:Assertions.ToArray()}
if($ResultsPath){$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultsPath}
$result|Select-Object Passed,Checks,SyntheticOnly,EvidenceRoot
