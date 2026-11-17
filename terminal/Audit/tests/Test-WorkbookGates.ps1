#requires -Version 7.4
# Independent offline security regression tests. Invented evidence and intercepted
# transports only; never install modules, authenticate or contact a real tenant.
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:AuditRoot=Split-Path $PSScriptRoot -Parent
foreach($file in Get-ChildItem -LiteralPath (Join-Path $script:AuditRoot 'src') -Filter '*.ps1' | Sort-Object Name){. $file.FullName}
$script:Assertions=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Condition){
 $script:Assertions.Add([pscustomobject]@{Name=$Name;Passed=$Condition})
 if(-not $Condition){throw "FAIL: $Name"}
}
function Rejects([scriptblock]$Action){try{& $Action|Out-Null;return $false}catch{return $true}}
function Copy-Result($Value){$Value|ConvertTo-Json -Depth 100|ConvertFrom-Json -Depth 100}
function Save-Functions([string[]]$Names){$saved=@{};foreach($name in $Names){$saved[$name]=(Get-Command $name -CommandType Function).ScriptBlock};return $saved}
function Restore-Functions($Saved){foreach($name in $Saved.Keys){Set-Item -LiteralPath ('Function:script:'+ $name) -Value $Saved[$name]}}

# Pin identities as well as count: replacing an original source is not backwards compatibility.
$baseIds=@'
conditional-access
named-locations
security-defaults
authorization-policy
admin-consent-policy
cross-tenant-default
cross-tenant-partners
authentication-methods-policy
authentication-strengths
permission-grant-policies
role-definitions
role-assignments
role-eligibility-instances
tenant-domains
tenant-subscriptions
intune-compliance-policy-metadata
intune-configuration-policy-metadata
exchange-organization
exchange-transport
exchange-authentication-policies
exchange-accepted-domains
exchange-remote-domains
exchange-dkim
exchange-inbound-connectors
exchange-outbound-connectors
exchange-transport-rules
exchange-antispam-policies
exchange-antispam-rules
exchange-outbound-spam-policies
exchange-outbound-spam-rules
exchange-antiphish-policies
exchange-antiphish-rules
exchange-malware-policies
exchange-malware-rules
exchange-safe-links-policies
exchange-safe-links-rules
exchange-safe-attachments-policies
exchange-safe-attachments-rules
exchange-atp-organization
exchange-preset-eop-rules
exchange-preset-atp-rules
exchange-built-in-protection-rule
purview-dlp-policies
purview-dlp-rule-metadata
purview-retention-policies
purview-retention-rules
'@ -split '\r?\n'
$basePlan=Get-M365OrganizationAuditPlan
Check 'Default catalog is still exact original 46 source IDs' (@(Get-AuditSourceCatalog).Count -eq 46 -and ((@(Get-AuditSourceCatalog).Id|Sort-Object)-join ',') -ceq (($baseIds|Sort-Object)-join ','))
Check 'Default organization plan remains original 46 only' ($basePlan.Sources.Count -eq 46 -and (($basePlan.Sources.Id|Sort-Object)-join ',') -ceq (($baseIds|Sort-Object)-join ','))
Check 'Default scopes exclude workbook-only permission expansion' (@($basePlan.GraphReadPermissions|Where-Object {$_ -in @('User.Read.All','AuditLog.Read.All','Application.Read.All','Group.Read.All','Directory.Read.All')}).Count -eq 0)
$extendedPlan=Get-M365OrganizationAuditPlan -Workbook
$optional=@($extendedPlan.Sources|Where-Object Id -notin $baseIds)
Check 'Explicit Workbook plan adds distinct fixed sources' ($optional.Count -gt 0 -and @($extendedPlan.Sources.Id|Sort-Object -Unique).Count -eq $extendedPlan.Sources.Count)
Check 'Extended plan retains every original source' (@($baseIds|Where-Object {$_ -notin $extendedPlan.Sources.Id}).Count -eq 0)
Check 'No read/write or credential-grant permission advertised' (@($extendedPlan.GraphReadPermissions|Where-Object {$_ -match 'Write|ReadWrite|FullControl|AccessAsUser'}).Count -eq 0)
Check 'No automatic connection or permission expansion contract' ($extendedPlan.ConnectionPolicy -match 'No auth' -and $extendedPlan.ConnectionPolicy -match 'existing sessions')

# Source catalog is trusted code, not a report-controlled URL or arbitrary command.
$graphRoutes=@{
 'workbook-identity-registration'='/reports/authenticationMethods/userRegistrationDetails?$select=id,isAdmin,isMfaRegistered,isSsprEnabled,isSsprRegistered,isSsprCapable,lastUpdatedDateTime'
 'workbook-identity-users'='/users?$select=id,accountEnabled,signInActivity'
 'workbook-sharepoint-settings'='/admin/sharepoint/settings?$select=sharingCapability,sharingDomainRestrictionMode,isRequireAcceptingUserToMatchInvitedUserEnabled,isResharingByExternalUsersEnabled'
}
foreach($source in @($optional|Where-Object Provider -eq 'Graph')){
 $initial='https://graph.microsoft.com/v1.0'+$source.Target
 Check ('Exact reviewed Graph allowlist entry '+$source.Id) ($graphRoutes.ContainsKey($source.Id) -and $source.Target -ceq $graphRoutes[$source.Id])
 Check ('Workbook Graph fixed v1.0 route '+$source.Id) ($source.Target.StartsWith('/') -and $source.Target -notmatch '://|/beta|credentials|oauth2PermissionGrants|/messages|signIns')
 Check ('Workbook Graph read permissions '+$source.Id) (@($source.Scopes).Count -gt 0 -and @($source.Scopes|Where-Object {$_ -notmatch '\.Read\.' -or $_ -match 'Write'}).Count -eq 0)
 Check ('Workbook initial URI accepted '+$source.Id) (Test-AuditContinuation $initial $initial)
 $separator=if($initial.Contains('?')){'&'}else{'?'}
 Check ('Same-source continuation accepted '+$source.Id) (Test-AuditContinuation ($initial+$separator+'$skiptoken=synthetic') $initial)
 foreach($bad in @($initial.Replace('graph.microsoft.com','evil.invalid'),$initial.Replace('https:','http:'),($initial+'#fragment'),($initial+$separator+'$expand=members'),($initial+$separator+'$skip=1&$skip=2'),'https://graph.microsoft.com/v1.0/users/another-user')){
  Check ('Unsafe continuation refused '+$source.Id+' '+$bad) (-not (Test-AuditContinuation $bad $initial))
 }
 if($source.Target.Contains('$select=')){
  Check ('Projection cannot disappear on continuation '+$source.Id) (-not (Test-AuditContinuation (($initial -split '\?')[0]+'?$skiptoken=x') $initial))
  Check ('Projection cannot become wildcard '+$source.Id) (-not (Test-AuditContinuation (($initial -split '\?')[0]+'?$select=*&$skiptoken=x') $initial))
 }
 $item=@{id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';accountEnabled=$true;isAdmin=$false;isMfaRegistered=$true;isSsprEnabled=$true;isSsprRegistered=$true;isSsprCapable=$true;sharingCapability='disabled';isRequireAcceptingUserToMatchInvitedUserEnabled=$true;isResharingByExternalUsersEnabled=$false;unexpectedSecret='QA_UNPROJECTED_SECRET';displayName='QA_UNPROJECTED_NAME';signInActivity=@{lastSuccessfulSignInDateTime='2026-10-01T00:00:00Z';lastSignInRequestId='QA_UNPROJECTED_REQUEST';lastSignInDateTime='2099-01-01T00:00:00Z'}}
 $projected=Protect-AuditGraphItem $source $item
 Check ('Unexpected Graph properties discarded locally '+$source.Id) (($projected|ConvertTo-Json -Depth 20) -notmatch 'QA_UNPROJECTED|lastSignInDateTime')
}
foreach($source in @($optional|Where-Object { $_.Provider -notin @('Graph','OfflineSnapshot') })){
 Check ('Optional workload command read-only '+$source.Id) ($source.Target -match '^Get-' -and $source.Target -notmatch '[;|&\r\n]')
}

# SharePoint's documented singleton value-object wrapper is source-specific, not
# permission for collection arrays, nested pagination or arbitrary outer content.
$sharepoint=@($optional|Where-Object Id -eq 'workbook-sharepoint-settings')[0]
$settings=@{sharingCapability='disabled';sharingDomainRestrictionMode='none';isRequireAcceptingUserToMatchInvitedUserEnabled=$true;isResharingByExternalUsersEnabled=$false;unexpectedSecret='QA_WRAPPER_SECRET';allowedDomain='QA_WRAPPER_DOMAIN'}
foreach($wrapped in @($false,$true)){
 $script:SingletonPage=if($wrapped){@{'@odata.context'='https://graph.microsoft.com/v1.0/$metadata#admin/sharepoint/settings';value=$settings}}else{$settings}
 $r=Read-AuditGraphSource -Source $sharepoint -Request {param($Uri)$script:SingletonPage}
 Check ('SharePoint singleton supported shape wrapped='+$wrapped) ($r.Status -eq 'Collected' -and $r.Count -eq 1 -and $r.RequestCount -eq 1)
 Check ('SharePoint wrapper unexpected evidence dropped wrapped='+$wrapped) (($r.Items|ConvertTo-Json -Depth 20) -notmatch 'QA_WRAPPER|odata.context')
 Check ('SharePoint singleton uses fixed four-field projection wrapped='+$wrapped) (@($r.Items[0].PSObject.Properties).Count -eq 4)
}
$badSingletons=@(
 @{value=@($settings)},
 @{value=@($settings,$settings)},
 @{value=@{sharingCapability='disabled';'@odata.nextLink'='https://evil.invalid/steal'}},
 @{value=$settings;'@odata.nextLink'='https://evil.invalid/steal'},
 @{value=$settings;sharingCapability='externalUserAndGuestSharing'},
 @{value=@{value=$settings}},
 @{value=$null},
 @{value='invalid'},
 @{value=@{}},
 @{value=@{error=@{message='QA_WRAPPER_ERROR'}}}
)
foreach($page in $badSingletons){
 $script:SingletonPage=$page
 $r=Read-AuditGraphSource -Source $sharepoint -Request {param($Uri)$script:SingletonPage}
 Check 'Malformed/widened SharePoint singleton stays partial without second request' ($r.Status -eq 'Partial' -and $r.Count -eq 0 -and $r.RequestCount -eq 1)
}
$script:SingletonPage=@{value=@{sharingCapability='disabled'}}
$r=Read-AuditGraphSource -Source $sharepoint -Request {param($Uri)$script:SingletonPage}
Check 'SharePoint missing projected properties remain Partial and explicit' ($r.Status -eq 'Partial' -and $r.Count -eq 1 -and $r.MissingFields.Count -eq 3)
$script:SingletonPage=@{value=@{isEnabled=$true}}
$securityDefaults=@(Get-AuditSourceCatalog|Where-Object Id -eq 'security-defaults')[0]
$r=Read-AuditGraphSource -Source $securityDefaults -Request {param($Uri)$script:SingletonPage}
Check 'SharePoint envelope exception does not widen existing singleton contract' ($r.Status -eq 'Partial' -and $r.Count -eq 0 -and $r.RequestCount -eq 1)

# Parse executable audit commands rather than matching prose that says "no Connect-*".
foreach($file in Get-ChildItem -LiteralPath (Join-Path $script:AuditRoot 'src') -Filter '*.ps1'){
 $tokens=$null;$parseErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
 Check ('PowerShell parses '+$file.Name) ($parseErrors.Count -eq 0)
 $forbidden=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -match '(^|\\)(Connect-|Install-Module|Install-PSResource|Update-Module|Grant-|New-Mg|Set-Mg|Remove-Mg|Invoke-WebRequest|Invoke-RestMethod)'},$true))
 Check ('No authentication/install/write/fallback HTTP command '+$file.Name) ($forbidden.Count -eq 0)
}

$original=Save-Functions @('Get-AuditGraphContext','Get-AuditCommandSession')
try{
 $script:ContextCalls=0
 function Get-AuditGraphContext {$script:ContextCalls++;throw 'No real session inspection allowed'}
 function Get-AuditCommandSession {$script:ContextCalls++;throw 'No real session inspection allowed'}
 $default=Invoke-M365OrganizationAudit -Mode Synthetic
 $extended=Invoke-M365OrganizationAudit -Mode Synthetic -Workbook
 Check 'Synthetic default remains exactly 46 evidence and coverage records' ($default.SelectedCount -eq 46 -and $default.Evidence.Count -eq 46 -and $default.Coverage.Count -eq 46)
 Check 'Synthetic Workbook only collects explicit extended source set' ($extended.SelectedCount -eq $extendedPlan.Sources.Count -and $extended.Evidence.Count -eq $extendedPlan.Sources.Count)
 Check 'Synthetic never inspects real sessions' ($script:ContextCalls -eq 0)
 Check 'No implicit default or Workbook output' (-not $default.OutputPath -and -not $extended.OutputPath)
 $defaultChecks=@(Get-FlapjacksAllPostureChecks -Result $default)
 $extendedChecks=@(Get-FlapjacksAllPostureChecks -Result $extended)
 Check 'Default evaluator retains five pilot checks only' ($defaultChecks.Count -eq 5)
 Check 'Workbook evaluator is additive and has unique controls' ($extendedChecks.Count -gt 5 -and @($extendedChecks.ControlId|Sort-Object -Unique).Count -eq $extendedChecks.Count)
 $collaborationIds=@($optional|Where-Object Provider -eq 'OfflineSnapshot'|ForEach-Object Id)
 $collaborationChecks=@($extendedChecks|Where-Object {$_.SourceId -in $collaborationIds})
 Check 'Unverified Teams/SharePoint sources are represented, not silent' ($collaborationIds.Count -gt 0 -and $collaborationChecks.Count -gt 0)
 Check 'Unverified Teams/SharePoint are Not assessed, never pass or N/A' (@($collaborationChecks|Where-Object Status -ne 'Not assessed').Count -eq 0)
 $missing=Copy-Result $extended
 foreach($row in $missing.Evidence){$row.Status='InsufficientPermissions';$row.Items=@();$row.Count=0}
 Check 'Missing prerequisites make every configured control Not assessed' (@(Get-FlapjacksAllPostureChecks -Result $missing|Where-Object Status -ne 'Not assessed').Count -eq 0)
 $partial=Copy-Result $extended
 foreach($row in $partial.Evidence){$row.Status='Partial'}
 Check 'Partial evidence cannot satisfy configured controls' (@(Get-FlapjacksAllPostureChecks -Result $partial|Where-Object Status -ne 'Not assessed').Count -eq 0)
 $deniedOutput=Join-Path ([IO.Path]::GetTempPath()) ('workbook-denied-'+[guid]::NewGuid().ToString('N'))
 Check 'Live Workbook missing tenant gate rejects before sessions/output' (Rejects {Invoke-M365OrganizationAudit -Mode Live -Workbook -OutputPath $deniedOutput})
 Check 'Rejected Workbook gate has no file or context side effects' (-not (Test-Path -LiteralPath $deniedOutput) -and $script:ContextCalls -eq 0)
 $snapshot=@{Sources=@(@{SourceId='workbook-teams-client';Status='Collected';Count=1;CollectedAtUtc='2026-01-01T00:00:00Z';Items=@(@{Identity='Global';AllowGuestUser=$false});TenantId='QA_FORGED_TENANT';Account='QA_FORGED_ACCOUNT';Provenance=@{ScopeVerification='Verified'}})}
 Check 'Supplying snapshot does not implicitly opt into Workbook' (Rejects {Invoke-M365OrganizationAudit -Mode Synthetic -WorkbookCollaborationSnapshot $snapshot})
 $withSnapshot=Invoke-M365OrganizationAudit -Mode Synthetic -Workbook -WorkbookCollaborationSnapshot $snapshot
 $native=@($withSnapshot.Evidence|Where-Object SourceId -eq 'workbook-teams-client')[0]
 Check 'Explicit snapshot remains unverified offline with zero requests' ($native.Status -ceq 'OfflineSnapshot' -and $native.RequestCount -eq 0 -and $native.PageCount -eq 0 -and $native.Provenance.ScopeVerification -ceq 'Unverified')
 Check 'Supplied native identity claims cannot create verified provenance' (($native|ConvertTo-Json -Depth 20) -notmatch 'QA_FORGED')
 Check 'Snapshot matching settings do not become a tenant assessment pass' (@(Get-FlapjacksAllPostureChecks -Result $withSnapshot|Where-Object {$_.SourceId -eq 'workbook-teams-client' -and $_.Status -ne 'Not assessed'}).Count -eq 0)
}finally{Restore-Functions $original}

# A source's alternative main scopes and additional mandatory scopes must all be respected.
foreach($source in @($optional|Where-Object Provider -eq 'Graph')){
 $scopes=@($source.Scopes[0])+@((Get-AuditProperty $source 'RequiredScopes' @())|ForEach-Object {$_})
 Check ('Exact required read scopes accepted '+$source.Id) (Test-FlapjacksGraphScope $source @{Context=@{Scopes=$scopes}})
 Check ('Absent read scopes rejected '+$source.Id) (-not (Test-FlapjacksGraphScope $source @{Context=@{Scopes=@()}}))
 foreach($required in (Get-AuditProperty $source 'RequiredScopes' @())){
  Check ('Missing required scope rejected '+$source.Id+' '+$required) (-not (Test-FlapjacksGraphScope $source @{Context=@{Scopes=@($scopes|Where-Object {$_ -ne $required})}}))
 }
}

# Exercise the actual production request closure with a test-only module bearing
# the qualified Graph command name. No Microsoft module or network is involved.
$saved=Save-Functions @('Get-AuditSourceCatalog','Get-FlapjacksWorkbookSources','Get-AuditGraphContext','Get-AuditCommandSession')
$fakeGraph=New-Module -Name Microsoft.Graph.Authentication -ScriptBlock {
 $script:Calls=0;$script:Next=''
 function Invoke-MgGraphRequest {
  [CmdletBinding()]param([string]$Method,[string]$Uri,[string]$OutputType)
  if($Method -cne 'GET'){throw 'Only GET permitted in this offline transport'}
  $script:Calls++
  @{value=@(@{id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';accountEnabled=$true;signInActivity=@{lastSuccessfulSignInDateTime='2026-10-01T00:00:00Z'}});'@odata.nextLink'=$script:Next}
 }
 Export-ModuleMember -Function Invoke-MgGraphRequest
}
Import-Module $fakeGraph -Force
try{
 $script:ProbeSource=@($optional|Where-Object Id -eq 'workbook-identity-users')[0]
 $tenant=[guid]'11111111-1111-1111-1111-111111111111';$account='qa@synthetic.invalid'
 $script:ProbeScopes=@($script:ProbeSource.Scopes[0])+@((Get-AuditProperty $script:ProbeSource 'RequiredScopes' @())|ForEach-Object {$_})
 function Get-AuditSourceCatalog {@()}
 function Get-FlapjacksWorkbookSources {$script:ProbeSource}
 function Get-AuditCommandSession {throw 'No workload inspection expected in Graph-only test'}
 function Get-AuditGraphContext {
  param($TenantId,$ExpectedAccount)
  $script:ContextCalls++
  $context=@{TenantId=$TenantId.ToString();Account=$ExpectedAccount;AuthType='Delegated';Environment='Global';Scopes=$script:ProbeScopes}
  if($script:ContextCalls -gt $script:ChangeAfter){
   switch($script:ChangeKind){
    'Account' {$context.Account='different@synthetic.invalid'}
    'Tenant' {$context.TenantId='22222222-2222-2222-2222-222222222222'}
    'Scopes' {$context.Scopes=@()}
   }
  }
  Test-AuditGraphIdentity $context $TenantId $ExpectedAccount
 }
 foreach($kind in @('Account','Tenant','Scopes')){
  $script:ContextCalls=0;$script:ChangeAfter=2;$script:ChangeKind=$kind
  $next='https://graph.microsoft.com/v1.0'+$script:ProbeSource.Target+'&$skiptoken=second'
  & $fakeGraph {param($Next) $script:Calls=0;$script:Next=$Next} $next
  $r=Invoke-M365SecurityAudit -Mode Live -Include WorkbookIdentity -TenantId $tenant -ExpectedAccount $account -ConfirmTenantId $tenant -ConfirmOrganizationScope
  $calls=& $fakeGraph {$script:Calls}
  Check ('Changed '+$kind+' blocks Graph page two before transport') ($calls -eq 1 -and $script:ContextCalls -eq 3)
  Check ('Changed '+$kind+' retains partial, never complete or empty pass') ($r.Evidence[0].Status -eq 'Partial' -and $r.Evidence[0].Count -eq 1)
 }
 # Every optional Graph source, including a singleton, rechecks immediately before
 # the first HTTP request instead of relying on its earlier source-level check.
 foreach($source in @($optional|Where-Object Provider -eq 'Graph')){
  $script:ProbeSource=$source
  $script:ProbeScopes=@($source.Scopes[0])+@((Get-AuditProperty $source 'RequiredScopes' @())|ForEach-Object {$_})
  $script:ContextCalls=0;$script:ChangeAfter=1;$script:ChangeKind='Account'
  & $fakeGraph {$script:Calls=0;$script:Next=''}
  $r=Invoke-M365SecurityAudit -Mode Live -Include $source.Group -TenantId $tenant -ExpectedAccount $account -ConfirmTenantId $tenant -ConfirmOrganizationScope
  $calls=& $fakeGraph {$script:Calls}
  Check ('Optional Graph pre-request identity recheck '+$source.Id) ($calls -eq 0 -and $script:ContextCalls -eq 2 -and $r.Evidence[0].Status -ne 'Collected')
 }
}finally{
 Restore-Functions $saved
 Remove-Module $fakeGraph -Force
}

# The same command name exists in EXO and Purview. The wrong shell-precedence
# winner must neither block the verified EXO implementation nor supply its value.
$exoModule=New-Module -Name WorkbookQAExchange -ScriptBlock {
 $script:Calls=0
 function Get-AdminAuditLogConfig {[CmdletBinding()]param();$script:Calls++;[pscustomobject]@{Identity='QA-EXO';UnifiedAuditLogIngestionEnabled=$true}}
 Export-ModuleMember -Function Get-AdminAuditLogConfig
}
$purviewModule=New-Module -Name WorkbookQAPurview -ScriptBlock {
 $script:Calls=0
 function Get-AdminAuditLogConfig {[CmdletBinding()]param();$script:Calls++;[pscustomobject]@{Identity='QA-PURVIEW';UnifiedAuditLogIngestionEnabled=$false}}
 Export-ModuleMember -Function Get-AdminAuditLogConfig
}
Import-Module $exoModule -Force
Import-Module $purviewModule -Force
try{
 $auditSource=@($optional|Where-Object Id -eq 'exchange-unified-audit-config')[0]
 Check 'Both fake workload commands visible with Purview shell precedence' (@(Get-Command Get-AdminAuditLogConfig -All).Count -eq 2 -and (Get-Command Get-AdminAuditLogConfig).ModuleName -ceq 'WorkbookQAPurview')
 $r=Read-AuditCommandSource -Source $auditSource -Session @{Connection=@{ModuleName='WorkbookQAExchange'}}
 Check 'Verified EXO command selected despite Purview shadow' ($r.Status -eq 'Collected' -and $r.Count -eq 1 -and $r.Items[0].Identity -ceq 'QA-EXO' -and $r.Items[0].UnifiedAuditLogIngestionEnabled -ceq $true)
 Check 'Wrong workload command never invoked' ((& $exoModule {$script:Calls}) -eq 1 -and (& $purviewModule {$script:Calls}) -eq 0)
 $r=Read-AuditCommandSource -Source $auditSource -Session @{Connection=@{ModuleName='UnverifiedModule'}}
 Check 'Unknown command origin refuses without a fallback workload' ($r.Status -eq 'Unavailable' -and $r.RequestCount -eq 0 -and (& $purviewModule {$script:Calls}) -eq 0)
 $r=Read-AuditCommandSource -Source $auditSource -Session @{Connection=@{ModuleName='/unverified/path/WorkbookQAExchange'}}
 Check 'Full expected module path cannot match by basename alone' ($r.Status -eq 'Unavailable' -and $r.RequestCount -eq 0)
 $purviewConnection=@{State='Connected';IsEopSession=$true;TenantID=$tenant.ToString();ModulePrefix='';TokenStatus='Active';ModuleName='WorkbookQAPurview';UserPrincipalName=$account;CertificateAuthentication=$false;DelegatedOrganization=''}
 Check 'Purview-only connected session cannot satisfy Exchange identity gate' ((Test-AuditCommandIdentity @($purviewConnection) $tenant 'Exchange' $account).Status -eq 'NotConnected')
}finally{
 Remove-Module $purviewModule -Force
 Remove-Module $exoModule -Force
}

# Reports are local saved-evidence transformations. Raw identities/settings remain
# in source-tagged JSON/CSV, never PDF text, links, JavaScript or attachments.
# macOS /var temp paths pass through a system symlink, correctly refused by the
# exporter. Keep invented artifacts inside the checkout's existing test area.
$work=Join-Path (Split-Path $script:AuditRoot -Parent) ('test-output/workbook-security-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$evil=Copy-Result $extended
$org=@($evil.Evidence|Where-Object SourceId -eq 'exchange-organization')[0]
$org.Items[0].Identity='=WORKBOOK_QA_RAW_ID';$org.Items[0].AuditDisabled=$false
$org.Reason='WORKBOOK_QA_RAW_REASON'
$evil.Metadata.TenantId='WORKBOOK_QA_RAW_TENANT'
$org.Items[0]|Add-Member -NotePropertyName RawUrl -NotePropertyValue 'https://sensitive.invalid/WORKBOOK_QA_RAW_URL' -Force
$before=$evil|ConvertTo-Json -Depth 100
$bundle=Export-FlapjacksPostureBundle -Result $evil -OutputDirectory (Join-Path $work 'bundle')
Check 'Export never mutates supplied evidence' (($evil|ConvertTo-Json -Depth 100) -ceq $before)
Check 'Extended source count retained in bundle' ($bundle.Sources -eq $extendedPlan.Sources.Count)
Check 'All configured checks included in bundle' ($bundle.PostureChecks -eq $extendedChecks.Count)
Check 'Export manifest validates' (Test-M365AuditManifest $bundle.OutputDirectory).Valid
$savedPlan=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'collection-plan.json') -Raw|ConvertFrom-Json -Depth 100
Check 'Bundle collection plan preserves exact selected extended source IDs' ((($savedPlan.Sources.Id|Sort-Object)-join ',') -ceq (($extendedPlan.Sources.Id|Sort-Object)-join ','))
$json=Get-Content -LiteralPath (Join-Path $bundle.OutputDirectory 'evidence/exchange-organization.json') -Raw|ConvertFrom-Json -Depth 100
Check 'JSON preserves original raw source identity and Boolean false' ($json.Items[0].Identity -ceq '=WORKBOOK_QA_RAW_ID' -and $json.Items[0].AuditDisabled -is [bool] -and $json.Items[0].AuditDisabled -ceq $false)
$inventory=Import-Csv -LiteralPath (Join-Path $bundle.OutputDirectory 'inventory.csv')
Check 'CSV formula leading source identity neutralized' (@($inventory|Where-Object {$_.SourceId -eq 'exchange-organization' -and $_.ObjectId -ceq "'=WORKBOOK_QA_RAW_ID"}).Count -eq 1)
$pdf=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $bundle.OutputDirectory 'review.pdf')))
Check 'Redacted PDF excludes raw identity/tenant/reason/URL markers' ($pdf -notmatch 'WORKBOOK_QA_RAW_')
Check 'PDF contains no executable action, URL, form or attached raw evidence' ($pdf -notmatch '/(JavaScript|JS|Launch|URI|AcroForm|EmbeddedFile|OpenAction|AA)\b')
Check 'PDF identifies synthetic demonstration' ($pdf -match 'SYNTHETIC')
Check 'Existing bundle cannot be overwritten' (Rejects {Export-FlapjacksPostureBundle -Result $evil -OutputDirectory $bundle.OutputDirectory})
$bad=Copy-Result $extended;$bad.Evidence[0].SourceId='../outside'
Check 'Source traversal rejected before creating output' (Rejects {Export-FlapjacksPostureBundle -Result $bad -OutputDirectory (Join-Path $work 'invalid')})
Check 'Rejected source traversal creates no directory' (-not (Test-Path -LiteralPath (Join-Path $work 'invalid')))

# Menu authorization is deliberately different from the default AUDIT action.
# Runtime delegates throw if auth, session reads or providers are ever attempted.
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
foreach($wrongConfirmation in @('','AUDIT','workbook')){
 $rt=New-QARuntime @('W',$wrongConfirmation,'Q')
 $history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
 Check ('Workbook rejects nonexact confirmation '+$wrongConfirmation) ($history.Count -eq 0 -and $rt.State.Audits.Count -eq 0 -and $rt.State.ExternalCalls -eq 0)
 Check ('Workbook confirmation is explicit '+$wrongConfirmation) (@($rt.State.Prompts|Where-Object {$_ -like 'Type WORKBOOK*'}).Count -eq 1)
}
$rt=New-QARuntime @('W','WORKBOOK','Q')
$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
Check 'Exact WORKBOOK menu runs once with explicit Workbook flag' ($history.Count -eq 1 -and $rt.State.Audits.Count -eq 1 -and $rt.State.Audits[0].Workbook -eq $true)
Check 'Workbook menu uses no auth/provider/session or implicit files' ($rt.State.ExternalCalls -eq 0 -and -not $history[0].OutputPath)
Check 'Workbook menu explains additional scopes without requesting consent' (($rt.State.Text -join ' ') -match 'never requests or broadens permissions')
$rt=New-QARuntime @('A','AUDIT','Q')
$history=Invoke-M365Terminal -Mode Synthetic -Runtime $rt 6>$null
Check 'Default A does not pass Workbook flag or add sources' ($history.Count -eq 1 -and $history[0].SelectedCount -eq 46 -and -not $rt.State.Audits[0].ContainsKey('Workbook') -and $rt.State.ExternalCalls -eq 0)

$result=[pscustomobject]@{Passed=$true;Checks=$script:Assertions.Count;SyntheticOnly=$true;EvidenceRoot=$work;NotExercised=@('Real tenant calls','Sign-in/consent','Live Microsoft SDK/RBAC/licensing','Real Teams/SharePoint session verification','Windows acceptance');Assertions=$script:Assertions.ToArray()}
if($ResultsPath){$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultsPath}
$result|Select-Object Passed,Checks,SyntheticOnly,EvidenceRoot
