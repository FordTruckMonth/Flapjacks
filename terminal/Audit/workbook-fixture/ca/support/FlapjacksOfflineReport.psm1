#requires -Version 7.4
# Exact frozen static-plan and renderer functions only. No collector, login or real-input host.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Test-AuditProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function Get-AuditProperty($Object, [string]$Name, $Default=$null) {
    if (Test-AuditProperty $Object $Name) { return ,($Object.$Name) }
    return ,$Default
}

function Get-AuditSourceCatalog {
    $sources = [System.Collections.Generic.List[object]]::new()
    function Add-GraphSource($Id, $Group, $Path, $Scopes, $Doc, $Shape = 'Collection', $Notes = '') {
        $sources.Add([pscustomobject]@{ Id=$Id; Group=$Group; Provider='Graph'; Target=$Path;
            Scopes=@($Scopes); Shape=$Shape; Fields=@(); Documentation="https://learn.microsoft.com/en-us/graph/api/$($Doc)?view=graph-rest-1.0"; Notes=$Notes })
    }
    function Add-CommandSource($Id, $Group, $Command, $Fields, $Notes='', [string[]]$OptionalFields=@()) {
        $sources.Add([pscustomobject]@{ Id=$Id; Group=$Group; Provider=$Group; Target=$Command;
            Scopes=@(); Shape='Collection'; Fields=@($Fields -split ','); OptionalFields=$OptionalFields; Documentation="https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/$($Command.ToLowerInvariant())?view=exchange-ps"; Notes=$Notes })
    }
    Add-GraphSource 'conditional-access' 'Core' '/identity/conditionalAccess/policies' 'Policy.Read.All' 'conditionalaccessroot-list-policies' -Notes 'Configuration only. Exclusions, report-only state and policy interactions require review. No effective access evaluation.'
    Add-GraphSource 'named-locations' 'Core' '/identity/conditionalAccess/namedLocations' 'Policy.Read.All' 'conditionalaccessroot-list-namedlocations'
    Add-GraphSource 'security-defaults' 'Core' '/policies/identitySecurityDefaultsEnforcementPolicy' 'Policy.Read.All' 'identitysecuritydefaultsenforcementpolicy-get' 'Singleton'
    Add-GraphSource 'authorization-policy' 'Core' '/policies/authorizationPolicy' 'Policy.Read.All' 'authorizationpolicy-get' 'Singleton'
    Add-GraphSource 'admin-consent-policy' 'Core' '/policies/adminConsentRequestPolicy' 'Policy.Read.All' 'adminconsentrequestpolicy-get' 'Singleton'
    Add-GraphSource 'cross-tenant-default' 'Core' '/policies/crossTenantAccessPolicy/default' 'Policy.Read.All' 'crosstenantaccesspolicyconfigurationdefault-get' 'Singleton' 'Basic access settings. Identity synchronization settings are not expanded.'
    Add-GraphSource 'cross-tenant-partners' 'Core' '/policies/crossTenantAccessPolicy/partners' 'Policy.Read.All' 'crosstenantaccesspolicy-list-partners' -Notes 'Basic access settings. Identity synchronization settings are not expanded.'
    Add-GraphSource 'authentication-methods-policy' 'Authentication' '/policies/authenticationMethodsPolicy' @('Policy.Read.AuthenticationMethod','Policy.Read.All') 'authenticationmethodspolicy-get' 'Singleton'
    Add-GraphSource 'authentication-strengths' 'Authentication' '/policies/authenticationStrengthPolicies' @('Policy.Read.AuthenticationMethod','Policy.Read.All') 'authenticationstrengthroot-list-policies'
    Add-GraphSource 'permission-grant-policies' 'Consent' '/policies/permissionGrantPolicies' 'Policy.Read.PermissionGrant' 'permissiongrantpolicy-list' -Notes 'Consent policy rules, not existing OAuth consent grants or app credentials.'
    Add-GraphSource 'role-definitions' 'Administration' '/roleManagement/directory/roleDefinitions' 'RoleManagement.Read.Directory' 'rbacapplication-list-roledefinitions'
    Add-GraphSource 'role-assignments' 'Administration' '/roleManagement/directory/roleAssignments' 'RoleManagement.Read.Directory' 'rbacapplication-list-roleassignments' -Notes 'Principal IDs only; no user/group resolution or transitive membership. Does not prove effective privileges.'
    Add-GraphSource 'role-eligibility-instances' 'Administration' '/roleManagement/directory/roleEligibilityScheduleInstances' @('RoleEligibilitySchedule.Read.Directory','RoleManagement.Read.Directory') 'rbacapplication-list-roleeligibilityscheduleinstances' -Notes 'PIM availability/license dependent; principal IDs only. No role activation.'
    Add-GraphSource 'tenant-domains' 'TenantInventory' '/domains' 'Domain.Read.All' 'domain-list'
    Add-GraphSource 'tenant-subscriptions' 'TenantInventory' '/subscribedSkus' 'LicenseAssignment.Read.All' 'subscribedsku-list' -Notes 'Tenant SKU inventory is not evidence that users are licensed for a policy feature.'
    Add-GraphSource 'intune-compliance-policy-metadata' 'Intune' '/deviceManagement/deviceCompliancePolicies?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version' 'DeviceManagementConfiguration.Read.All' 'intune-deviceconfig-devicecompliancepolicy-list' -Notes 'METADATA ONLY: not compliance settings, assignments or outcomes. Active Intune tenant license required.'
    Add-GraphSource 'intune-configuration-policy-metadata' 'Intune' '/deviceManagement/deviceConfigurations?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version' 'DeviceManagementConfiguration.Read.All' 'intune-deviceconfig-deviceconfiguration-list' -Notes 'METADATA ONLY: excludes secret-bearing settings, settings catalog, security baselines, assignments and devices. Active Intune tenant license required.'
    Add-CommandSource 'exchange-organization' 'Exchange' 'Get-OrganizationConfig' 'Identity,OAuth2ClientProfileEnabled,AuditDisabled,DefaultAuthenticationPolicy,AutoExpandingArchiveEnabled,RejectDirectSend' 'Selected organization settings only; no mailbox collection.'
    Add-CommandSource 'exchange-transport' 'Exchange' 'Get-TransportConfig' 'Identity,SmtpClientAuthenticationDisabled,ExternalPostmasterAddress,InternalSMTPServers' 'Selected transport settings only.'
    Add-CommandSource 'exchange-authentication-policies' 'Exchange' 'Get-AuthenticationPolicy' 'Identity,Name,AllowBasicAuthActiveSync,AllowBasicAuthAutodiscover,AllowBasicAuthImap,AllowBasicAuthMapi,AllowBasicAuthOfflineAddressBook,AllowBasicAuthOutlookService,AllowBasicAuthPop,AllowBasicAuthPowershell,AllowBasicAuthReportingWebServices,AllowBasicAuthRest,AllowBasicAuthRpc,AllowBasicAuthSmtp,AllowBasicAuthWebServices' 'No per-user assignments. Service-wide protocol retirement can override stored values.'
    Add-CommandSource 'exchange-accepted-domains' 'Exchange' 'Get-AcceptedDomain' 'Identity,Name,DomainName,DomainType,Default'
    Add-CommandSource 'exchange-remote-domains' 'Exchange' 'Get-RemoteDomain' 'Identity,Name,DomainName,AutoForwardEnabled,AutoReplyEnabled,AllowedOOFType,IsInternal'
    Add-CommandSource 'exchange-dkim' 'Exchange' 'Get-DkimSigningConfig' 'Identity,Name,Domain,Enabled,Status,Selector1CNAME,Selector2CNAME' 'Configuration only; no DNS lookups, mail delivery or signature test.'
    Add-CommandSource 'exchange-inbound-connectors' 'Exchange' 'Get-InboundConnector' 'Identity,Name,Enabled,ConnectorType,RequireTls,RestrictDomainsToCertificate,RestrictDomainsToIPAddresses,SenderDomains,SenderIPAddresses,TlsSenderCertificateName,TreatMessagesAsInternal'
    Add-CommandSource 'exchange-outbound-connectors' 'Exchange' 'Get-OutboundConnector' 'Identity,Name,Enabled,ConnectorType,RecipientDomains,SmartHosts,UseMXRecord,TlsSettings,TlsDomain,RouteAllMessagesViaOnPremises,IsTransportRuleScoped'
    Add-CommandSource 'exchange-transport-rules' 'Exchange' 'Get-TransportRule' 'Identity,Name,State,Mode,Priority,Description,StopRuleProcessing,Comments' 'Human-readable description, not a full executable rule export. No message content.'
    Add-CommandSource 'exchange-antispam-policies' 'Exchange' 'Get-HostedContentFilterPolicy' 'Identity,Name,IsDefault,SpamAction,HighConfidenceSpamAction,PhishSpamAction,HighConfidencePhishAction,BulkSpamAction,BulkThreshold,InlineSafetyTipsEnabled,AllowedSenders,AllowedSenderDomains,BlockedSenders,BlockedSenderDomains,EnableLanguageBlockList,LanguageBlockList,EnableRegionBlockList,RegionBlockList' -OptionalFields @('QuarantineRetentionPeriod','SpamZapEnabled','PhishZapEnabled')
    Add-CommandSource 'exchange-antispam-rules' 'Exchange' 'Get-HostedContentFilterRule' 'Identity,Name,State,Priority,HostedContentFilterPolicy,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-outbound-spam-policies' 'Exchange' 'Get-HostedOutboundSpamFilterPolicy' 'Identity,Name,IsDefault,AutoForwardingMode,ActionWhenThresholdReached,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,NotifyOutboundSpam,NotifyOutboundSpamRecipients'
    Add-CommandSource 'exchange-outbound-spam-rules' 'Exchange' 'Get-HostedOutboundSpamFilterRule' 'Identity,Name,State,Priority,HostedOutboundSpamFilterPolicy,From,FromMemberOf,SenderDomainIs,ExceptIfFrom,ExceptIfFromMemberOf,ExceptIfSenderDomainIs'
    Add-CommandSource 'exchange-antiphish-policies' 'Exchange' 'Get-AntiPhishPolicy' 'Identity,Name,IsDefault,Enabled,EnableSpoofIntelligence,EnableMailboxIntelligence,EnableMailboxIntelligenceProtection,EnableTargetedUserProtection,EnableTargetedDomainsProtection,EnableOrganizationDomainsProtection,EnableFirstContactSafetyTips,EnableSimilarUsersSafetyTips,EnableSimilarDomainsSafetyTips,EnableUnusualCharactersSafetyTips,TargetedUsersToProtect,TargetedDomainsToProtect,ExcludedSenders,ExcludedDomains,PhishThresholdLevel,AuthenticationFailAction' 'Impersonation features depend on Defender for Office 365 licensing.' -OptionalFields @('TargetedUserProtectionAction','TargetedDomainProtectionAction','MailboxIntelligenceProtectionAction')
    Add-CommandSource 'exchange-antiphish-rules' 'Exchange' 'Get-AntiPhishRule' 'Identity,Name,State,Priority,AntiPhishPolicy,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-malware-policies' 'Exchange' 'Get-MalwareFilterPolicy' 'Identity,Name,IsDefault,EnableFileFilter,FileTypes,FileTypeAction,ZapEnabled,EnableInternalSenderAdminNotifications,EnableExternalSenderAdminNotifications'
    Add-CommandSource 'exchange-malware-rules' 'Exchange' 'Get-MalwareFilterRule' 'Identity,Name,State,Priority,MalwareFilterPolicy,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-safe-links-policies' 'Exchange' 'Get-SafeLinksPolicy' 'Identity,Name,IsBuiltInProtection,EnableSafeLinksForEmail,EnableSafeLinksForTeams,EnableSafeLinksForOffice,ScanUrls,TrackClicks,AllowClickThrough,DoNotRewriteUrls,DeliverMessageAfterScan,DisableUrlRewrite,EnableForInternalSenders' 'Defender for Office 365 availability/license dependent.'
    Add-CommandSource 'exchange-safe-links-rules' 'Exchange' 'Get-SafeLinksRule' 'Identity,Name,State,Priority,SafeLinksPolicy,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-safe-attachments-policies' 'Exchange' 'Get-SafeAttachmentPolicy' 'Identity,Name,IsBuiltInProtection,Enable,Action,Redirect,RedirectAddress' 'Defender for Office 365 availability/license dependent.'
    Add-CommandSource 'exchange-safe-attachments-rules' 'Exchange' 'Get-SafeAttachmentRule' 'Identity,Name,State,Priority,SafeAttachmentPolicy,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-atp-organization' 'Exchange' 'Get-AtpPolicyForO365' 'Identity,EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen' 'Selected Defender settings only; Safe Documents requires its own eligible licensing.'
    Add-CommandSource 'exchange-preset-eop-rules' 'Exchange' 'Get-EOPProtectionPolicyRule' 'Identity,Name,State,Priority,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs' 'Preset policy assignment exceptions; collection does not resolve precedence.'
    Add-CommandSource 'exchange-preset-atp-rules' 'Exchange' 'Get-ATPProtectionPolicyRule' 'Identity,Name,State,Priority,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs'
    Add-CommandSource 'exchange-built-in-protection-rule' 'Exchange' 'Get-ATPBuiltInProtectionRule' 'Identity,Name,State,Priority,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs' 'Built-in preset exclusions; no effective recipient evaluation.'
    Add-CommandSource 'purview-dlp-policies' 'Purview' 'Get-DlpCompliancePolicy' 'Identity,Name,Enabled,Mode,Workload,Priority,ExchangeLocation,ExchangeLocationException,SharePointLocation,SharePointLocationException,OneDriveLocation,OneDriveLocationException,TeamsLocation,TeamsLocationException,DistributionStatus' 'Selected metadata/scope with DistributionDetail; distribution output is not proof of enforcement. Excludes adaptive scopes and complete workload settings.'
    Add-CommandSource 'purview-dlp-rule-metadata' 'Purview' 'Get-DlpComplianceRule' 'Identity,Name,Disabled,Priority,ParentPolicyName,Comment' 'RULE METADATA ONLY: conditions and actions are not collected.'
    Add-CommandSource 'purview-retention-policies' 'Purview' 'Get-RetentionCompliancePolicy' 'Identity,Name,Enabled,Mode,Workload,ExchangeLocation,ExchangeLocationException,SharePointLocation,SharePointLocationException,OneDriveLocation,OneDriveLocationException,TeamsChannelLocation,TeamsChatLocation,DistributionStatus' 'Selected policy metadata/scope with DistributionDetail; Workload is not actual targeting. Excludes adaptive scopes, labels and effective retention.'
    Add-CommandSource 'purview-retention-rules' 'Purview' 'Get-RetentionComplianceRule' 'Identity,Name,Disabled,Policy,RetentionDuration,RetentionComplianceAction,ExpirationDateOption,ContentMatchQuery' 'Selected rule settings only. ContentMatchQuery is configuration, not matched content.'
    return $sources.ToArray()
}

function Get-FlapjacksWorkbookIdentitySources {
    [pscustomobject]@{
        Id='workbook-identity-registration'; Group='WorkbookIdentity'; Provider='Graph'
        Target='/reports/authenticationMethods/userRegistrationDetails?$select=id,isAdmin,isMfaRegistered,isSsprEnabled,isSsprRegistered,isSsprCapable,lastUpdatedDateTime'
        Scopes=@('AuditLog.Read.All'); RequiredScopes=@(); Shape='Collection'
        Fields=@('id','isAdmin','isMfaRegistered','isSsprEnabled','isSsprRegistered','isSsprCapable','lastUpdatedDateTime')
        Documentation='https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
        Notes='Optional sensitive identity snapshot. No names, UPNs, method details or activity events selected. Disabled users are not supported by this report. Reports Reader or another documented supported role and eligible licensing are required. The v1.0 SDK documents -Property/-Select; REST prose explicitly lists only $filter. Projection must be retained on every page and locally; never retry without $select. Service validation is still required. Registration does not prove effective MFA enforcement; report refresh can lag.'
    }
    [pscustomobject]@{
        Id='workbook-identity-users'; Group='WorkbookIdentity'; Provider='Graph'
        Target='/users?$select=id,accountEnabled,signInActivity'
        Scopes=@('User.Read.All','Directory.Read.All'); RequiredScopes=@('AuditLog.Read.All'); Shape='Collection'
        Fields=@('id','accountEnabled','signInActivity')
        Documentation='https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0'
        Notes='Optional identity denominator and latest-success snapshot only, not sign-in events. Requires one listed read scope AND AuditLog.Read.All, an eligible Entra P1/P2 license and a supported role. Locally retain only id, accountEnabled and signInActivity.lastSuccessfulSignInDateTime; discard all request IDs and attempt timestamps. Null or absent success time is unknown, not never-used or dormant. Last-success history starts December 2023 and is not backfilled.'
    }
}

function Get-FlapjacksWorkbookExchangeSources {
    @(
        [pscustomobject]@{
            Id='exchange-unified-audit-config'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-AdminAuditLogConfig'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','UnifiedAuditLogIngestionEnabled')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-adminauditlogconfig?view=exchange-ps'
            Notes='Exchange Online REST session only. Security & Compliance PowerShell returns a misleading false value for this property. Configuration only; no audit events, searches, retention validation or ingestion test.'
        },
        [pscustomobject]@{
            Id='exchange-external-sender-tagging'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-ExternalInOutlook'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','Enabled','AllowList')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook?view=exchange-ps'
            Notes='Native external-sender identification and exceptions in supported Outlook clients only. Not transport-rule banner coverage, filtering, or proof of phishing protection.'
        },
        [pscustomobject]@{
            Id='exchange-connection-filter-policies'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-HostedConnectionFilterPolicy'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','Name','IPAllowList','IPBlockList','EnableSafeList')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedconnectionfilterpolicy?view=exchange-ps'
            Notes='Selected connection-filter settings only. IP lists may disclose infrastructure. Allow-list and safe-list configuration does not establish effective filtering or message outcomes.'
        }
    )
}

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

function Get-FlapjacksWorkbookSources {
    Get-FlapjacksWorkbookIdentitySources
    Get-FlapjacksWorkbookExchangeSources
    Get-FlapjacksWorkbookCollaborationSources
}

function Get-M365AuditPlan {
    [CmdletBinding()]
    param([ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')][string[]]$Include=@())
    $catalog=@(Get-AuditSourceCatalog)
    if (@($Include | Where-Object { $_ -like 'Workbook*' }).Count) { $catalog+=@(Get-FlapjacksWorkbookSources) }
    $selected=@($catalog | Where-Object { $_.Group -eq 'Core' -or $_.Group -in $Include })
    # Each source's first scope is the documented least-privileged option. Existing Policy.Read.All
    # covers Authentication as well, so do not request an unnecessary extra scope in the combined plan.
    $scopes=@($selected | Where-Object Provider -eq 'Graph' | ForEach-Object { $_.Scopes[0]; (Get-AuditProperty $_ 'RequiredScopes' @()) | Where-Object { $_ } } | Sort-Object -Unique)
    if ('Policy.Read.All' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'Policy.Read.AuthenticationMethod' }) }
    if ('RoleManagement.Read.Directory' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'RoleEligibilitySchedule.Read.Directory' }) }
    [pscustomobject]@{ SchemaVersion='1.1'; ToolVersion='0.2.0-terminal'; ReadOnly=$true; Cloud='Global';
        SelectedGroups=@('Core')+@($Include | Sort-Object -Unique); GraphReadPermissions=$scopes;
        ConnectionPolicy='Use separately authorized existing sessions only. No auth, grants, module installs or role activation performed.';
        Sources=$selected }
}

function Get-M365OrganizationAuditPlan {
    [CmdletBinding()]
    param([switch]$Workbook)
    $include=@('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview')
    if($Workbook){$include+=@('WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')}
    $plan=Get-M365AuditPlan -Include $include
    $plan | Add-Member -NotePropertyName OrganizationScope -NotePropertyValue ('Organization-wide current settings and selected posture evidence across '+$plan.Sources.Count+' sources; not effective policy evaluation.')
    $plan | Add-Member -NotePropertyName SensitiveReportNotice -NotePropertyValue 'Reports may include tenant policy targeting identities, addresses and infrastructure. Keep on approved local storage.'
    $word=if($Workbook){'WORKBOOK'}else{'AUDIT'}
    $plan | Add-Member -NotePropertyName ConfirmationRequired -NotePropertyValue ('Verify signed-in delegated account and tenant binding, and explicitly authorize organization-wide configuration collection. Interactive Flapjacks uses one '+$word+' confirmation; direct API callers must supply matching confirmed tenant ID. No tenant writes or log collection.')
    return $plan
}

function ConvertTo-AuditCsvValue($Value) {
    $s=if ($null -eq $Value) { '' } elseif ($Value -is [string] -or $Value -is [ValueType]) { [string]$Value } else { ConvertTo-Json -InputObject $Value -Depth 100 -Compress }
    if ($s -match '^[\s\p{Cf}]*[=+@\-]' -or $s -match '^[\t\r\n]') { return "'"+$s }
    return $s
}

function Write-AuditCsv([string]$Path,$Rows,[string[]]$Columns) {
    $safe=@(foreach ($row in $Rows) {
        $copy=[ordered]@{}; foreach ($col in $Columns) { $copy[$col]=ConvertTo-AuditCsvValue (Get-AuditProperty $row $col) }; [pscustomobject]$copy
    })
    if ($safe.Count -eq 0) { [IO.File]::WriteAllText($Path,('"'+($Columns -join '","')+'"'+[Environment]::NewLine),[Text.UTF8Encoding]::new($true)) }
    else { $safe | Export-Csv -LiteralPath $Path -Encoding utf8BOM }
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

Export-ModuleMember -Function Get-M365OrganizationAuditPlan
