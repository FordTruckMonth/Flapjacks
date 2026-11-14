# Exact source catalog

Contracts checked against Microsoft Learn on 2026-11-14. All Graph requests are GET /v1.0 in the global cloud. Optional groups are never collected unless selected.

Each scope is an alternative supported read permission; the first is least privileged. Combined plans remove redundant scopes. Workload cmdlets require approved Exchange/Purview RBAC, not Graph permissions.

## conditional-access

- Group: Core; provider: Graph.
- Request: `/identity/conditionalAccess/policies`.
- Read permission alternatives: `Policy.Read.All`.
- Limit: Configuration only. Exclusions, report-only state and policy interactions require review. No effective access evaluation.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0)

## named-locations

- Group: Core; provider: Graph.
- Request: `/identity/conditionalAccess/namedLocations`.
- Read permission alternatives: `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations?view=graph-rest-1.0)

## security-defaults

- Group: Core; provider: Graph.
- Request: `/policies/identitySecurityDefaultsEnforcementPolicy`.
- Read permission alternatives: `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0)

## authorization-policy

- Group: Core; provider: Graph.
- Request: `/policies/authorizationPolicy`.
- Read permission alternatives: `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0)

## admin-consent-policy

- Group: Core; provider: Graph.
- Request: `/policies/adminConsentRequestPolicy`.
- Read permission alternatives: `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/adminconsentrequestpolicy-get?view=graph-rest-1.0)

## cross-tenant-default

- Group: Core; provider: Graph.
- Request: `/policies/crossTenantAccessPolicy/default`.
- Read permission alternatives: `Policy.Read.All`.
- Limit: Basic access settings. Identity synchronization settings are not expanded.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicyconfigurationdefault-get?view=graph-rest-1.0)

## cross-tenant-partners

- Group: Core; provider: Graph.
- Request: `/policies/crossTenantAccessPolicy/partners`.
- Read permission alternatives: `Policy.Read.All`.
- Limit: Basic access settings. Identity synchronization settings are not expanded.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-list-partners?view=graph-rest-1.0)

## authentication-methods-policy

- Group: Authentication; provider: Graph.
- Request: `/policies/authenticationMethodsPolicy`.
- Read permission alternatives: `Policy.Read.AuthenticationMethod`, `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0)

## authentication-strengths

- Group: Authentication; provider: Graph.
- Request: `/policies/authenticationStrengthPolicies`.
- Read permission alternatives: `Policy.Read.AuthenticationMethod`, `Policy.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies?view=graph-rest-1.0)

## permission-grant-policies

- Group: Consent; provider: Graph.
- Request: `/policies/permissionGrantPolicies`.
- Read permission alternatives: `Policy.Read.PermissionGrant`.
- Limit: Consent policy rules, not existing OAuth consent grants or app credentials.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/permissiongrantpolicy-list?view=graph-rest-1.0)

## role-definitions

- Group: Administration; provider: Graph.
- Request: `/roleManagement/directory/roleDefinitions`.
- Read permission alternatives: `RoleManagement.Read.Directory`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roledefinitions?view=graph-rest-1.0)

## role-assignments

- Group: Administration; provider: Graph.
- Request: `/roleManagement/directory/roleAssignments`.
- Read permission alternatives: `RoleManagement.Read.Directory`.
- Limit: Principal IDs only; no user/group resolution or transitive membership. Does not prove effective privileges.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)

## role-eligibility-instances

- Group: Administration; provider: Graph.
- Request: `/roleManagement/directory/roleEligibilityScheduleInstances`.
- Read permission alternatives: `RoleEligibilitySchedule.Read.Directory`, `RoleManagement.Read.Directory`.
- Limit: PIM availability/license dependent; principal IDs only. No role activation.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances?view=graph-rest-1.0)

## tenant-domains

- Group: TenantInventory; provider: Graph.
- Request: `/domains`.
- Read permission alternatives: `Domain.Read.All`.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/domain-list?view=graph-rest-1.0)

## tenant-subscriptions

- Group: TenantInventory; provider: Graph.
- Request: `/subscribedSkus`.
- Read permission alternatives: `LicenseAssignment.Read.All`.
- Limit: Tenant SKU inventory is not evidence that users are licensed for a policy feature.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)

## intune-compliance-policy-metadata

- Group: Intune; provider: Graph.
- Request: `/deviceManagement/deviceCompliancePolicies?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version`.
- Read permission alternatives: `DeviceManagementConfiguration.Read.All`.
- Limit: METADATA ONLY: not compliance settings, assignments or outcomes. Active Intune tenant license required.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0)

## intune-configuration-policy-metadata

- Group: Intune; provider: Graph.
- Request: `/deviceManagement/deviceConfigurations?$select=id,displayName,description,createdDateTime,lastModifiedDateTime,version`.
- Read permission alternatives: `DeviceManagementConfiguration.Read.All`.
- Limit: METADATA ONLY: excludes secret-bearing settings, settings catalog, security baselines, assignments and devices. Active Intune tenant license required.
- [Microsoft contract](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfiguration-list?view=graph-rest-1.0)

## exchange-organization

- Group: Exchange; provider: Exchange.
- Request: `Get-OrganizationConfig`.
- Selected fields: `Identity`, `OAuth2ClientProfileEnabled`, `AuditDisabled`, `DefaultAuthenticationPolicy`, `AutoExpandingArchiveEnabled`.
- Limit: Selected organization settings only; no mailbox collection.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-organizationconfig?view=exchange-ps)

## exchange-transport

- Group: Exchange; provider: Exchange.
- Request: `Get-TransportConfig`.
- Selected fields: `Identity`, `SmtpClientAuthenticationDisabled`, `ExternalPostmasterAddress`, `RejectDirectSend`, `InternalSMTPServers`.
- Limit: Selected transport settings only.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-transportconfig?view=exchange-ps)

## exchange-authentication-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-AuthenticationPolicy`.
- Selected fields: `Identity`, `Name`, `AllowBasicAuthActiveSync`, `AllowBasicAuthAutodiscover`, `AllowBasicAuthImap`, `AllowBasicAuthMapi`, `AllowBasicAuthOfflineAddressBook`, `AllowBasicAuthOutlookService`, `AllowBasicAuthPop`, `AllowBasicAuthPowershell`, `AllowBasicAuthReportingWebServices`, `AllowBasicAuthRest`, `AllowBasicAuthRpc`, `AllowBasicAuthSmtp`, `AllowBasicAuthWebServices`.
- Limit: No per-user assignments. Service-wide protocol retirement can override stored values.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-authenticationpolicy?view=exchange-ps)

## exchange-accepted-domains

- Group: Exchange; provider: Exchange.
- Request: `Get-AcceptedDomain`.
- Selected fields: `Identity`, `Name`, `DomainName`, `DomainType`, `Default`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-accepteddomain?view=exchange-ps)

## exchange-remote-domains

- Group: Exchange; provider: Exchange.
- Request: `Get-RemoteDomain`.
- Selected fields: `Identity`, `Name`, `DomainName`, `AutoForwardEnabled`, `AutoReplyEnabled`, `AllowedOOFType`, `IsInternal`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-remotedomain?view=exchange-ps)

## exchange-dkim

- Group: Exchange; provider: Exchange.
- Request: `Get-DkimSigningConfig`.
- Selected fields: `Identity`, `Name`, `Domain`, `Enabled`, `Status`, `Selector1CNAME`, `Selector2CNAME`.
- Limit: Configuration only; no DNS lookups, mail delivery or signature test.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dkimsigningconfig?view=exchange-ps)

## exchange-inbound-connectors

- Group: Exchange; provider: Exchange.
- Request: `Get-InboundConnector`.
- Selected fields: `Identity`, `Name`, `Enabled`, `ConnectorType`, `RequireTls`, `RestrictDomainsToCertificate`, `RestrictDomainsToIPAddresses`, `SenderDomains`, `SenderIPAddresses`, `TlsSenderCertificateName`, `TreatMessagesAsInternal`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector?view=exchange-ps)

## exchange-outbound-connectors

- Group: Exchange; provider: Exchange.
- Request: `Get-OutboundConnector`.
- Selected fields: `Identity`, `Name`, `Enabled`, `ConnectorType`, `RecipientDomains`, `SmartHosts`, `UseMXRecord`, `TlsSettings`, `TlsDomain`, `RouteAllMessagesViaOnPremises`, `IsTransportRuleScoped`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-outboundconnector?view=exchange-ps)

## exchange-transport-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-TransportRule`.
- Selected fields: `Identity`, `Name`, `State`, `Mode`, `Priority`, `Description`, `StopRuleProcessing`, `Comments`.
- Limit: Human-readable description, not a full executable rule export. No message content.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-transportrule?view=exchange-ps)

## exchange-antispam-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-HostedContentFilterPolicy`.
- Selected fields: `Identity`, `Name`, `IsDefault`, `SpamAction`, `HighConfidenceSpamAction`, `PhishSpamAction`, `HighConfidencePhishAction`, `BulkSpamAction`, `BulkThreshold`, `InlineSafetyTipsEnabled`, `AllowedSenders`, `AllowedSenderDomains`, `BlockedSenders`, `BlockedSenderDomains`, `EnableLanguageBlockList`, `LanguageBlockList`, `EnableRegionBlockList`, `RegionBlockList`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedcontentfilterpolicy?view=exchange-ps)

## exchange-antispam-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-HostedContentFilterRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `HostedContentFilterPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedcontentfilterrule?view=exchange-ps)

## exchange-outbound-spam-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-HostedOutboundSpamFilterPolicy`.
- Selected fields: `Identity`, `Name`, `IsDefault`, `AutoForwardingMode`, `ActionWhenThresholdReached`, `RecipientLimitExternalPerHour`, `RecipientLimitInternalPerHour`, `RecipientLimitPerDay`, `NotifyOutboundSpam`, `NotifyOutboundSpamRecipients`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedoutboundspamfilterpolicy?view=exchange-ps)

## exchange-outbound-spam-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-HostedOutboundSpamFilterRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `HostedOutboundSpamFilterPolicy`, `From`, `FromMemberOf`, `SenderDomainIs`, `ExceptIfFrom`, `ExceptIfFromMemberOf`, `ExceptIfSenderDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedoutboundspamfilterrule?view=exchange-ps)

## exchange-antiphish-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-AntiPhishPolicy`.
- Selected fields: `Identity`, `Name`, `IsDefault`, `Enabled`, `EnableSpoofIntelligence`, `EnableMailboxIntelligence`, `EnableMailboxIntelligenceProtection`, `EnableTargetedUserProtection`, `EnableTargetedDomainsProtection`, `EnableOrganizationDomainsProtection`, `EnableFirstContactSafetyTips`, `EnableSimilarUsersSafetyTips`, `EnableSimilarDomainsSafetyTips`, `EnableUnusualCharactersSafetyTips`, `TargetedUsersToProtect`, `TargetedDomainsToProtect`, `ExcludedSenders`, `ExcludedDomains`, `PhishThresholdLevel`, `AuthenticationFailAction`.
- Limit: Impersonation features depend on Defender for Office 365 licensing.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-antiphishpolicy?view=exchange-ps)

## exchange-antiphish-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-AntiPhishRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `AntiPhishPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-antiphishrule?view=exchange-ps)

## exchange-malware-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-MalwareFilterPolicy`.
- Selected fields: `Identity`, `Name`, `IsDefault`, `EnableFileFilter`, `FileTypes`, `FileTypeAction`, `ZapEnabled`, `EnableInternalSenderAdminNotifications`, `EnableExternalSenderAdminNotifications`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-malwarefilterpolicy?view=exchange-ps)

## exchange-malware-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-MalwareFilterRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `MalwareFilterPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-malwarefilterrule?view=exchange-ps)

## exchange-safe-links-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-SafeLinksPolicy`.
- Selected fields: `Identity`, `Name`, `IsBuiltInProtection`, `EnableSafeLinksForEmail`, `EnableSafeLinksForTeams`, `EnableSafeLinksForOffice`, `ScanUrls`, `TrackClicks`, `AllowClickThrough`, `DoNotRewriteUrls`, `DeliverMessageAfterScan`, `DisableUrlRewrite`, `EnableForInternalSenders`.
- Limit: Defender for Office 365 availability/license dependent.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinkspolicy?view=exchange-ps)

## exchange-safe-links-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-SafeLinksRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `SafeLinksPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safelinksrule?view=exchange-ps)

## exchange-safe-attachments-policies

- Group: Exchange; provider: Exchange.
- Request: `Get-SafeAttachmentPolicy`.
- Selected fields: `Identity`, `Name`, `IsBuiltInProtection`, `Enable`, `Action`, `Redirect`, `RedirectAddress`.
- Limit: Defender for Office 365 availability/license dependent.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safeattachmentpolicy?view=exchange-ps)

## exchange-safe-attachments-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-SafeAttachmentRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `SafeAttachmentPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-safeattachmentrule?view=exchange-ps)

## exchange-atp-organization

- Group: Exchange; provider: Exchange.
- Request: `Get-AtpPolicyForO365`.
- Selected fields: `Identity`, `EnableATPForSPOTeamsODB`, `EnableSafeDocs`, `AllowSafeDocsOpen`.
- Limit: Selected Defender settings only; Safe Documents requires its own eligible licensing.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-atppolicyforo365?view=exchange-ps)

## exchange-preset-eop-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-EOPProtectionPolicyRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- Limit: Preset policy assignment exceptions; collection does not resolve precedence.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-eopprotectionpolicyrule?view=exchange-ps)

## exchange-preset-atp-rules

- Group: Exchange; provider: Exchange.
- Request: `Get-ATPProtectionPolicyRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-atpprotectionpolicyrule?view=exchange-ps)

## exchange-built-in-protection-rule

- Group: Exchange; provider: Exchange.
- Request: `Get-ATPBuiltInProtectionRule`.
- Selected fields: `Identity`, `Name`, `State`, `Priority`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs`.
- Limit: Built-in preset exclusions; no effective recipient evaluation.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-atpbuiltinprotectionrule?view=exchange-ps)

## purview-dlp-policies

- Group: Purview; provider: Purview.
- Request: `Get-DlpCompliancePolicy`.
- Selected fields: `Identity`, `Name`, `Enabled`, `Mode`, `Workload`, `Priority`, `ExchangeLocation`, `ExchangeLocationException`, `SharePointLocation`, `SharePointLocationException`, `OneDriveLocation`, `OneDriveLocationException`, `TeamsLocation`, `TeamsLocationException`, `DistributionStatus`.
- Limit: Selected metadata/scope with DistributionDetail; distribution output is not proof of enforcement. Excludes adaptive scopes and complete workload settings.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancepolicy?view=exchange-ps)

## purview-dlp-rule-metadata

- Group: Purview; provider: Purview.
- Request: `Get-DlpComplianceRule`.
- Selected fields: `Identity`, `Name`, `Disabled`, `Priority`, `ParentPolicyName`, `Comment`.
- Limit: RULE METADATA ONLY: conditions and actions are not collected.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancerule?view=exchange-ps)

## purview-retention-policies

- Group: Purview; provider: Purview.
- Request: `Get-RetentionCompliancePolicy`.
- Selected fields: `Identity`, `Name`, `Enabled`, `Mode`, `Workload`, `ExchangeLocation`, `ExchangeLocationException`, `SharePointLocation`, `SharePointLocationException`, `OneDriveLocation`, `OneDriveLocationException`, `TeamsChannelLocation`, `TeamsChatLocation`, `DistributionStatus`.
- Limit: Selected policy metadata/scope with DistributionDetail; Workload is not actual targeting. Excludes adaptive scopes, labels and effective retention.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-retentioncompliancepolicy?view=exchange-ps)

## purview-retention-rules

- Group: Purview; provider: Purview.
- Request: `Get-RetentionComplianceRule`.
- Selected fields: `Identity`, `Name`, `Disabled`, `Policy`, `RetentionDuration`, `RetentionComplianceAction`, `ExpirationDateOption`, `ContentMatchQuery`.
- Limit: Selected rule settings only. ContentMatchQuery is configuration, not matched content.
- [Microsoft contract](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-retentioncompliancerule?view=exchange-ps)

## Shared service contracts

- [Graph paging](https://learn.microsoft.com/en-us/graph/paging)
- [Graph throttling and Retry-After](https://learn.microsoft.com/en-us/graph/throttling)
- [Authentication methods automatic expansion](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy?view=graph-rest-1.0)
- [Permission grant includes/excludes automatic expansion](https://learn.microsoft.com/en-us/graph/api/resources/permissiongrantpolicy?view=graph-rest-1.0)
