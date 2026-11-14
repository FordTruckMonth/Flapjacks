# Least-privilege prerequisites

Checked against official Microsoft documentation on 2026-11-14. Review the exact source's official link in SOURCES.md when operating; endpoints, roles and licensing can change. This release supports the Microsoft global cloud only even where Microsoft supports sovereign clouds.

## Graph

| Group | Read permission | Notes |
|---|---|---|
| Core | `Policy.Read.All` | Conditional Access, named locations, security defaults, authorization, admin consent and cross-tenant settings |
| Authentication | `Policy.Read.AuthenticationMethod` alone; existing `Policy.Read.All` is also documented | Core already requires Policy.Read.All, so the combined plan does not add a redundant scope |
| Consent | `Policy.Read.PermissionGrant` | Current permissionGrantPolicies list documentation does **not** list Policy.Read.All as a substitute |
| Administration | `RoleManagement.Read.Directory` | Also covers the eligibility list. Standalone eligibility API has the narrower `RoleEligibilitySchedule.Read.Directory` option; combined plan avoids requesting both |
| TenantInventory | `Domain.Read.All`, `LicenseAssignment.Read.All` | No User.Read.All or Directory.Read.All requested |
| Intune | `DeviceManagementConfiguration.Read.All` | Metadata-only does not create a narrower Graph permission. Opt-in is therefore explicit |

Microsoft documents these permissions for work/school delegated and application access; this terminal adapter intentionally accepts delegated administrator-user contexts only. Personal accounts are unsupported. Permissions alone are not sufficient where a delegated role is also required. The collector checks visible delegated read scopes and exact expected account/tenant before each source. App-only contexts are refused; tokens are never read.

Supported read-oriented delegated roles vary by API: Conditional Access/named locations support Security Reader or Global Reader; authentication methods require Global Reader or Authentication Policy Administrator; authentication strengths support Security Reader; admin-consent workflow supports Global Reader; direct role definition/assignment lists support Directory Readers or Global Reader. Cross-tenant reader roles expose basic properties, not necessarily identity synchronization. See the source-specific docs rather than assigning a broad administrator role to overcome a failure. [CA permissions](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0), [methods](https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0), [roles](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)

Conditional Access generally requires Entra ID P1; risk-based capabilities require P2. PIM requires P2 or Entra ID Governance. Intune policy APIs require an active Intune tenant license. These are feature prerequisites, not a diagnosis from an HTTP status. [Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview), [PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started), [Intune](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfiguration-list?view=graph-rest-1.0)

## Exchange and Purview

Graph scopes do not grant Exchange/Purview cmdlet rights. Use approved view-only workload roles, constrained to the cmdlets and parameters you need. Microsoft identifies Global Reader, Security Reader and View-Only Organization Management for relevant mail-security read operations, but exact availability remains tenant RBAC-dependent. Purview DLP and retention read roles are separate and should be assigned through the organization's compliance-access process. Do not grant Organization Management or Global Administrator as a blanket workaround. [Mail-security read permissions](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-eop-configure), [cmdlet RBAC discovery](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps), [Purview roles](https://learn.microsoft.com/en-us/purview/purview-permissions)

Safe Links/Attachments and impersonation protection depend on Defender for Office 365 licensing; Safe Documents has separate licensing requirements. DLP/retention capabilities depend on workload and subscription. Missing commands can mean RBAC, session, module or product availability, not an absent control. Preset and built-in protection may apply even without custom policies. [Safe Links](https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure), [Safe Attachments](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure)

Use current, trusted Microsoft modules through your approved software process. This tool does not install or update them. ExchangeOnlineManagement must expose REST session metadata including TenantID and ModuleName via Get-ConnectionInformation; older remote PowerShell sessions are intentionally refused. [Connection metadata](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-connectioninformation?view=exchange-ps)

No authentication examples in this package grant consent, create a credential, register an app or activate a role. Obtain any required approvals independently. A missing permission is an honest gap, not a reason for automatic elevation.
