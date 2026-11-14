# Authentication and execution contract

## Supported Microsoft mechanisms

- [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0): delegated `-UseDeviceCode -ContextScope Process -TenantId` with explicit read scopes. No token extraction, user/password form, secret file or app registration.
- [Get-MgContext](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/get-mgcontext?view=graph-powershell-1.0): local account, tenant, environment, authentication type and scopes are checked. The toolkit does not print or export the full authentication context.
- [Connect-ExchangeOnline](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-exchangeonline?view=exchange-ps): PowerShell 7 `-Device`; returned identity is verified rather than assumed from a login hint. Existing sessions are preferred and device-code mode is never a fallback after denial.
- [Get-ConnectionInformation](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-connectioninformation?view=exchange-ps): active REST connection, tenant, UPN, token status, workload, module prefix and command-origin binding are verified.
- [Connect-IPPSSession](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-ippssession?view=exchange-ps): no documented `-Device` switch. This app **never calls it**. Only an existing approved matching Purview session can be used; otherwise those sources are unavailable.

Device-code login still requires an approved web browser/device for Microsoft's verification page. It avoids the local redirect/listener that [MSAL system-browser authentication](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/using-web-browsers) may use. The toolkit does not control Microsoft page behavior or tenant policy. A device-code denial remains a denial; there is no retry using a different identity or auth mode.

## Scope sequencing

1. Bootstrap Graph requests only `User.Read`, or reuses a matching delegated context.
2. Before Audit reads, confirm the exact tenant and organization-wide scope. The selected catalog generates the required read-scope list; unavailable scopes/roles/licensing remain gaps.
3. Before Pull Logs reads, validate all exact targets and the time window, then obtain explicit target approval. Core Graph log sources use approved `AuditLog.Read.All`, `Directory.Read.All` and `IdentityRiskEvent.Read.All`; optional Defender adds `ThreatHunting.Read.All`. These Graph delegated permissions can be tenant-wide even though every tool query is target-scoped. The app does not shrink existing token privileges or certify RBAC.
4. Missing read scopes default to skipped sources. An explicit operator `D` choice requests only the chosen action's supported read scopes plus bootstrap `User.Read`; it does not automatically preserve unrelated broad scopes.
5. Source access is validated during collection. Session identity changes cannot silently redirect the next request to another tenant/account. No external tenant writes, broad log fallback, role activation or consent grants are attempted.

Operators must only request access already approved by their organization and must stop at any unexpected consent prompt. This documentation is not permission to grant access.
