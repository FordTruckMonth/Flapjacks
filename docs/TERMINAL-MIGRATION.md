# Moving to the terminal application

## Preferred entrypoint

From the repository directory in PowerShell 7.4+:

```powershell
./terminal/Start-M365Toolkit.ps1
```

For a completely offline demonstration:

```powershell
./terminal/Start-M365Toolkit.ps1 -Mode Synthetic
```

The new application is additive under `terminal/`. Existing root PowerShell files, fixtures and the selected README banner are preserved. `Start-BecInvestigation.ps1` remains the legacy command; it is **not** an alias for the new launcher. Existing scripts can keep their legacy behavior until the operator explicitly switches entrypoints.

## Important differences

| Area | Terminal entrypoint | Legacy root entrypoint |
|---|---|---|
| Workflow | Sign-in/reuse prompt, then Audit or Pull Logs | Direct fixture/live mailbox investigation |
| Authentication | Graph or Exchange device sign-in/reuse first; authenticated tenant/account confirmation; permissions deferred by action | Operator establishes sessions separately |
| Interface | Terminal summaries and paginated in-memory source viewer | Local static HTML case report |
| Files | Optional JSON/CSV evidence and hashes | Case files including HTML always written |
| Mailbox scope | Exact selected mailboxes only; no tenant-wide log fallback | May collect tenant-wide UAL/directory-audit pages for local target matching |
| Organization audit | Separate explicit tenant and organization-scope confirmations; 46 supported configuration sources | Not a comprehensive policy inventory |

Mailbox scope is a request boundary, not a reduction in existing token privileges. Skipping broad audit sources loses potentially relevant delegate/admin evidence. A result with gaps is not an exhaustive BEC investigation or a clean bill of health.

## Sign in first, confirm the resolved organization

The first prompt is `G` (default Graph device sign-in), `E` (Exchange device sign-in), or `R` (reuse either provider). There is no manual tenant GUID prompt before authentication. Initial Graph sign-in requests only `User.Read`. `Get-MgContext` or Exchange `Get-ConnectionInformation.TenantID` supplies the authenticated tenant and account for confirmation. Missing, ambiguous or unreliable identity metadata stops the workflow; the app does not infer tenant identity from an email suffix.

The confirmed context binds every later component. Full audit displays Graph, Exchange and Purview requirements. Missing or mismatched components are independent coverage gaps: Graph-only audits need no Exchange connection. Additional Graph device sign-in is pinned to the confirmed tenant, and the returned account must match. Exchange device sign-in is checked after it returns. Purview uses a preconnected matching session only. Organization-wide audit still requires the typed `AUDIT <resolved-tenant-guid>` confirmation and a separate authorization answer before collection.

## Authentication is not browser-free MFA

Device code avoids a local callback listener and does not launch a browser. Microsoft still requires the operator to approve a code on an approved browser/device. The app cannot promise a wholly browser-free delegated MFA login. Stop at unexpected consent or policy blocks; do not weaken controls. Purview has no documented device-code switch and only reuses an already approved matching session.

Use least-privileged approved read roles, not Global Administrator merely to make a source succeed. Global Microsoft cloud/delegated operator accounts only. Graph, Exchange and Purview must agree on the tenant and operator. Missing modules, read permissions, licensing or data are reported as gaps. The code does not install modules, grant permissions, activate PIM, create app registrations or remediate resources.

## Validation and rollout

Run both independent suites:

```powershell
./tests/Test-All.ps1
./terminal/tests/Test-All.ps1
```

Only synthetic fixtures, mocked authentication and injected transports were used for this change. See the terminal validation JSON for exact counts. Windows/macOS integration, actual device-code sign-in, Microsoft module/session lifetime, tenant licensing/RBAC, server paging and policy effectiveness remain unvalidated. Review the draft PR before merging. No merge or deployment is included.

Do not upload a real evidence directory to GitHub. Keep optional outputs local and access-controlled. Hashes detect later byte changes, not evidence truth. Existing licensing is unchanged.
