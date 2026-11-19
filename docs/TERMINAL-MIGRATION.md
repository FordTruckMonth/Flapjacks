# Moving to the terminal application

## Preferred entrypoint

From the repository directory in PowerShell 7.4+:

```powershell
./terminal/Start-M365Toolkit.ps1
```

Synthetic mode has been removed from the application. Use the [OS setup READMEs](../README.md#start-with-the-organization-wide-audit) for a live launch; fixtures and their dependent scenarios remain only in a separate private QA copy.

The application remains under `terminal/`; the root BEC collector and selected README banner are preserved. QA data and replay code are removed from the proposed public tree. `Start-BecInvestigation.ps1` remains the legacy command, not an alias for the terminal launcher. Direct collection APIs and the BEC launcher now require explicit `-Mode Live`; previously offline invocations stop before work.

## Important differences

| Area | Terminal entrypoint | Legacy root entrypoint |
|---|---|---|
| Workflow | Sign-in/reuse prompt, then Audit or Pull Logs | Direct live mailbox investigation |
| Authentication | Graph or Exchange device sign-in/reuse first; authenticated tenant/account confirmation; permissions deferred by action | Operator establishes sessions separately |
| Interface | Terminal summaries and paginated in-memory source viewer | Local static HTML case report |
| Files | Optional JSON/CSV evidence and hashes | Case files including HTML always written |
| Mailbox scope | Exact selected mailboxes only; no tenant-wide log fallback | May collect tenant-wide UAL/directory-audit pages for local target matching |
| Organization audit | Separate explicit tenant and organization-scope confirmations; 46 supported configuration sources | Not a comprehensive policy inventory |

Mailbox scope is a request boundary, not a reduction in existing token privileges. Skipping broad audit sources loses potentially relevant delegate/admin evidence. A result with gaps is not an exhaustive BEC investigation or a clean bill of health.

## Sign in first, confirm the resolved organization

The launch scripts first require an affirmative `LIVE` response unless the operator supplied explicit `-Mode Live`. The exported `Invoke-M365Terminal` requires that bound mode and stops before work if it is omitted. The operator then selects `G` (identity-only Graph device sign-in), `A` (Graph Audit approved-read sign-in), `E` (Exchange device sign-in), or `R` (reuse either provider). Blank input or EOF cancels at the live, sign-in and reuse-provider prompts; no provider is selected by default. There is no manual tenant GUID prompt before authentication. G requests only `User.Read`; A displays its approved Audit read scopes before selection. `Get-MgContext` or Exchange `Get-ConnectionInformation.TenantID` supplies the authenticated tenant and account for confirmation. Missing, ambiguous or unreliable identity metadata stops the workflow; the app does not infer tenant identity from an email suffix.

The confirmed context binds every later component. Full audit displays Graph, Exchange and Purview requirements. Missing or mismatched components are independent coverage gaps: Graph-only audits need no Exchange connection. Additional Graph device sign-in is pinned to the confirmed tenant, and the returned account must match. Exchange device sign-in is checked after it returns. Purview uses a preconnected matching session only. Organization-wide audit still requires the typed `AUDIT <resolved-tenant-guid>` confirmation and a separate authorization answer before collection.

## Authentication is not browser-free MFA

Device code avoids a local callback listener and does not launch a browser. Microsoft still requires the operator to approve a code on an approved browser/device. The app cannot promise a wholly browser-free delegated MFA login. Stop at unexpected consent or policy blocks; do not weaken controls. Purview has no documented device-code switch and only reuses an already approved matching session.

Use least-privileged approved read roles, not Global Administrator merely to make a source succeed. Global Microsoft cloud/delegated operator accounts only. Graph, Exchange and Purview must agree on the tenant and operator. Missing modules, read permissions, licensing or data are reported as gaps. The code does not install modules, grant permissions, activate PIM, create app registrations or remediate resources.

## Validation and rollout

Run the public static check from the repository root:

```powershell
./tools/Test-ReleaseBoundary.ps1
```

Historical development used synthetic fixtures, mocked authentication and injected transports in QA. That data and the dependent scenarios are retained only in a separate private copy and were not rerun for this cleanup. See the terminal validation JSON for exact counts. Windows/macOS integration, actual device-code sign-in, Microsoft module/session lifetime, tenant licensing/RBAC, server paging and policy effectiveness remain unvalidated. Review the draft PR before merging. No merge or deployment is included.

Do not upload a real evidence directory to GitHub. Keep optional outputs local and access-controlled. Hashes detect later byte changes, not evidence truth. Existing licensing is unchanged.
