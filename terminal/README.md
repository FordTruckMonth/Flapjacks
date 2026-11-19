# Flapjacks terminal toolkit

**PowerShell-only application. No localhost, listener, web server, HTML UI, automatic browser launch, or Python dependency.**

Primary goal: tenant-level Microsoft 365 security-posture review informed by Microsoft guidance and NIST CSF 2.0. See the [bounded first-stage mapping](docs/POSTURE-MAPPING.md), not an automated compliance or scoring claim.

A read-only terminal workflow for an approved Microsoft 365 operator:

1. Choose live operation explicitly, then select Microsoft Graph or Exchange device-code sign-in, or reuse a verified session. Account and tenant returned by Microsoft are displayed and bound; no tenant GUID is requested up front. Startup A offers the displayed already-approved Audit scopes in one sign-in.
2. Choose **A** for the standard audit, **W** for extended workbook posture, or **L** for mailbox logs.
3. Use **V** to inspect the result, **P** to save an audit PDF/Excel/CSV bundle, or **S** to save the latest JSON. Files are saved only when requested.

This is a synthetic-tested review build, **not live-tenant validated**. It never grants consent, activates roles, changes policy, remediates a mailbox, downloads mail bodies/attachments, or uploads evidence.

## Start

First follow the separate [Windows](../docs/setup/windows/README.md), [macOS](../docs/setup/macos/README.md), or [Linux](../docs/setup/linux/README.md) setup README. Windows `RemoteSigned` can still block the unsigned GitHub source. The Windows guide describes an approved signed or managed distribution under the existing workstation policy; missing trust or policy requires administrator assistance.

Use **PowerShell 7.4+**, not Windows PowerShell 5.1. From this `terminal` directory run `Start-Flapjacks.cmd` on Windows for runtime/download checks, or run the script inside PowerShell 7:

```powershell
./Start-Flapjacks.ps1
```

Type **LIVE** at the startup prompt, or supply explicit `-Mode Live` on the launch command, before the app can inspect or open a Microsoft session. Blank input, EOF, or any other response cancels. Direct module callers must use `Invoke-M365Terminal -Mode Live`; omitted or retired modes stop before any work. The script wrappers forward supplied arguments and offer the live prompt only when Mode is omitted.

Already-installed, organization-approved modules are required for live work:

- `Microsoft.Graph.Authentication`, exposing `Connect-MgGraph -UseDeviceCode` and `Get-MgContext`.
- `ExchangeOnlineManagement` **3.7.0+** for Trace V2 and REST connection metadata. Versions **3.10+ require PowerShell 7.6+**; use a compatible version on 7.4/7.5.

For a clean Windows, macOS or Debian machine, follow the two-step [prerequisite guide](docs/PREREQUISITES.md): official PowerShell runtime first, then `./Install-Prerequisites.ps1` (local plan by default). Use `-Mode Install -IncludeExchange -WhatIf` to preview optional messaging components and remove `-WhatIf` only for an approved per-user install. Python is not required. Debian Exchange setup is skipped as unsupported; Purview is unavailable on macOS/Linux.

The separate prerequisite installer never signs in. The runtime app imports installed modules when connecting but never installs or updates them. Use a clean PowerShell process when session ambiguity occurs. Do not weaken execution policy, identity policy or security controls to make a run succeed.

### Authentication limitation, clearly stated

**The app stays in the terminal, but Microsoft device-code sign-in requires you to approve a code on a Microsoft web page using an approved browser/device.** No local browser is launched and no loopback callback is used. A fully browser-free delegated MFA login cannot be promised. Never type your password into the app.

After the live choice, startup choices are **A = Graph Audit approved-read sign-in**, **G = identity-only Graph sign-in** (`User.Read`), **E = Exchange device sign-in**, or **R = reuse**. Neither this prompt nor the reuse-provider prompt has a default provider; blank input, EOF, or Q cancels startup. A displays the exact read scopes before selection, makes one device-code connection, then proceeds directly to the single `AUDIT` authorization for the displayed tenant. There is no duplicate A selection. Canceling that audit authorization returns to the menu. G/E/R display authenticated account/tenant and open the menu directly; no extra Y/N merely to see it. Missing or ambiguous identity fails closed.

Audit A and Pull Logs L use existing approved same-tenant/same-account sessions only. There are no repeated provider/scope/Intune consent questions, reconnects or automatic permission expansion. Missing sources remain explicit coverage gaps with an Audit gap summary; use V / @coverage for detail. Identity-only G cannot collect configuration APIs without already-present scopes, so choose startup A deliberately when the displayed Audit access is already approved. Purview can only reuse an existing approved matching session. No new consent is authorized by choosing A.

If Microsoft shows a **new consent request** or Conditional Access blocks device code, stop and follow your administrator's approval process. The app cannot suppress every provider consent screen, and it never approves one. There is no browser/password fallback, grant API, role activation, app registration or policy workaround.

Tenant and operator account must match across Graph, Exchange and Purview. Sessions are checked again during collection. Ambiguous, mismatched, expired, prefixed or cross-tenant delegated Exchange sessions are refused. Commands must belong to the verified REST session. Microsoft Global cloud and delegated operator accounts only; app-only/national-cloud workflows are not supported here. No Global Administrator requirement is imposed: use the least-privileged approved read roles for selected data.

## Terminal menu

- **A — Audit:** displays the organization-wide configuration scope. After viewing the bound tenant/operator and concrete read scope, type exactly `AUDIT` once to authorize; blank or anything else cancels. No copying the GUID or second Y/N. The audit selects all **46 supported sources**, including Conditional Access and identity policies, role metadata, limited Intune policy metadata, Exchange protection policies and selected Purview retention/DLP settings. This is not every M365 setting, an effective-policy engine or compliance certification. Every selected source reports collected, partial, denied or unavailable coverage.
- **W — Extended workbook posture:** review the 55-source plan and type `WORKBOOK`. Stored mail settings use the Microsoft Standard comparison. This is not full 134-item workbook coverage.
- **P — Save audit posture bundle:** save the latest completed A/W audit as PDF, Excel, CSV, and evidence in a new directory under an existing private local folder; Enter at the destination prompt cancels.
- **L — Pull Logs:** accepts up to **50 exact usernames/UPNs/email addresses**, separated by commas. Bare usernames require an explicitly entered UPN suffix; the app does not guess a tenant domain or expand groups/wildcards. Confirm targets and a 1–90 day lookback or explicit ISO timestamps with timezone. Defender metadata and beta non-interactive user sign-ins are separate opt-ins. Each mailbox is queried independently.
- **V — View:** inspect the latest in-memory operation. Select a mailbox/audit result, then an exact source ID and page number. `@coverage`, `@observations`, `@timeline` and `@correlations` are also available. Output is paginated, terminal-control characters are escaped, URLs are defanged, and very long records are truncated. No files are needed for this viewer.
- **S — Save:** explicitly save the latest in-memory result as a new JSON file in an existing private directory. Blank cancels; existing files and symlink/reparse directories are refused. No recollection, reconnect, implicit directory creation or upload.
- **Q — Quit:** no automatic disconnect or tenant changes. Unsaved results are lost when the process exits.

### Pull Logs boundary

Collection includes current mailbox/rule/delegate/protocol/folder metadata; sent/received message traces and details; exact-user Entra sign-ins, risks and delegated grants; and optional target-filtered Defender hunting metadata. All requests stay scoped to the selected mailbox/user and verified current SMTP aliases.

It **never queries tenant-wide UAL, directory audit pages, accepted domains or all-principal OAuth grants**. Those gaps are visible and can hide delegate/admin actions relevant to an investigation. It does not claim a complete forensic acquisition. Graph requires the exact UPN; an email alias can work for Exchange yet leave Graph unavailable rather than triggering directory enumeration. No bodies, attachments, inbox-message APIs, URL fetching or blanket tenant user enumeration occur.

Provider retention, licensing, service deployment, RBAC, ingestion delay and query limits still apply. Empty data is not a clean verdict. Snapshot settings are current, not historical. Shared message/session identifiers are observations, not proof of causation; IP proximity is explicitly inferred.

## Optional local evidence

Choose menu **P** for the full audit bundle or **S** for a JSON snapshot when you want to save. It asks for a new local JSON path and serializes the latest existing result, without running collection again. The JSON can include sensitive mailbox metadata, policy targeting and infrastructure information. Keep it access-controlled and local; the app neither encrypts files nor changes filesystem permissions. Original direct collector APIs retain their explicit JSON/CSV output options; menu S is a JSON snapshot, not the original hashed report bundle. No transcript, token, password, device-code or credential file is created by app code. Microsoft modules may maintain their own session/cache state.

Integrity hashes detect later changes; they do not prove the truth or completeness of Microsoft records. CSV cells that could execute formulas are neutralized. Raw JSON preserves returned metadata strings and should be treated as untrusted data.

The application is live-only. Launch scripts require an affirmative **LIVE** response or explicit `-Mode Live`; `-Mode Synthetic` is rejected. QA datasets, replay adapters and scenarios live in a separate private copy, outside this public tree. The exported terminal orchestrator and Audit/Logs workflow helpers require explicit `-Mode Live` before any work; workflow authorization prompts remain mandatory.

The module exports the interactive terminal, the guarded Audit/Logs/current-snapshot workflows, and the non-collecting runtime, session-inspection, text/input and saved-evidence utilities needed by the launchers. Generic command execution, provider acquisition and transport helpers remain internal. The current-snapshot workflow and its standalone launcher also require explicit `-Mode Live`; conversion/export of already-supplied evidence preserves its original provenance.

See [postures checked and why](../docs/posture/README.md) for the standard and extended checks.

## Static checks and historical QA

From the repository root:

```powershell
./tools/Test-ReleaseBoundary.ps1
```

Historical private tests used Microsoft PowerShell **7.7.0 on Linux**, local mocks, injected transports and synthetic fixtures. Those scenarios are not shipped or run by public CI and were not rerun for this cleanup. They covered authentication choice/denial, tenant/account/session binding, scope deferral, multiple exact mailboxes, time/input validation, audit cancellation/gates, request/continuation scope, paging/throttling, escaping, evidence integrity, terminal viewing and no default file output.

**Not tested:** actual Microsoft sign-in/MFA/consent, live tenant APIs, Windows/macOS acceptance, real module/session persistence, server paging/retention, or licensed policy effectiveness. Do not treat an offline pass as those acceptances.

Detailed source/permission contracts: `Audit/docs/`, `Logs/README.md`, and `docs/AUTHENTICATION.md`. This integration is proposed through a review branch. Publication does not imply merge, deployment or live acceptance.

## Optional current mailbox snapshot

See [MAILBOX-SNAPSHOT.md](docs/MAILBOX-SNAPSHOT.md) for the narrow four-command Exchange-only smoke and optional interoperable local export. Audit remains the primary organization configuration workflow. This addition does not change Pull Logs or its historical collection scope.
