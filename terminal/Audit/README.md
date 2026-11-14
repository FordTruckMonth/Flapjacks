# Microsoft 365 Terminal Audit Adapter

**Version 0.2.0-terminal. PowerShell only. No HTML, localhost server, browser or web UI.**

This is the organization-configuration audit component for the integrated **Audit / Pull Logs** terminal launcher. It is separate from the earlier review build. The launcher owns administrator sign-in and confirmation prompts; this module never authenticates, grants permissions or changes tenant settings.

## Default: terminal and memory only

From PowerShell 7.4 or later:

```powershell
Import-Module ./M365SecurityAudit.psm1
$result = Invoke-M365OrganizationAudit -Mode Synthetic
Write-M365AuditSummary -Result $result
Write-M365AuditSource -Result $result -SourceId conditional-access -Offset 0 -Limit 20
```

No files are created when `-OutputPath` is omitted. The returned object retains Metadata, Coverage, Observations and Evidence for the launcher's terminal details menu. The standalone `Start-M365SecurityAudit.ps1 -Mode Synthetic` prints a summary and then exits; use the module/launcher to retain and inspect unsaved evidence.

All example records are invented. The full synthetic run has 46 selected sources, 43 collected and three deliberate gaps. Nothing connects to Microsoft.

## Optional structured local export

Only when the operator chooses to save evidence:

```powershell
$result = Invoke-M365OrganizationAudit -Mode Synthetic -OutputPath ./reports/demo
Write-M365AuditSummary -Result $result
./Test-AuditManifest.ps1 -Path ./reports/demo
```

Exports: `audit.json`, `coverage.csv`, `inventory.csv`, `observations.csv`, `collection-plan.json`, `evidence/*.json`, and `manifest.json`. No HTML is generated. Use a new directory; existing output paths are refused. Exported identities, policy targeting and infrastructure may be confidential.

## Live audit gate and launcher contract

1. The launcher establishes its approved delegated administrator sessions and verifies the account and tenant.
2. Display `Get-M365OrganizationAuditPlan`: all 46 supported source families, read scopes, limitations and data sensitivity.
3. Ask the operator to type the exact tenant confirmation, for example `AUDIT <tenant-guid>`, and explicitly agree to organization-wide configuration collection.
4. Only after both responses match, call:

```powershell
$result = Invoke-M365OrganizationAudit -Mode Live `
  -TenantId $verifiedTenantId -ExpectedAccount $verifiedAccountUpn `
  -ConfirmedTenantId $verifiedTenantId -ConfirmOrganizationWide
Write-M365AuditSummary -Result $result
```

Add `-OutputPath` only after the operator opts into saving evidence. The gate is validated **before any session inspection, request or output-directory creation**. Graph, Exchange and Purview identity checks run again for **each selected source**. A switched account, different tenant, app-only Graph context, certificate-based workload context, ambiguous workload session, expired token or unsupported context becomes an explicit gap rather than a read. Matching is exact apart from UPN case.

The wrapper includes all source groups. “Organization-wide” describes the subject scope, **not a claim to collect every Microsoft 365 setting**. Seven core sources plus explicit supported authentication, consent, administration, tenant inventory, Intune metadata, Exchange and Purview sources are documented in [SOURCES](docs/SOURCES.md). No users, sign-in logs, mail bodies, OAuth grants, app credentials, active probes or tenant writes are collected. Intune remains metadata-only. Conditional Access and other policy snapshots are not effective-enforcement results.

The underlying `Invoke-M365SecurityAudit` supports selected `-Include` groups and enforces the same live gate through `-ConfirmTenantId` and `-ConfirmOrganizationScope`; use the full wrapper for the integrated full-organization audit.

## Permissions and gaps

Use `Get-M365OrganizationAuditPlan` for the read-scope plan. Existing delegated read permissions and appropriate workload RBAC are required. The module does not install Microsoft modules, reconnect, request consent, activate roles or fall back to broader privileges. Missing permissions are reported, not granted. [Permission details](docs/PERMISSIONS.md) and [coverage boundaries](docs/COVERAGE.md).

Supported cloud: Microsoft global cloud only. Exchange/Purview require one active, unprefixed, tenant/account-matching REST session per workload, with command origin bound to that session. The launcher may offer an approved authentication workflow separately; this adapter contains no authentication commands.

## Validation

```powershell
./tests/Test-All.ps1
./tests/Test-TerminalGates.ps1
```

- **159 collection/report assertions passed.**
- **48 terminal gate/identity assertions passed.**
- Independent review verified rejected gates before session/disk activity, no-file mode and delegated account/tenant checks.

Tests use fixtures and intercepted collectors only. No Microsoft authentication, consent grant or live tenant call occurred. Windows/macOS and live module/RBAC/licensing validation remain unrun. Terminal controls are neutralized in summaries and the bounded per-source detail viewer. JSON/CSV evidence is optional; never interpret a missing source or an empty observation list as a clean tenant.
