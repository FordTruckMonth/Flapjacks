# Terminal mailbox logs adapter

PowerShell 7.4+. No authentication, module installation, web UI, HTML reports, listener, body/attachment retrieval, mutation or external transfer. The parent terminal application supplies a preauthenticated, tenant-checked transport.

```powershell
Import-Module ./Logs/M365Bec.psm1 -Force
$context = New-BecContext -Transport $guardedTransport
$result = Invoke-BecInvestigation -Mode Live -TargetUpn alex@contoso.example `
    -Start ([DateTimeOffset]'2026-11-01T00:00:00Z') `
    -End ([DateTimeOffset]'2026-11-02T00:00:00Z') -Context $context
$result.Coverage | Format-Table Source, Status, Reason -Wrap
```

Return fields: `Metadata`, `Collections` (raw collection objects), `Timeline`, `Correlations`, `Coverage`, `Summary`, `TimelineRows`, `Mode`, `CollectionScope`, and optional `CasePath`/`Manifest`. No files are written unless `-OutputRoot` is supplied. Output must be within `-ProjectRoot` (defaults to this Logs directory); the launcher can pass its own root for local evidence exports. Optional files are JSON, formula-guarded CSV, and SHA256 manifests. Returned raw data remains unmodified; a terminal renderer must sanitize control sequences before printing untrusted fields.

`CollectionScope` accepts only `MailboxOnly`. Tenant-wide UAL, Entra directory audit, accepted domains and tenant delegated grants are not collected, and their coverage gaps are explicit. Target mailbox lookup must return exactly one matching UPN/SMTP address; fuzzy/display-name results are rejected before further Exchange collection. Graph user lookup must return the exact supplied UPN and a GUID. An alias which is not the Graph UPN remains a Graph coverage gap; it is not broadened into another lookup. Current verified aliases may be used for trace queries about the same mailbox.

Graph target/time filters must remain unchanged on every continuation page. Missing filters, changed paths, added nonpaging parameters and duplicate parameters are refused; fetched earlier pages remain Partial. This intentionally rejects opaque skiptoken-only links that omit the original filters, rather than risking an unscoped query. Optional Defender and noninteractive-preview collectors remain explicit switches. Preview APIs, RBAC, licensing, retention, quotas and server behavior are not live validated.

Offline test command: `./Logs/tests/Test-All.ps1`. All provider calls in tests are injected; no tenant authentication or network collection is performed. Fixture records are synthetic, reserved-domain data. Missing evidence never means a clean mailbox.
