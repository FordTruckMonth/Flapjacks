# Security boundary

Read-only configuration audit component. Review build, not a certified security product.

- The standalone launcher defaults to local Plan. Collection APIs require explicit Mode Live; there is no synthetic collection path. Optional reports require an explicit OutputPath. Otherwise no disk writes occur.
- Live requires tenant ID, matching repeated tenant, exact expected delegated administrator UPN and explicit organization-wide scope confirmation, before session/disk activity.
- Identity is rechecked per source. Graph is delegated/global only. Workload REST identity, auth metadata, single-session status, token status and command origin must match.
- No sign-in, consent, app/credential creation, role activation, permission grant, tenant setting changes, users/logs/content, OAuth grants, exploitation or active probes.
- Graph calls are GET to fixed v1.0 policy endpoints; safe same-resource continuation rules preserve metadata projections. Workload operations are allowlisted Get-* only.
- No HTML, web assets, server listener, localhost dashboard, browser launch, telemetry or upload.
- Terminal source values are neutralized for ANSI/OSC/C0/C1 and bidi control codes. Treat administrator-authored strings as data, never shell commands.
- Optional CSV exports neutralize formula-leading strings; JSON preserves configuration as data. Reports can contain identities, addresses, infrastructure and arbitrary sensitive descriptions. Store/share only through approved processes.
- Invalid/unavailable/denied/partial/unselected sources remain unknown. No auto-remediation or blanket secure/compliant score.
- Existing reports are never overwritten. Hash verification refuses traversal and link paths. A manifest is not a signature/trusted timestamp; protect it with its report.
- Trusted Microsoft modules and a controlled PowerShell process remain operator prerequisites. This is not isolation from a malicious local process.
