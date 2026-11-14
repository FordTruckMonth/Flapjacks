# M365 phishing/BEC investigator — review build

![Pixel-art bacon, egg and cheese sandwich in a security operations center, with a magnifying glass examining an email envelope.](docs/assets/bec-breakfast-banner.webp)

This PowerShell tool collects **read-only metadata** for a target mailbox and produces a local evidence case. It includes a complete synthetic demonstration and executable Exchange, Purview, Entra and optional Defender adapters. It never authenticates, installs modules, retrieves message bodies/attachments, fetches evidence URLs, or remediates a tenant.

**Review-ready fixture build; not live-tenant validated or a complete forensic acquisition.** Non-interactive user sign-ins have a separately labeled, opt-in Graph beta collector; its preview contract can change and is not a production support guarantee. See [coverage and limitations](docs/COVERAGE.md). An empty source is never a clean verdict.

## Run the synthetic demonstration

PowerShell **7.4+** is required (not Windows PowerShell 5.1). Native tests were run with Microsoft's portable **7.6.9**, macOS arm64. Python, Node, Pester and Microsoft modules are not needed for fixture mode.

From a shell with PowerShell on your PATH:

```sh
cd m365-bec-investigator
pwsh -NoLogo -NoProfile -File ./Start-BecInvestigation.ps1 -Mode Fixture -TargetUpn alex@contoso.example -NonInteractive
```

The result prints the exact `CasePath` and `report.html` path. Open that local HTML file. It has no JavaScript or remote assets. Fixture time is anchored to `2026-11-11T00:00:00Z`; the default period is the preceding 30 days. All records use synthetic identities, reserved example domains and documentation IPs. The scenario links phishing delivery, a Safe Links event, sign-in activity, a delegate-created rule, Bind/Sync mail-access evidence and post-delivery quarantine. Denied/unavailable/partial sources are deliberately included.

For prompts, omit `-TargetUpn` and `-NonInteractive`. The CLI asks for the target UPN and lookback days (default 30). It never asks for a password. `-StartUtc` and `-EndUtc` accept explicit ISO timestamps with offsets; `-LookbackDays` accepts 1–90. Historical timeline bounds are `[start,end)`; returned boundary records remain in raw JSON. Current snapshots always describe collection time.

## Tests and case verification

Inside PowerShell in this project:

```powershell
./tests/Test-All.ps1
./Test-CaseManifest.ps1 -CasePath './cases/<printed-case-directory>'
```

The suite parses the actual implementation and runs the preserved 9 UTC-helper scenarios (21 assertions), 18 pager cases and the investigator fixture checks. It uses injected transports, including paging, throttling, denials, hostile fields and missing modules. Results and a generated test case stay inside the project by default. The CLI exits successfully when a case is written and its hashes verify, even if every source is unavailable: inspect coverage, not only exit status. A passing fixture test does **not** verify tenant licensing, cmdlet availability, RBAC or server behavior. See [provenance](PROVENANCE.md).

## Live use — separate operator authentication

Live collection was **not executed** during development. Obtain authorization for the tenant and target first. Existing Microsoft modules and appropriate read roles must already be present; the tool neither installs them nor grants consent. Use a dedicated approved operator account with MFA, separate from the target. Authenticate in the **same PowerShell process** used to run the script; starting a new process loses those sessions.

The following are operator-run examples, not actions this tool performs:

```powershell
# Existing ExchangeOnlineManagement 3.7.0+ is required for Trace V2.
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName investigator@your-tenant.example
# If your approved audit workflow uses the compliance session:
Connect-IPPSSession -UserPrincipalName investigator@your-tenant.example

Import-Module Microsoft.Graph.Authentication
# Request only the scopes needed for the sources you are authorized to inspect.
# Tenant consent and role assignment must already be separately approved.
Connect-MgGraph -ContextScope Process -Scopes @(
  'AuditLog.Read.All', 'Directory.Read.All', 'IdentityRiskEvent.Read.All',
  'Policy.Read.ConditionalAccess', 'ThreatHunting.Read.All'
)

./Start-BecInvestigation.ps1 -Mode Live -TargetUpn target@your-tenant.example -LookbackDays 30 -IncludeDefender -IncludeNonInteractivePreview -NonInteractive
```

Omit `-IncludeNonInteractivePreview` if preview APIs are not approved for your environment; the report retains the resulting coverage gap. Microsoft documents beta APIs as subject to change and unsupported for production applications. Omit `-IncludeDefender` and `ThreatHunting.Read.All` if Defender is not authorized/needed. Omit other optional scopes when their source is out of scope; missing access is reported. Microsoft may show an interactive MFA/consent screen in those **separate** connection commands. Do not bypass it or supply a password to this tool. No connection commands are embedded in the implementation.

| Source | Existing privileges/capability to verify |
|---|---|
| Exchange snapshots | Scoped Exchange RBAC for the listed Get-* cmdlets and target. `Get-InboxRule` is not available to Global Reader or View-Only Organization Management alone; use a custom approved role with necessary read cmdlets rather than broad administrator access. |
| Trace V2/details | Exchange role allowing message trace, ExchangeOnlineManagement 3.7.0+, mailbox/trace scope. |
| Purview UAL | View-Only Audit Logs or Audit Logs role (for example approved audit-reader access); audit ingestion and relevant workloads enabled. |
| Entra sign-ins/audits | `AuditLog.Read.All`, supported role such as Reports Reader/Security Reader. Graph sign-in download requires P1/P2. CA policy details additionally require a supported CA read scope/role. |
| Target lookup/OAuth grants | `Directory.Read.All` and a supported directory-reading role; grants are current snapshots, with replication delay. |
| Risks | `IdentityRiskEvent.Read.All`, supported security-reading role and eligible Identity Protection license. |
| Defender | `ThreatHunting.Read.All`, supported role/data access and deployed licensed Defender services for each table. |

Microsoft Graph is currently restricted to the **Global** cloud. Unsupported national-cloud contexts are explicitly unavailable; the tool will not guess an endpoint or forward credentials. See the exact [Microsoft source mapping](docs/SOURCES.md). Permissions listed here are requirements to review, not grants.

## Collection behavior and limits

- Exchange retains current mailbox fields, aliases/type, size/quota/archive, forwarding/retain-copy, hidden rules, FullAccess/SendAs and `GrantSendOnBehalfTo`, folder ACLs, client protocols, mobile statistics and mailbox audit/retention fields. Missing/denied commands fail independently. Folder enumeration is bounded; the default cap is 100 ACL queries. Archive-statistics errors do not establish whether an archive exists; check the mailbox snapshot.
- Trace queries sent and received separately for the target plus verified current SMTP aliases/primary address in at most 10-day windows, `ResultSize=5000`. Full pages continue with the documented last recipient/received-time cursor. Repeated/no-progress/saturated/capped queries remain partial. Detail calls default to 200 unique trace/recipient pairs. Raw duplicates are retained; normalized duplicates merge their references and observed directions.
- Trace requests share a conservative local 90-calls/300-second limiter (Microsoft documents 100/5 minutes). Other clients can still cause throttling. Only 429/503/504 retry, at most twice. `Retry-After` longer than 60 seconds stops with a recorded failure rather than retrying early. Provider-owned internal retries are outside this wrapper's accounting.
- UAL uses one-day windows and a stable `ReturnLargeSet` session per window, `ResultSize=5000`, paging until empty or the 50,000/session cap. It queries tenant-wide pages **without an actor-only UserIds filter**, then exports records matched on named target/actor fields, verified mailbox identifiers and mailbox-qualified rule/folder identity boundaries. Thus delegates/admins can be included. Large tenants can hit the cap; narrower investigations or a separately implemented Management Activity API acquisition may be needed. Non-UPN/legacy identity representations and missing target fields can evade matching; this is explicitly not exhaustive attribution.
- Entra follows same-collection, HTTPS Graph nextLinks with bounded pages. Default `-MaxPages 20` applies to each paged query (1–100 accepted by CLI). Interactive/v1.0 collection stays separate. `-IncludeNonInteractivePreview` adds the documented beta `signInEventTypes/any(t: t eq 'nonInteractiveUser')` filter using the same read scopes; only `/beta/auditLogs/signIns` is allowed, with same-collection continuation. Omitting the switch records that coverage as unavailable. Service-principal and managed-identity sign-ins are outside this user-investigation collector. Tenant-wide OAuth grants and user-specific grants are separate; app-only service-principal assignments are not enumerated.
- Defender uses **Graph `POST /v1.0/security/runHuntingQuery`**, a read-only query operation. It queries fixed metadata columns from UrlClickEvents, EmailEvents, EmailPostDeliveryEvents and account-associated AlertEvidence, one-day windows, capped at 10,000 rows per table/window. Saturation is partial. It does not enumerate every tenant alert or all quarantined mail.

Override caps explicitly with `-MaxPages`, `-MaxDetails` and `-MaxFolders`; higher limits increase work and sensitive local evidence. No unbounded retries. Raw `Pages`, `Windows`, attempts and timestamps document what was requested and what failed. Already fetched generic-pager overflow is retained separately as `OverflowItems`; it is not silently counted as processed timeline data.

## Evidence and interpretation

Every case contains self-contained `report.html`, `timeline.csv/json`, `coverage.csv/json`, `correlations.csv/json`, `correspondents.csv`, `summary.json`, per-source `raw/*.json`, `manifest.json` and `manifest.sha256`. Summary records runtime/module versions, implementation hashes, collection times and fixture hash where applicable. Output is constrained to this project, in a unique case directory; existing output is not overwritten and symlink output paths are refused.

Raw values are **reserialized source objects**, not original HTTP bytes. Hashes detect byte changes after export; they do not authenticate Microsoft records or certify time. No source payload is mutated by normalization. Keep raw evidence local and access-controlled; the tool does not change filesystem permissions or encrypt cases. Do not publish a real case.

HTML encodes all evidence as text; URLs are defanged and not linked. CSV neutralizes formula-leading values including whitespace/control prefixes. Raw JSON retains original metadata strings. Do not render raw email-like fields as HTML. There are no bodies, attachments or email-content APIs in these collectors.

The UTC timeline separates historical events from current snapshots and flags missing timestamps. Exact, case-sensitive opaque IDs support **observed shared-identifier** links, not causation. Session links stay within provider families; IP proximity within 30 minutes is explicitly **inferred** and may reflect NAT/proxies. Link generation is capped and disclosed. There is no compromise score.

MailItemsAccessed **Bind** records retain aggregated item IDs; **Sync** remains folder-level, without invented item timestamps. Neither proves human reading; offline reads are absent. Safe Links is not full browsing history and clicks do not prove credential submission. Missing/default message IDs remain unlinked, and click-to-email correlation requires an actual EmailEvents record. `ActionType`, `IsClickedThrough` and click `ReportId` retain separate meanings.
