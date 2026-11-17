# Flapjacks: optional current mailbox snapshot

Flapjacks leads with **Audit**, the existing 46-source organization configuration review. This optional handoff is a separate, narrowly scoped current-mailbox collector/export for BEC analysis. Neither path certifies that a tenant is secure. The old `Start-M365Toolkit.ps1` and legacy collectors remain unchanged in purpose; `Start-Flapjacks.ps1` is a compatible branded entrypoint. No GitHub repository rename is part of this local change.

## Offline demo and tests (no Microsoft account, module, or network)

From the repository directory in PowerShell 7.4+:

```powershell
./terminal/Start-Flapjacks.ps1 -Mode Synthetic
./terminal/tests/Test-MailboxSnapshot.ps1
./terminal/tests/Test-All.ps1

# Optional local synthetic export. Choose an existing private directory and a NEW file.
Import-Module ./terminal/M365Toolkit.psm1 -DisableNameChecking
$result = Get-Content ./terminal/fixtures/mailbox-snapshot-input.synthetic.json -Raw | ConvertFrom-Json -Depth 100
Export-ToolkitMailboxSnapshot -Result $result `
  -TenantId '11111111-2222-3333-4444-555555555555' `
  -Path './flapjacks-SYNTHETIC.json'
```

The example tenant and mailbox are synthetic. Do not replace their identifiers to present fixture results as live evidence. Tests use injected command responses only, including denial, wrong-tenant and wrong-mailbox cases. Existing broad Logs fixture tests remain independent.

## Proposed manual single-mailbox smoke (not yet executed live)

Use an approved delegated Exchange operator in Microsoft Global cloud, an exact canonical mailbox UPN (not an alias), and a mailbox the operator is authorized to inspect. Use an existing unprefixed, active REST session in the **same PowerShell process** where possible. No Graph scope is required by this narrow path. Do not use the normal **L / Pull Logs** menu as the minimal smoke: it also collects current statistics/protocol/mobile/folder-permission metadata and target-scoped historical trace/Entra sources. Defender and non-interactive sign-ins are separate opt-ins there. Audit is explicitly organization-wide.

Runtime prerequisites:

- PowerShell **7.4+**, never Windows PowerShell 5.1. With ExchangeOnlineManagement **3.10+**, use PowerShell **7.6+**. This local offline run used 7.6.9; the locally available EXO version reported during setup is 3.11.1. Module presence is not proof of successful authentication or usable RBAC.
- Approved ExchangeOnlineManagement **3.7+** exposing REST `Get-ConnectionInformation` and its authenticated tenant/operator metadata. Compatible module/runtime and supported OS are required; no installation or settings changes occur in the smoke script. See [Microsoft's module requirements](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps).
- Existing Exchange RBAC must permit exactly `Get-Mailbox -Identity`, `Get-InboxRule -Mailbox -IncludeHidden -ResultSize`, `Get-MailboxPermission -Identity`, and `Get-RecipientPermission -Identity` for the selected mailbox. The tool neither grants nor shrinks privileges. `Get-InboxRule` does **not** work under View-Only Organization Management or Entra Global Reader alone; an authorized administrator must determine the tenant's appropriate existing scoped role. Do not grant a broad administrator role to work around a denial. [Inbox-rule permissions](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps), [RBAC discovery](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps).
- No Graph delegated scopes, no Purview connection, no app registration, no client secret, no app-only authentication. This path does not require trace/history/Defender licensing merely to run; source availability and mailbox permissions remain unverified live.

Start PowerShell interactively, without `-NonInteractive`. On this Mac:

```sh
'/Volumes/Cheese and Mac/Mac/openclaw/runtime/powershell/7.6.9/pwsh' -NoLogo -NoProfile
```

On Windows with approved PowerShell installed:

```text
pwsh -NoLogo -NoProfile
```

In that PowerShell process, change to the repository directory. If an approved existing Exchange session is already in this process, skip the login lines. Otherwise **only when the operator is ready and authorized**, use:

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Device
```

The operator completes Microsoft's device-code sign-in in an approved browser/device. Stop for new consent, missing privileges, unsupported session metadata or Conditional Access denial; do not bypass controls. The script itself never logs in or reconnects. [Microsoft device sign-in command](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-exchangeonline?view=exchange-ps).

Run the smallest in-memory smoke, replacing the example UPN:

```powershell
$snapshot = ./terminal/Get-CurrentMailboxSnapshot.ps1 -MailboxUpn 'person@your-domain.example'
$snapshot.sources.GetEnumerator() | ForEach-Object {
    [pscustomobject]@{Source=$_.Key;Status=$_.Value.status;Records=$_.Value.records.Count}
}
```

The script displays verified tenant/operator, exact mailbox and reads, then requires `SNAPSHOT <verified-tenant-guid> <exact-input-UPN>`. A mismatch stops before collection. It resolves one mailbox first and refuses alias/mismatched resolution; no additional mailbox commands then run. Session tenant/operator are rechecked before each read. There are four logical reads (transient/provider retries may issue additional requests):

1. `Get-Mailbox -Identity <UPN>` for forwarding and SendOnBehalf fields.
2. `Get-InboxRule -Mailbox <UPN> -IncludeHidden -ResultSize 1000`. At 1000 returned records, status is partial, never complete.
3. `Get-MailboxPermission -Identity <UPN>` for returned mailbox access entries.
4. `Get-RecipientPermission -Identity <UPN>` for returned recipient permissions.

There is no historical search, group expansion, delegate resolution, statistics read, mail-body/attachment retrieval, remediation, Graph, Purview, or tenant-wide fallback. Local connection metadata checks are not mailbox collection. No provider calls have been made by this local implementation/validation task.

To intentionally save during a later run, pass `-OutputPath` pointing to a new file in an existing private directory. That run reads again; it is not a save of the previous `$snapshot`. The destination is shown before confirmation. Export has no encryption/permission-hardening, refuses existing files and symlink/reparse ancestors, and never uploads. Files contain sensitive mailbox metadata; use organization-approved storage/retention. Do not save in a shared or synchronized folder inadvertently. Avoid concurrent filesystem changes during export; path validation is not an OS-level sandbox.

## Shared data contract

Top level:

```json
{
  "schema": "response-menu.mailbox-snapshot.v1",
  "tenant_id": "11111111-2222-3333-4444-555555555555",
  "mailbox_upn": "alex@contoso.example",
  "acquired_at": "2026-11-11T00:00:00.0000000Z",
  "synthetic": true,
  "evidence_class": "reserialized-source-objects",
  "sources": {
    "inbox_rules": {"status":"collected","records":[]},
    "forwarding": {"status":"collected","records":[]},
    "delegates": {"status":"collected","records":[]}
  }
}
```

This schematic is not evidence; use the explicit synthetic fixture for actual records. Each group has `collected`, `partial`, `denied`, or `unavailable` coverage. All `records` are arrays, including zero/one record cases. The exact source shapes are:

- `inbox_rules.records`: unchanged in-memory `Exchange.Rules.Items` objects serialized to JSON.
- `forwarding.records`: whole `Exchange.Mailbox.Items` objects, **not just forwarding fields**. Inspect `ForwardingAddress`, `ForwardingSmtpAddress`, `DeliverToMailboxAndForward`; missing properties mean partial, not disabled. Whole-object serialization can include additional mailbox metadata.
- `delegates.records`: `{ "source": "Exchange.FullAccess" | "Exchange.SendAs" | "Exchange.Mailbox.SendOnBehalf", "record": <source object> }`. SendOnBehalf uses the whole mailbox object and its `GrantSendOnBehalfTo` property. Do not count that wrapper as an individual delegate. Preserve inherited/deny/system entries; consumer must not treat all returned permissions as effective explicit grants.

Delegates are collected only if all three components were collected and SendOnBehalf is present. Mixed success/failure is partial; all denied is denied; no successful component is unavailable otherwise. This compact group contract cannot carry every original per-component reason, query log or timeline; retain the original investigation result for those details. A missing group source is unavailable, never a clean bill of health. A collected empty list only describes what that command returned under that session's permissions. No privilege-expansion inference is made.

`acquired_at` is overall collection completion in UTC, not an atomic transaction time or historic event timestamp. Current data can change between reads. `synthetic` comes from explicit Fixture/Live mode; unknown provenance is refused. Tenant identity is supplied by the verified session at the entrypoint; the serialization helper trusts its caller and does not authenticate or independently attest a supplied tenant GUID. `mailbox_upn` is lowercased; use canonical UPN results, not legacy SMTP-alias results.

This is **reserialized source objects**, not original HTTP bytes, signed evidence, a raw export, or a complete tenant timeline. No current field is used to reconstruct earlier mailbox state. Historical data is rejected by the exporter. Existing collector results can be passed to `ConvertTo-ToolkitMailboxSnapshot` or `Export-ToolkitMailboxSnapshot` without further network reads; these helper functions do not perform authentication, consent or evidence acquisition.

## Readiness and unknowns

Local PowerShell 7.6.9 passed the native parser and full synthetic suite: 7 authentication-display checks, 50 snapshot checks, 152 toolkit, 46 prerequisites, 37 Logs, 9 original-helper scenarios/21 assertions, 18 pager cases, 159 Audit and 48 Audit gate assertions. No Windows execution, real sign-in, tenant RBAC, licensing, real provider serialization/shape, API throttling, or correctness against known live mailbox data has been verified. A successful synthetic run is not a known-data live test. First live smoke should compare returned statuses and deliberately known current rules/forwarding/delegates for one authorized test mailbox, while recording missing fields as unknowns. No historical accuracy claim follows from that test. No cross-project license files were copied or changed.
