# Integrated terminal launcher interface

Import `Audit/M365SecurityAudit.psm1`. All code is PowerShell. No HTML or UI dependency exists.

```powershell
$plan = Get-M365OrganizationAuditPlan
# Launcher displays plan, signs in via its approved flow, and obtains typed tenant + explicit scope confirmation.
$result = Invoke-M365OrganizationAudit -Mode Live `
  -TenantId $tenantId -ExpectedAccount $accountUpn `
  -ConfirmedTenantId $typedAndVerifiedTenantId -ConfirmOrganizationWide
Write-M365AuditSummary -Result $result
# Preserve result and let the operator select from result.Coverage.SourceId:
Write-M365AuditSource -Result $result -SourceId $selectedId -Offset 0 -Limit 20
```

Optional `-OutputPath` writes JSON/CSV and hash manifest. Omitted path means no files or hidden temporary output. The result object contains:

- `Mode`, `TenantId`, `OutputPath` (empty for memory-only)
- `SelectedCount`, `CollectedCount`, `IncompleteCount`, `FindingCount`
- `Metadata`: audit schema `1.1`, tool version, scope confirmation, collection times/limits
- `Coverage`: source ID/group/provider/status/count/reason/missing-fields/limitations
- `Observations`: explainable review prompts
- `Evidence`: full per-source returned/configuration records and collection provenance

`Get-M365OrganizationAuditPlan` selects all 46 supported sources and returns the required read-permission union without redundant scopes. Missing auth scopes, unavailable modules, product licenses or workload roles remain visible gaps. The module never reconnects or grants permission.

Live gate order: nonempty TenantId; explicit ConfirmOrganizationWide; ConfirmedTenantId equality; ExpectedAccount UPN. This happens before directory creation or session calls. The module then checks delegated exact account+tenant per source. Graph is delegated-only and global-cloud only. Workload contexts reject certificate authentication, missing documented auth metadata, cross-tenant delegation, mismatched UPN, multiple sessions, prefixes and inactive tokens. Cmdlets bind to the validated REST session's module.

The wrapper uses the shared internal audit core with all optional source groups and maps its confirmation parameters to `ConfirmTenantId` / `ConfirmOrganizationScope`. Both public APIs accept Live only and enforce the live gate. There is no fixture collection or replay consumer in the public tree; historical saved-file provenance is preserved.

`Write-M365AuditSummary` reports every source status and important gaps. `Write-M365AuditSource` validates an exact source ID and prints a bounded JSON view in terminal. Both neutralize terminal control codes, including ANSI/OSC and bidi reordering. They do not return raw strings as executable commands, write files or launch a browser.

The standalone script is a summary wrapper. The integrated launcher must retain the returned object to provide a source-detail menu; otherwise unsaved evidence is deliberately discarded on exit. No historical incident conclusion should be inferred from a configuration snapshot.
