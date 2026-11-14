# Microsoft contracts checked 2026-11-11

Implementation uses public documentation, not third-party repository code. Documentation can change; live acceptance must check the installed modules and tenant capabilities.

| Implementation | Primary contract |
|---|---|
| Trace windows, cap, last-recipient/received continuation, rates | [Get-MessageTraceV2](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2?view=exchange-ps) |
| Trace detail identities and dates | [Get-MessageTraceDetailV2](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracedetailv2?view=exchange-ps) |
| Module 3.7.0+ requirement | [Modern message trace](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac) |
| Hidden rules and RBAC caveat | [Get-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps) |
| Folder enumeration | [Get-MailboxFolderStatistics](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailboxfolderstatistics?view=exchange-ps) |
| Mobile metadata | [Get-MobileDeviceStatistics](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mobiledevicestatistics?view=exchange-ps) |
| UAL paging, stable session, unsorted 50k cap | [Search-UnifiedAuditLog](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog?view=exchange-ps) |
| UAL roles and use case | [Audit log search script](https://learn.microsoft.com/en-us/purview/audit-log-search-script) |
| Mail access aggregates, Bind/Sync, licensing caveats | [Investigate compromised accounts](https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts) |
| Sign-ins, roles and conditional-access limitations | [List signIns](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [v1.0 resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0) |
| Opt-in preview non-interactive filter | [Beta signIn resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta), [beta list contract](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta) |
| Audit target resources | [List directoryAudits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) |
| User and all-principal delegated grants | [User oauth2PermissionGrants](https://learn.microsoft.com/en-us/graph/api/user-list-oauth2permissiongrants?view=graph-rest-1.0), [tenant grants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0) |
| Risk detections | [List riskDetections](https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0) |
| Retention and irreversible expiry | [Entra data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention) |
| Modern hunting endpoint and permission | [Graph runHuntingQuery](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0), [Start-MgSecurityHuntingQuery](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.security/start-mgsecurityhuntingquery?view=graph-powershell-1.0), [results schema](https://learn.microsoft.com/en-us/graph/api/resources/security-huntingqueryresults?view=graph-rest-1.0) |
| Click fields and missing/default message IDs | [UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table) |
| Delivery metadata | [EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table) |
| Quarantine/removal metadata | [EmailPostDeliveryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailpostdeliveryevents-table) |
| Account-associated alerts | [AlertEvidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table) |

Remaining snapshot cmdlets are listed literally in `src/Live.ps1`: Get-Mailbox, Get-MailboxStatistics, Get-MailboxPermission, Get-RecipientPermission, Get-CASMailbox, Get-MailboxFolderPermission, Get-AcceptedDomain. Only read commands are allowlisted. No `Get-Credential`, `Connect-*`, install, mutation, message-body, attachment-download or evidence-URL request is executed by the tool.
