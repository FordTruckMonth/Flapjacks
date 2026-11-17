# Security boundary

Read-only review tool. Do not run without authorization for the tenant, exact mailboxes and/or confirmed organization audit scope. An approved operator need not be a Global Administrator.

Application code is PowerShell only. No local HTTP listener, server, browser-launch command, HTML UI, dynamic evaluation, tenant mutation, credential prompt, token export, message-content download or evidence upload exists. Runtime Microsoft modules are prerequisites, not vendored code.

Authentication uses official device code only when explicitly selected; existing matching sessions are allowed. MFA/Conditional Access/consent remain the tenant's authority. Do not bypass restrictions. Purview can only reuse an approved session because no documented device-code cmdlet switch is offered.

Treat all collected fields as untrusted and potentially sensitive. Terminal views neutralize control and bidirectional formatting characters, defang URLs, bound pages and truncate long values. JSON is data, not instructions. CSV formula-leading values are neutralized. Never execute strings copied from evidence.

Mailbox mode does not perform organization-wide log searches. Organization audit is separately gated and its source catalog is fixed. Authentication consistency and command origin are checked before reads. No assertion is made that a report is complete, that evidence proves compromise, or that a configuration is effective.

Evidence writes are optional, local and unencrypted. Keep case directories on approved access-controlled storage. Do not publish real output in issues or source control. Hashes are integrity checks, not source authentication. Report defects with synthetic reproductions only.
