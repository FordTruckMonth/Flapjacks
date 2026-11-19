# Terminal adapter validation

This is a historical QA record. Named test scripts and their data are retained in the separate private QA copy, are not shipped in this public tree, and were not run for this cleanup. Current candidate receipts cover static inspection only.

Version 0.2.0-terminal; audit schema 1.1; manifest schema 1.0. Tested offline on Linux x86_64 with official portable PowerShell 7.7.0.

- `tests/Test-All.ps1`: **159 assertions passed**, including collection pagination/retries/errors, selected-field projections, safe output, command origin/prompt guards, Purview DistributionDetail and manifest integrity.
- `tests/Test-TerminalGates.ps1`: **48 assertions passed**. Missing/mismatched tenant/scope/account rejected before session inspection and file creation; pure Graph/Exchange/Purview identity fixtures; delegated-only checks; ambiguous/mismatched/expired sessions; all 46 per-source identity rechecks; no reads with missing scopes; in-memory-only operation; terminal sanitization; bounded detail viewing.
- Independent read-only review confirmed invalid gates precede session/disk activity, synthetic wrapper returns 46-source in-memory evidence, and no HTML/browser/server path remains.

No live service API calls, Microsoft authentication, admin consent, app registrations, grants or role activation. The tests that invoke `-Mode Live` intercept collectors and session helpers inside the isolated test process; they do not reach Microsoft.

Not validated: real Microsoft module/RBAC integration, live license/API acceptance, effective policies, Windows/macOS. The integrated launcher has its own sign-in and input/menu tests, outside this adapter's scope.
