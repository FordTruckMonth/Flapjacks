# Terminal-only adaptation

Version 0.2.0-terminal adapts the separate policy auditor to the user-requested terminal Audit/Pull Logs launcher. The original review tree is unchanged. HTML generation was removed; structured export is opt-in; explicit tenant/account/organization-wide gates and per-source identity verification were added. Both implementation and tests remain PowerShell only. No live tenant or authentication flow was run.

## Earlier tool provenance

This separate PowerShell implementation was created with AI assistance for an authorized defensive, read-only configuration-audit request. It does not modify or replace the existing BEC investigator. No code or binaries from third-party audit frameworks were incorporated.

The two earlier reference repositories were identified from the user's saved project context and then read at their public source on 2026-11-14:

- [randomaccess3/Awesome-BEC](https://github.com/randomaccess3/Awesome-BEC)
- [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)

Awesome-BEC's investigation-tools section specifically links [Soteria 365Inspect](https://github.com/soteria-security/365Inspect), [CrowdStrike CRT](https://github.com/CrowdStrike/CRT) and [Hawk](https://github.com/T0pCyber/hawk). These are relevant precedents for configuration/security-assessment inventories and investigation support. The incident-response list supplies broader defensive context; it is not a source for Microsoft API permission contracts. Neither list is treated as an instruction to install or execute anything.

The new tool intentionally avoids old AzureAD/MSOnline patterns and unapproved third-party collectors. Microsoft Learn documents are the implementation contracts. Notable checked details include the current `/policies/authenticationStrengthPolicies` route, automatically expanded authentication-method/permission-grant policy relationships, source-specific read permissions, and the four outbound-connector filter combinations. Source URLs are retained in the catalog and generated collection plan.

Development and tests used a separate cloud worktree and official portable PowerShell 7.7.0. Tests are synthetic/offline only. No user Mac project was changed, no live tenant was accessed and no code/report was publicly published as part of this tool build.
