# Contributing

Use a feature branch and open a pull request against main. Keep changes focused, explain the behavior and risks, and request a review before merging.

## Local checks
Use PowerShell 7.4 or newer:
```powershell
./tools/Test-ReleaseBoundary.ps1
```
This check parses source and inspects public collection guards without importing application modules or running collection. Release CI runs this static check only.

QA data, generators, replay adapters and dependent scenarios belong in the separate private QA copy. Do not add them to a proposed public Git tree or its new commit ancestry. Keep credentials, tenant records and generated evidence out of all source commits. Review staged changes before pushing. Arrange any separately authorized regression work in the private QA copy; its historical passes are not validation of a new public candidate.

The proposed public tree must exclude scenarios in both a Git clone and an archive. `export-ignore` is only an additional archive safeguard. Build source/release downloads with `git archive <reviewed-commit>`; do not zip a working checkout. Keep the complete QA source snapshot on its private branch/worktree. Public-base history is not rewritten by this cleanup.

## Safety contract
Keep collection read-only. The terminal launcher may offer explicit official device-code sign-in before resolving the authenticated tenant and account for explicit operator confirmation; it must never grant consent, bypass tenant policy or fall back to browser/password authentication. Reuse verified sessions and defer action-specific read scopes. Collectors themselves must never authenticate. The separate prerequisite installer may install explicitly selected Microsoft modules into CurrentUser only, with a non-mutating default/WhatIf, preserved repository/license prompts and no repository, execution-policy, OS-security or tenant-authentication changes. Do not add automatic sign-in, consent grants, remediation, message bodies/attachments, evidence-URL fetching, external report assets or telemetry without an explicit design discussion. Preserve coverage gaps, collection provenance, raw-reference links and observed-versus-inferred distinctions. A fixture pass is not live-tenant validation.

Use reserved example domains and documentation IPs in private QA. Report public bugs with non-sensitive reproduction steps, not QA datasets or investigation evidence.

## Licensing
Original project material is available under the [MIT License](LICENSE). See [license scope](LICENSE-SCOPE.md) for exclusions.
