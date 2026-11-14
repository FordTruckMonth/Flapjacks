# Contributing

Use a feature branch and open a pull request against main. Keep changes focused, explain the behavior and risks, and request a review before merging.

## Local checks
Use PowerShell 7.4 or newer:
```powershell
./tests/Test-All.ps1
./terminal/tests/Test-All.ps1
```
Tests use synthetic fixtures and injected transports. Never add live credentials, tenant records or generated case/test-output folders to commits. Review staged changes before pushing. Add regression tests for parser, paging, coverage and reporting changes.

## Safety contract
Keep collection read-only. The terminal launcher may offer explicit official device-code sign-in after the operator supplies the tenant and account; it must never grant consent, bypass tenant policy or fall back to browser/password authentication. Reuse verified sessions and defer action-specific read scopes. Collectors themselves must never authenticate. Do not add automatic sign-in, consent grants, remediation, message bodies/attachments, evidence-URL fetching, external report assets or telemetry without an explicit design discussion. Preserve coverage gaps, collection provenance, raw-reference links and observed-versus-inferred distinctions. A fixture pass is not live-tenant validation.

Use reserved example domains and documentation IPs in tests. Report bugs with a minimal synthetic reproduction, not investigation evidence.

## Licensing
No open-source license has been selected yet. Public visibility does not by itself grant an open-source license. Discuss licensing with the repository owner before external reuse or redistribution.
