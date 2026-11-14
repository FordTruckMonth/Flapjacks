# Integrated terminal review build provenance

This integration was prepared for the repository owner and is proposed through a feature-branch pull request. It does not replace the legacy implementation at the repository root. It combines:

- Mailbox collector logic derived from `FordTruckMonth/m365-bec-investigator`, public base `3490b92126d020794b8951dfa7ae0275cad94703`, reviewed no-loopback branch `ced0175016e6704c18fa9519d7b41769a4e5a8ef`.
- The separately authored M365 policy auditor, adapted into the `Audit/` PowerShell module with explicit organization scope/identity gates and terminal output only.
- A new PowerShell-only launcher with device-code/reuse authentication choices, session binding, deferred read scopes, multi-target mailbox prompts, terminal triage and paginated in-memory viewing.

No external audit executable, live tenant data or credentials are included. The original reviewed tools were not overwritten. Publication is limited to the review branch; no merge or deployment is performed. Existing source licensing remains unchanged; public visibility alone does not grant a new open-source license.

All provider/authentication tests use synthetic fixtures, local mocks or injected transports. Microsoft PowerShell 7.7.0 Linux x64 was downloaded from the official PowerShell/PowerShell release and verified against its published SHA-256 hashes; the runtime is not included in the deliverable. Windows/macOS and real Microsoft module/identity acceptance remain untested.
