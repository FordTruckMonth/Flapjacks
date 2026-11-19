# Coverage is part of the audit

## Status vocabulary

- **Collected**: the configured request completed and all observed top-level Graph continuation pages were collected, or all configured command variants succeeded without a detected warning/property gap. This is **not** proof of a complete workload inventory or effective protection.
- **Partial**: records may exist, but paging/record caps, an invalid/repeated continuation, malformed response, incomplete expanded relationship, missing selected fields, command warning or later request failure prevents a complete claim.
- **NotSelected**: explicit opt-in was not provided. No read attempted.
- **NotProvided**: a historical saved synthetic result lacked a supplied source. This remains a provenance/coverage label for old files, not a current collection mode or tenant evidence.
- **ModuleUnavailable / NotConnected**: prerequisite module/session absent or session identity ambiguous. No sign-in/install attempted.
- **TenantMismatch / IdentityMismatch / UnsupportedCloud**: tenant, delegated-account or cloud validation failed. No request for the affected source was made.
- **InsufficientPermissions**: no supported read scope appears in the existing delegated Graph context. No consent request or privileged fallback.
- **Unauthorized / AccessDenied / Unavailable / Throttled / Error**: collection failed. A 403 does not establish which permission, role, license or service prerequisite is missing; a 404 does not prove that no policy exists.

A successful empty collection is distinct from a failed collection. Unselected sources remain visible. Review observations use only Collected sources and never turn a missing source into a pass.

## What “current state” means

Each source has a collection timestamp; collection is not an atomic cross-service snapshot. A policy can change while the run is in progress. Graph `RequestCount` counts adapter invocations including retries, not the SDK's internal HTTP attempts. Graph `PageCount` counts successful page responses. For Exchange/Purview these counters count command invocations and successful command variants, not service-internal pages. API/SDK/module pagination and retry behavior can change.

In-memory policy JSON is retained; local JSON/CSV is written only when OutputPath is provided. Raw policy JSON is retained for the allowlisted Graph policy APIs. Exchange/Purview are deliberately **selected-field snapshots**, not full-fidelity exports. Complex Exchange values are represented as display strings instead of recursively serializing backing objects. Missing selected fields are named in `MissingFields` and mark a source Partial. Policy definitions may contain identities, addresses, IP ranges, domain names and arbitrary administrator-authored descriptions. They are not anonymous.

## Deliberate coverage boundaries

- **Conditional Access:** configuration and exclusions only. No what-if evaluation, sign-in data, group expansion, dynamic membership, device state, per-user MFA inventory, policy simulation or effective-access assertion. Enabled policies can have gaps; disabled or report-only policies may be intentional. Authentication strengths don't prove that users registered those methods.
- **Security defaults:** disabled does not itself imply a failure; Conditional Access can be the intended alternative. No inferred MFA coverage percentage.
- **Cross-tenant access:** basic defaults/partner settings; identity synchronization relationships are not expanded. Delegated readers may only receive basic properties.
- **Consent:** permission-grant policy definitions, not existing app permissions/OAuth grants, application/service-principal inventory, app credentials or consent requests.
- **Administration:** direct role assignments and eligibility IDs, not transitive group membership, identity resolution, actual activation histories, role-management policy rules, access reviews, effective privilege, workload-specific admin roles or complete PIM inventory.
- **Exchange:** selected policy settings and targeting rules. No mailbox enumeration, per-user authentication assignments, inbox rules, forwarding settings, permissions, message traces, audit logs or bodies. No DNS lookups or delivery tests. Transport rules have human-readable descriptions, not full executable conditions/actions. Inbound/outbound connectors are configuration only. All four outbound test-mode/rule-scope filter combinations are queried and deduplicated by identity. Default, preset and custom protections interact; precedence and recipient membership are not evaluated. Zero custom Safe Links/Attachments policies is not proof of no protection.
- **Purview:** selected DLP/retention fields and DLP rule labels. DLP/retention policy reads request DistributionDetail because summary location/status values can be inaccurate; returned distribution status is still not proof of enforcement. Retention Workload is not reliable actual targeting. No DLP rule condition/action evaluation, classification-content scan, adaptive scope expansion, label inventory, eDiscovery, retention enforcement or matched user content.
- **Intune:** policy metadata only. No secret-bearing policy settings, Settings Catalog, endpoint security baselines, assignment evaluation, device inventory or compliance status. Projection is enforced again locally if an API unexpectedly returns extra properties.
- **Licenses:** tenant SKUs do not establish per-user assignments, eligible feature use or service readiness.
- No SharePoint/OneDrive sharing-settings audit, Teams policy inventory, Defender for Endpoint/Cloud Apps configuration, Azure resource inventory, SaaS agents, attack simulation, DNS/network probes, credentials, user/bulk sign-ins, OAuth grants or audit events.

## Review observations

This initial release emits a small set of transparent review prompts: CA non-enforced/unknown states and exclusions; a truly empty CA response; security defaults disabled; user app registration allowed; organization mailbox auditing disabled; outbound automatic forwarding enabled; DKIM configuration disabled. There are no automatic remediations and no risk score. Other configuration is available for manual review in the inventory.

Hashes detect changes relative to a local manifest. They are not a signature, trusted timestamp or chain-of-custody guarantee. Protect the manifest and report together. The verifier refuses path traversal and symbolic-link paths. A caller can still replace the report and manifest together; use your own trusted archival/signing process when required.
