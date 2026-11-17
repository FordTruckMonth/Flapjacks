# Flapjacks posture review: first-stage mapping

**Primary purpose: whole-tenant Microsoft 365 security-posture review against Microsoft guidance, organized with NIST CSF 2.0.** The current implementation inventories 46 supported configuration sources. That is tenant-level scope, not complete Microsoft 365 coverage or effective-policy assessment. The separate single-mailbox snapshot is only an optional BEC handoff, not the product's main assessment.

This first stage is a **documented analyst mapping**, not an implemented compliance engine. It adds no collector, permissions, scoring, remediation, or tenant calls. Mappings below are our review organization, not an official Microsoft/NIST crosswalk or certification. NIST CSF describes adaptable outcomes, not a universal configuration checklist. [NIST CSF 2.0, February 2024](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

## What existing evidence can support

| Existing Flapjacks Audit evidence | Analyst review using Microsoft guidance | NIST CSF function context (not attainment) | What cannot be inferred |
|---|---|---|---|
| Conditional Access, named locations, security defaults, authentication methods/strengths | Review enforced state, exclusion rationale and intended strong-authentication design | PROTECT | Actual user/device coverage, MFA registration, authentication success, policy precedence or effective access |
| Authorization/consent policies, direct directory roles and eligibility IDs, cross-tenant settings | Review permission and administrator design, external-access intent | PROTECT; GOVERN context | Transitive/effective privilege, app grants, activation history, governance ownership or approved exceptions |
| Mail-protection settings and targeting rules, DKIM configuration, connectors, outbound forwarding policy | Compare configured protection and targeting with Microsoft's product guidance | PROTECT | DNS correctness, effective recipient protection, transport-rule execution, mail delivery or attack resistance |
| Organization mailbox auditing configuration | Review whether the setting merits investigation | DETECT | Log retention, collection completeness, detection coverage, alert quality or response readiness |
| DLP/retention selected fields and distribution details | Review intended data-protection policies and unresolved deployment status | PROTECT; GOVERN context | Actual enforcement, data classification, content coverage or legal retention compliance |
| Tenant domains/SKUs and restricted Intune policy metadata | Establish limited service/configuration context for the review | IDENTIFY | Complete asset/user/device inventory, per-user license eligibility or device compliance |

These rows refer to existing [exact source contracts](../Audit/docs/SOURCES.md), [permissions](../Audit/docs/PERMISSIONS.md), and [coverage boundaries](../Audit/docs/COVERAGE.md). Source records are evidence for review, not automatic passes. Microsoft API documentation supports field interpretation; it is not itself a recommendation to set every value in one direction. Disabled security defaults, zero custom protections, and report-only policies require context rather than automatic failure labels.

## Microsoft guidance to review alongside evidence

- [Microsoft 365 Zero Trust deployment](https://learn.microsoft.com/en-us/security/zero-trust/microsoft-365-zero-trust): organize a broader tenant posture roadmap beyond this collector.
- [Security defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults) and [Conditional Access planning](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access): evaluate the intended protection model and exclusions rather than grading a single enabled flag.
- [Recommended EOP/Defender for Office 365 settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365): compare applicable mail-protection settings, with license and recipient-targeting gaps retained.
- [Mailbox auditing](https://learn.microsoft.com/en-us/purview/audit-mailboxes): distinguish configured auditing from proven audit coverage.

These references are review inputs supplied for this stage, not newly implemented checks. Collection state and assessment state must stay separate.

## Microsoft baseline approach

Use the applicable Microsoft 365 product guidance and the tenant's approved baseline, not Azure controls indiscriminately. [Microsoft Secure Score](https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score) can provide a separately reviewed posture reference, but Flapjacks does not retrieve it, recreate it, or claim its score. Do not add Graph access to fetch it in this stage. The [Microsoft cloud security benchmark v2 page](https://learn.microsoft.com/en-us/security/benchmark/azure/overview) is explicitly Azure-focused and preview; it is not a substitute for a complete M365 baseline.

## Analyst output contract for a later posture engine

For each proposed finding, record:

1. Stable check ID, affected source IDs and exact observed fields.
2. Observation time, tenant/run identity and collection status.
3. Applicable Microsoft guidance URL and review/version date.
4. NIST CSF version plus explicitly analyst-mapped outcome/category, with rationale.
5. Applicability, licensing/RBAC dependency, missing evidence and confidence.
6. Observed condition separately from recommended action; owner/exceptions and suggested validation.
7. A conclusion such as `review-needed`, `not-assessed`, or `not-applicable` with justification. Reserve any future `satisfied` result for a documented, tested rule and sufficient evidence; never translate a collection success to a control pass.

No numeric score, compliance percentage, or green “secure tenant” badge is appropriate from this release. A failed or absent source is unknown. Even successful current configuration reads may be non-atomic and omit effective-targeting evidence.

## Explicit next-stage boundaries

GOVERN organizational policies, training, risk acceptance and supplier management; RESPOND procedures/exercises; RECOVER backup and restoration evidence require additional human/process evidence outside this collector. Current coverage also excludes SharePoint/OneDrive sharing, Teams policies, Defender endpoint/cloud-app configuration and effective per-user policy evaluation. These are visible gaps, not silently satisfied controls.

Next stage should define a small versioned recommendation catalog, validate it against synthetic positive/negative/unknown cases, and obtain review of the mappings before any additional live source or permission is proposed. Whole-tenant Audit retains its existing typed tenant and organization-wide authorization gates. No tenant run was initiated for this document.
