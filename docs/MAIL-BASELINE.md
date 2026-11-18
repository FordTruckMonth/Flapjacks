# Recommend mail baseline and workbook crosswalk

Documentation review: 2026-11-17. This is a bounded crosswalk from the mail themes in the supplied 134-control posture workbook to original, read-only Flapjacks checks. Workbook row references identify the supplied sheet's physical rows, not the number of implemented controls. The workbook is not copied, imported, executed, or treated as a complete Microsoft baseline. A workbook row and a Flapjacks check can have different conditions.

## Selection and operation

- Terminal **W / Recommend** selects the **Standard** mail comparison and displays that selection with its existing workbook read plan. It retains the single `WORKBOOK` organization-wide authorization for the displayed tenant and operator; choosing a comparison does not introduce another baseline prompt.
- `Invoke-M365OrganizationAudit -Workbook -WorkbookMailBaseline Standard` or `Strict` explicitly selects the API comparison. API omission remains `None` for reproducibility; `-WorkbookMailBaseline None` explicitly declines profile-dependent comparisons. The three separate Microsoft Global comparisons still use their fixed published targets; `None` does not turn them into Standard/Strict checks. The legacy `-WorkbookAntiPhishBaseline` parameter and the new alias select the same value, not independent baselines.
- The baseline selects local comparisons, not a tenant policy. It does not enable Standard/Strict presets or change any setting. Existing tenant/account matching, per-source session checks, scope checks, and access failures still apply.
- This mail expansion adds **no collection source, Graph scope, provider, sign-in, consent, role activation, remediation, or message-content collection**. It uses the same Exchange `Get-*` commands and existing tenant/account/provider checks. The second batch adds six optional field projections only when `WorkbookExchange` is explicitly selected: three impersonation actions from `Get-AntiPhishPolicy`, and quarantine retention plus spam/phishing ZAP from `Get-HostedContentFilterPolicy`. Missing fields are not fetched by a fallback call. The third batch changes comparisons only: it adds no getter or projection and reuses the already selected `Get-AtpPolicyForO365` switches and `Get-MalwareFilterPolicy` `FileTypes`.
- **A / Audit** retains its separate baseline. **P** renders the saved result locally; it does not recollect. The PDF, workbook Controls sheet, and presentation CSV use the same assessment rows. Source coverage remains a separate view.

## How to read an assessment

`Meets selected setting` means the saved, correctly typed values in every policy included by that check meet the documented comparison. Safe Links and Safe Attachments exclude explicitly identified Built-in protection records. It is not a claim that the tenant meets the whole workbook, has the Microsoft preset configured, or protects every recipient. `Needs action` means a comparison differs and needs review, not permission to modify a policy. `Not assessed` is not a pass or automatic `N/A`.

Successful source collection alone never passes a control. Empty results, denied or partial reads, absent/null/malformed fields, unknown enumeration values, and insufficient evidence remain unknown. No service default is invented from a missing value. A selected `None` baseline leaves the profile-dependent comparisons unassessed; it is not evidence that protection is disabled.

Older snapshots without the six optional fields remain usable for their existing checks. Each absent new field leaves its corresponding new check `Not assessed`; its absence does not invalidate otherwise sufficient base-field evidence. Default Audit does not project the optional fields, and re-rendering an older report does not collect them.

The authority of the comparison also matters:

1. **Microsoft recommendation:** a statically defined comparison with a specific Microsoft source. Report rationale labels this explicitly. Merely linking Microsoft documentation does not make an analyst rule a Microsoft recommendation. Three organization-level rows deliberately have no Standard/Strict target. They instead use the separate `Microsoft global` recommendation label and Microsoft's published Global/Built-in protection values. The file-type check measures coverage of Microsoft's documented defaults, not an exhaustive dangerous-extension recommendation.
2. **Analyst-selected rule:** for example, the existing connection safe-list review, the no-exceptions external-tagging rule, or accepting threshold 4 as meeting a Standard minimum of 3. These are not exact Microsoft preset claims.
3. **No assessed policy scope:** the records do not establish which recipients receive these settings. No effective coverage percentage is calculated.

## Workbook mail crosswalk

The comparisons below describe the implementation, not a transcription of workbook prose. Standard is the Recommend selection. Where values differ, the order is **Standard / Strict**. Every policy check is subject to the evidence and effective-scope limits above.

### Anti-phishing and impersonation

Definitions: [MailBaselineAntiphish.ps1](../terminal/Audit/src/MailBaselineAntiphish.ps1). Existing spoof-intelligence and phishing-threshold checks remain in [WorkbookExchange.ps1](../terminal/Audit/src/WorkbookExchange.ps1), without duplicate IDs.

| Workbook reference or theme | Implemented check and field | Comparison or remaining limit |
|---|---|---|
| Row 30: selected-user impersonation | `MDO-PHISH-USER-PROTECTION`: `EnableTargetedUserProtection` | `true` in both profiles. `TargetedUsersToProtect` is inventory; the required people and completeness of that list require organization-specific review. |
| Row 32: selected-domain impersonation | `MDO-PHISH-CUSTOM-DOMAIN-PROTECTION`: `EnableTargetedDomainsProtection`; `MDO-PHISH-ORGANIZATION-DOMAINS`: `EnableOrganizationDomainsProtection` | Both switches compare to `true`. The external-domain list, accepted domains, and ownership are not reconciled. |
| Rows 33 and 35: intelligence and protection | `MDO-PHISH-MAILBOX-INTELLIGENCE`: `EnableMailboxIntelligence`; `MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION`: `EnableMailboxIntelligenceProtection` | Separate `true` comparisons. One matching switch is not proof that the other prerequisite or an action is configured. |
| Row 36: targeted-user response | `MDO-PHISH-USER-ACTION`: `TargetedUserProtectionAction` | `Quarantine` in both profiles. Optional field; missing older-snapshot values remain unassessed. An action match does not establish the enable switch, protected-user list, targeting, or quarantine rights. |
| Row 38: domain-impersonation response | `MDO-PHISH-DOMAIN-ACTION`: `TargetedDomainProtectionAction` | `Quarantine` in both profiles. Optional field; an action match does not establish custom/organization-domain enablement, domain-list completeness, or quarantine rights. |
| Row 40: mailbox-intelligence response | `MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION`: `MailboxIntelligenceProtectionAction` | `MoveToJmf` / `Quarantine`. Standard matches this workbook row's Junk Email predicate; Strict does not. Both intelligence switches remain separate dependencies, not an effective-protection conclusion. |
| Rows 42, 44 and 46: impersonation tips | `MDO-PHISH-USER-SAFETY-TIP`, `MDO-PHISH-DOMAIN-SAFETY-TIP`, `MDO-PHISH-UNUSUAL-CHARACTER-TIP` | Respectively compare `EnableSimilarUsersSafetyTips`, `EnableSimilarDomainsSafetyTips`, and `EnableUnusualCharactersSafetyTips` to `true`. No client-rendering or blocking test. |
| First-contact and spoof response | `MDO-PHISH-FIRST-CONTACT`: `EnableFirstContactSafetyTips`; `MDO-PHISH-SPOOF-ACTION`: `AuthenticationFailAction` | `true`; `MoveToJmf` / `Quarantine`. The latter is a spoof action, not an impersonation or DMARC-action check. |
| Trusted impersonation exceptions | `MDO-PHISH-TRUSTED-SENDERS`: `ExcludedSenders`; `MDO-PHISH-TRUSTED-DOMAINS`: `ExcludedDomains` | Empty lists. A justified exception can be intentional; differences require review, not automatic deletion. |
| Existing spoof intelligence and threshold | `EOP-SPOOF-INTELLIGENCE`: `EnableSpoofIntelligence`; `EOP-PHISH-THRESHOLD`: `PhishThresholdLevel` | `true`; Standard accepts valid integer 3 or 4, Strict accepts 4. The minimum-threshold rule is not exact Standard-profile equivalence. |

### Inbound and outbound spam

Definitions: [MailBaselineSpam.ps1](../terminal/Audit/src/MailBaselineSpam.ps1). Inbound checks use `exchange-antispam-policies`; outbound checks use `exchange-outbound-spam-policies`.

| Workbook reference or theme | Implemented check and field | Comparison or remaining limit |
|---|---|---|
| Rows 57, 59, 61, 63 and 65: verdict actions | `EOP-SPAM-ACTION` (`SpamAction`); `EOP-SPAM-HIGH-CONFIDENCE-ACTION` (`HighConfidenceSpamAction`); `EOP-SPAM-PHISH-ACTION` (`PhishSpamAction`); `EOP-SPAM-HIGH-CONFIDENCE-PHISH-ACTION` (`HighConfidencePhishAction`); `EOP-SPAM-BULK-ACTION` (`BulkSpamAction`) | Spam and bulk: `MoveToJmf` / `Quarantine`. The other three: `Quarantine` in both profiles. Quarantine access and notifications are not assessed; retention has a separate stored-setting check. |
| Row 67: bulk threshold | `EOP-SPAM-BULK-THRESHOLD`: `BulkThreshold` | Exact integer `6` / `5`. Unlike a workbook condition of `<= 6`, a lower explicit value is a profile deviation, not automatically a weaker control. `MarkAsSpamBulkMail` is not collected. |
| Row 69: quarantine retention | `EOP-SPAM-QUARANTINE-RETENTION`: `QuarantineRetentionPeriod` | Exact integer `30` days in both profiles; valid stored range is 1–30. Zero is invalid, not a service-default placeholder. Optional field; actual message expiry and the recipient's effective anti-spam policy are not verified. |
| Row 71: spam ZAP | `EOP-SPAM-ZAP`: `SpamZapEnabled` | `true` in both profiles. Optional stored switch only; verdict actions, overrides, message state, and actual purge execution are not evaluated. This is not the malware or phishing ZAP check. |
| Separate phishing ZAP comparison | `EOP-SPAM-PHISH-ZAP`: `PhishZapEnabled` | `true` in both profiles. A separate optional field and definition, not an additional exact workbook row 71 or proof of a delivered-message purge. |
| Rows 72 and 169: inbound allow lists | `EOP-SPAM-ALLOWED-SENDERS`: `AllowedSenders`; `EOP-SPAM-ALLOWED-DOMAINS`: `AllowedSenderDomains` | Empty lists. These are not the Tenant Allow/Block List, connection IP allow list, or impersonation exceptions. |
| Spam safety tips | `EOP-SPAM-SAFETY-TIPS`: `InlineSafetyTipsEnabled` | `true`. Configuration only, not display verification. |
| Rows 74 and 75: forwarding and limit response | `EOP-SPAM-OUTBOUND-FORWARDING`: `AutoForwardingMode`; `EOP-SPAM-OUTBOUND-LIMIT-ACTION`: `ActionWhenThresholdReached` | `Off`; `BlockUser`. Row 74's system-controlled workbook condition differs from explicit `Off` and is not an exact workbook upgrade. Mailbox and remote-domain forwarding are not combined into an effective result. |
| Rows 76, 77 and 78: outbound recipient limits | `EOP-SPAM-OUTBOUND-EXTERNAL-LIMIT`: `RecipientLimitExternalPerHour`; `EOP-SPAM-OUTBOUND-INTERNAL-LIMIT`: `RecipientLimitInternalPerHour`; `EOP-SPAM-OUTBOUND-DAILY-LIMIT`: `RecipientLimitPerDay` | Exact `500` / `400`, `1000` / `800`, `1000` / `800`. Zero selects unresolved service defaults and is unassessed. A lower explicit limit is not automatically weaker. |
| Row 79: outbound notifications | `EOP-SPAM-OUTBOUND-LEGACY-NOTIFY`: `NotifyOutboundSpam` | `false` in both profiles. This follows the referenced replacement-alert approach, not a workbook or Secure Score expectation to enable the legacy switch. It does not verify that the replacement alert exists or reaches an administrator. |

Outbound comparisons do not demonstrate that a Standard or Strict preset applies: outbound spam policies are separate from those presets. Language/region restrictions and blocklists remain inventory, not universal security failures. See [Microsoft's outbound-policy guidance](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#outbound-spam-policy-settings).

### Safe Links, Safe Attachments, malware and global settings

Definitions: [MailBaselineProtection.ps1](../terminal/Audit/src/MailBaselineProtection.ps1) and [MailBaselineFileTypes.ps1](../terminal/Audit/src/MailBaselineFileTypes.ps1). All implemented Standard/Strict targets in this table are identical between profiles. The three Global targets are separate and are never substituted into either profile.

| Workbook reference or theme | Implemented check and field | Comparison or remaining limit |
|---|---|---|
| Row 49: Safe Links for Office | `MDO-LINK-OFFICE`: `EnableSafeLinksForOffice` | `true`. Supported-client behavior and licensing remain unverified. |
| Other Safe Links switches | `MDO-LINK-EMAIL`: `EnableSafeLinksForEmail`; `MDO-LINK-INTERNAL`: `EnableForInternalSenders`; `MDO-LINK-SCAN`: `ScanUrls`; `MDO-LINK-WAIT`: `DeliverMessageAfterScan`; `MDO-LINK-TEAMS`: `EnableSafeLinksForTeams`; `MDO-LINK-TRACK`: `TrackClicks` | Each compares to `true`. Click telemetry and delivered-message protection are not collected or tested. |
| Safe Links rewrite and bypass | `MDO-LINK-REWRITE`: `DisableUrlRewrite`; `MDO-LINK-CLICKTHROUGH`: `AllowClickThrough` | Both compare to `false`. `DoNotRewriteUrls` remains inventory, not a scored no-exceptions rule. |
| Rows 51 and 52: Safe Attachments response and scanning | `MDO-ATTACH-ACTION`: `Action`; `MDO-ATTACH-ENABLE`: `Enable` | `Block`; `true`. These are separate policy fields. The action is meaningful only when scanning is enabled; neither check proves the associated rule is enabled or assigned. |
| Safe Attachments redirection | `MDO-ATTACH-REDIRECT`: `Redirect` | `false`; `RedirectAddress` is not assessed. |
| Row 56: malware ZAP | `EOP-MALWARE-ZAP`: `ZapEnabled` | `true`. No actual post-delivery purge is tested, and this says nothing about spam/phishing ZAP. |
| Common-attachment response | `EOP-MALWARE-FILE-ACTION`: `FileTypeAction` | `Reject`. Existing `EOP-FILE-FILTER` separately compares `EnableFileFilter` to `true`; it is not duplicated. Default file-type coverage has its own check below; neither check establishes comprehensive filter contents or effective protection. |
| Row 168: common-attachment file types | `EOP-MALWARE-FILE-TYPES`: `FileTypes` | Contains all **53 documented default types** for Standard and Strict; extra configured types are permitted. This is stored-list coverage only. Row 168 remains partial because its comprehensive/custom list and linked enabled-rule requirement are not established. |
| Rows 81 and 82: organization-level protection | `MDO-ORG-COLLAB`: `EnableATPForSPOTeamsODB`; `MDO-ORG-SAFEDOCS`: `EnableSafeDocs`; related `MDO-ORG-SAFEDOCS-OPEN`: `AllowSafeDocsOpen` | Separate **Microsoft Global** targets are `true`, `true`, and `false`, respectively, from the published Built-in protection column. Standard/Strict targets remain undefined. Sufficient typed saved evidence permits assessment even when the profile is `None`; no effective protection or entitlement is inferred. |

The Global targets come from [Microsoft's Global settings guidance](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#global-settings-for-safe-attachments), not a Standard/Strict preset. Safe Documents additionally requires an assigned eligible **Office 365 SafeDocs (`SAFEDOCS`)** service plan and **Microsoft 365 Apps for enterprise version 2004 or later**. Defender for Office 365 Plan 1 or Plan 2 alone does not include Safe Documents. The saved organization switches do not verify service-plan assignment, client support, per-user availability, or actual file handling. `AllowSafeDocsOpen = false` alone does not establish blocking when Safe Documents is disabled or unavailable. See [Safe Documents eligibility and client requirements](https://learn.microsoft.com/en-us/defender-office-365/safe-documents-in-e5-plus-security-about).

The file-type target is the fixed default list documented in [Common attachments filter in anti-malware policies](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies), not the separate optional portal list or a workbook-derived list. Every returned policy must cover all 53 defaults; matching ignores case, a single leading dot, duplicates, and order. A well-formed empty or incomplete list is `Needs action`; absent, null, scalar, or malformed evidence is `Not assessed`. Extra valid types do not cause a mismatch. Filter enablement and response remain separate checks, and rule linkage, rule enablement, targeting, actual type detection, and attachment handling are not resolved.

The Safe Links and Safe Attachments checks require a Boolean `IsBuiltInProtection` flag to distinguish profiles. They exclude records marked `true`; a built-in-only response remains unassessed. Missing or malformed classification also prevents a pass. This separation is not an effective recipient-policy calculation.

### Coverage accounting

The three batches add **51 mail definition rows**: **48** profile-dependent comparisons and **three separately assessed Global comparisons**. Combined with the existing 30 workbook-profile rows, the aggregate report has **81 rows** over the same **55 selected sources**. The third batch adds one row (`EOP-MALWARE-FILE-TYPES`) and makes the three existing Global rows assessable; it does not add four rows or any sources. Neither 51 nor 81 is a count of satisfied workbook controls.

An exact workbook upgrade requires the same setting **and a comparable predicate**, plus the stated evidence scope. With the **Standard** comparison plus the separate **Global** targets, the strict same-setting/predicate mapping is **43 of 134 workbook rows (32%)**: the prior 14 plus **29 additional matches**, at worksheet rows **30, 32, 33, 35, 36, 38, 40, 42, 44, 46, 49, 51, 52, 56, 57, 59, 61, 63, 65, 69, 71, 72, 75, 76, 77, 78, 81, 82, and 169**. Rows 81/82 count only as matches to the same Global enable toggles, not as Standard/Strict targets or effective-protection results. The related Safe Documents click-through check is not another exact workbook upgrade. **91 rows remain outside this comparable mapping.**

Here, "strict mapping" describes the equivalence method, **not the Microsoft Strict profile**. Do not carry the 43/134 figure over to Strict: for example, row 40's `MoveToJmf` predicate differs from Strict's `Quarantine`. Rows 30/32 match the enable switches, not protected-list completeness. Rows 76–78 ask for recommended limits without fixed workbook numbers, so the explicit Microsoft values supply the comparison. This is implementation coverage, not a tenant pass count or proof of recipient coverage; missing or insufficient saved fields still leave the corresponding checks unassessed.

Keep row 67 (upper bound versus exact value), row 74 (system-controlled versus explicit forwarding off), row 79 (administrator notification not verified), and row 168 (comprehensive/custom file-type list plus a linked enabled rule not established) separate from exact upgrades. The separate phishing ZAP check likewise does not add another exact row 71 match. A broader Microsoft comparison can still be useful without being equivalent to a workbook row. The shared evaluation logic is in [MailBaseline.ps1](../terminal/Audit/src/MailBaseline.ps1).

## Source coverage is not recipient coverage

The report's source counts answer whether selected reads succeeded. They do not measure the number or percentage of users protected. Stored-setting comparisons include disabled, unassigned, and superseded policies; the explicit Built-in exclusions for Safe Links/Safe Attachments are the exception described above. Consequently, an inactive policy can cause a stored-setting difference even when it does not affect a recipient; a matching policy can protect nobody.

Rule state, priority, targeting, exceptions, group membership, and preset assignments are not resolved by this evaluator. Existing rule/preset records remain evidence for manual review. Microsoft's policy ordering applies the first matching policy of a type, not a merge of all matching settings; preset precedence can override a custom policy. See [Order and precedence of email protection](https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined).

Built-in protection also differs from Standard/Strict and can cover recipients outside those profiles or custom Safe Links/Safe Attachments policies, subject to its exclusions. Excluding built-in records from this comparison must not be relabeled as proof of an unprotected mailbox. See [Preset security policies in cloud organizations](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies).

## Remaining gaps and non-goals

- **Impersonation completeness:** action comparisons now exist, but impersonation quarantine tags, whether protected-person/domain lists cover the right population, and dependency-aware effective protection remain unassessed. Stored actions do not prove their prerequisites or actual message handling.
- **DMARC and spoof details:** `HonorDmarcPolicy`, `DmarcQuarantineAction`, `DmarcRejectAction`, `SpoofQuarantineTag`, `EnableUnauthenticatedSender`, and `EnableViaTag` are not selected. No SPF, DKIM, or DMARC DNS/delivery validation is performed.
- **Spam completeness:** retention and spam/phishing ZAP now have separate optional-field comparisons. Quarantine policies, release rights, notifications, ASF settings, bulk-filter enablement, actual expiry, and purge outcomes remain unassessed. Matching a stored setting does not prove its prerequisite or effective behavior.
- **Attachment/URL completeness:** documented default file-type coverage is assessed, but comprehensive list suitability and linked enabled-rule coverage remain unassessed. Quarantine settings, encrypted-attachment controls, URL rewrite exceptions, notification presentation, and the separate SharePoint malicious-file download restriction are not assessed. No specific Microsoft recommendation is inferred for fields the cited guidance leaves to business choice.
- **Licensing and access:** eligible Defender features, per-recipient entitlements, role availability, and actual service behavior are not inferred from tenant SKUs, policy existence, a missing cmdlet, or an empty response. Access failures remain gaps rather than insecure/secure verdicts.
- **Actual protection:** no mail-flow simulation, message-header analysis, delivery test, false-positive measurement, audit-ingestion test, or change to tenant configuration. No complete workbook parity, certification, posture score, or live acceptance claim.

## Microsoft references by exact section

The implementation uses selected comparisons, not the entirety of these sections. The source page is [Recommended email and collaboration threat policy settings for cloud organizations](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365).

- [Common attachments filter: documented default file types](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies)
- [Safe Documents entitlement and supported clients](https://learn.microsoft.com/en-us/defender-office-365/safe-documents-in-e5-plus-security-about)
- [Anti-malware policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-malware-policy-settings)
- [Anti-spam policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-policy-settings)
- [Outbound spam policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#outbound-spam-policy-settings)
- [Anti-phishing policy settings for all cloud mailboxes](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-phishing-policy-settings-for-all-cloud-mailboxes)
- [Phishing email thresholds in anti-phishing policies in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#phishing-email-thresholds-in-anti-phishing-policies-in-microsoft-defender-for-office-365)
- [Impersonation settings in anti-phishing policies in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365)
- [Global settings for Safe Attachments](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#global-settings-for-safe-attachments)
- [Safe Attachments policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#safe-attachments-policy-settings)
- [Safe Links policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#safe-links-policy-settings)

Related local contracts: [workbook expansion](WORKBOOK-POSTURE.md), [source catalog](../terminal/Audit/src/Catalog.ps1), [source documentation](../terminal/Audit/docs/SOURCES.md), and [permissions](../terminal/Audit/docs/PERMISSIONS.md). Local synthetic tests validate implementation paths, not a live tenant or effective enforcement.

## Local verification

From the repository root, use PowerShell **7.4 or newer** for the focused offline checks:

```powershell
./terminal/Audit/tests/Test-MailBaselineProtection.ps1
./terminal/Audit/tests/Test-MailBaselineFileTypes.ps1
./terminal/Audit/tests/Test-MailBaselineGates.ps1
./terminal/Audit/tests/Test-MailBaselinePresentation.ps1
```

The full local regression entry points remain `./tests/Test-All.ps1` and `./terminal/tests/Test-All.ps1`; the Audit suite's `./terminal/Audit/tests/Test-All.ps1` also parses every shipped Audit PowerShell file for syntax errors. These are synthetic/local checks, not tenant reads, licensing validation, or live acceptance. Run syntax checks and the applicable focused and aggregate tests against the final edited tree; passing only the focused checks is not a full regression pass.
