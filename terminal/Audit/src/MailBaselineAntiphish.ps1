#requires -Version 7.4
# Fixed recommendations over Catalog.ps1 selected and optional projection fields only.
# Safe to dot-source: no authentication, provider calls, evaluation or export.
# EOP-SPOOF-INTELLIGENCE and EOP-PHISH-THRESHOLD remain in WorkbookExchange.ps1.
# Do not duplicate those controls or infer absent optional actions or uncollected DMARC/quarantine settings.
function Get-FlapjacksMailBaselineAntiphishDefinitions {
    $recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    $basicReference=$recommended+'#anti-phishing-policy-settings-for-all-cloud-mailboxes'
    $impersonationReference=$recommended+'#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365'
    $policyLimit='Stored settings in every returned policy, including disabled or unassigned policies. Rule enablement, priority, targeting, exclusions, preset precedence and effective recipient protection are not resolved.'
    $basicAccess='Existing approved Exchange Online read access to Get-AntiPhishPolicy; no new permissions or sessions. These basic settings are available for all cloud mailboxes.'
    $defenderAccess='Existing approved Exchange Online read access to Get-AntiPhishPolicy; no new permissions or sessions. Impersonation features require eligible Defender for Office 365 licensing; availability and recipient licensing are not verified.'
    @(
        [pscustomobject]@{
            Id='MDO-PHISH-FIRST-CONTACT'; Name='First-contact safety tip'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableFirstContactSafetyTips'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Microsoft recommends enabling the first-contact safety tip in both profiles.'
            Limitation=$policyLimit+' This setting is independent of spoof settings. A stored enabled switch does not prove a tip appeared or that any message was blocked.'
            Reference=$basicReference; Access=$basicAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-SPOOF-ACTION'; Name='Spoof-detection action'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='AuthenticationFailAction'; Kind='Enumeration'; Standard='MoveToJmf'; Strict='Quarantine'
            # Supported tokens: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps#-authenticationfailaction
            ValidValues=@('MoveToJmf','Quarantine')
            Rationale='The documented spoof action differs between Standard and Strict.'
            Limitation=$policyLimit+' Compares only the stored action for blocked spoof senders, not spoof-intelligence enablement. HonorDmarcPolicy, DmarcQuarantineAction, DmarcRejectAction and SpoofQuarantineTag are not collected; DMARC handling, quarantine rights and actual disposition are not assessed.'
            Reference=$basicReference; Access=$basicAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-USER-PROTECTION'; Name='Targeted-user impersonation protection switch'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableTargetedUserProtection'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable protection for selected high-value senders.'
            Limitation=$policyLimit+' Switch-only comparison. TargetedUsersToProtect must separately be reviewed against organization-specific key roles; an enabled switch with an empty or incomplete list is not complete protection. TargetedUserProtectionAction is assessed separately when available; quarantine settings are not collected.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-CUSTOM-DOMAIN-PROTECTION'; Name='Custom-domain impersonation protection switch'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableTargetedDomainsProtection'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable protection for selected external sender domains.'
            Limitation=$policyLimit+' Switch-only comparison. TargetedDomainsToProtect requires organization-specific review of frequently contacted external domains; an enabled switch does not establish list completeness. TargetedDomainProtectionAction is assessed separately when available; quarantine settings are not collected.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-ORGANIZATION-DOMAINS'; Name='Organization-domain impersonation protection'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableOrganizationDomainsProtection'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles include organization-owned domains in impersonation protection.'
            Limitation=$policyLimit+' Does not reconcile accepted domains, domain ownership or sender authentication. TargetedDomainProtectionAction is assessed separately when available; quarantine settings are not collected. Enabling this switch is not proof of message handling.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-MAILBOX-INTELLIGENCE'; Name='Mailbox intelligence'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableMailboxIntelligence'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable mailbox intelligence.'
            Limitation=$policyLimit+' Does not inspect mailbox communication history or detection outcomes. EnableMailboxIntelligenceProtection is a separate setting; this switch alone does not establish an impersonation response.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION'; Name='Mailbox-intelligence impersonation protection'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableMailboxIntelligenceProtection'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable impersonation protection using mailbox intelligence.'
            Limitation=$policyLimit+' Depends on EnableMailboxIntelligence; this is not a combined effective-protection check. MailboxIntelligenceProtectionAction is assessed separately when available; MailboxIntelligenceQuarantineTag is not collected, so release rights remain unknown.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-USER-SAFETY-TIP'; Name='User-impersonation safety tip'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableSimilarUsersSafetyTips'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable the user-impersonation safety tip.'
            Limitation=$policyLimit+' Tip switch only; does not validate protected senders, detection prerequisites, supported client rendering or a blocking action.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-DOMAIN-SAFETY-TIP'; Name='Domain-impersonation safety tip'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableSimilarDomainsSafetyTips'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable the domain-impersonation safety tip.'
            Limitation=$policyLimit+' Tip switch only; does not validate protected domains, detection prerequisites, supported client rendering or a blocking action.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-UNUSUAL-CHARACTER-TIP'; Name='Unusual-character impersonation safety tip'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='EnableUnusualCharactersSafetyTips'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both profiles enable the unusual-character impersonation safety tip.'
            Limitation=$policyLimit+' Tip switch only; does not establish detection of every visually similar character, protected-sender coverage, client rendering or a blocking action.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-TRUSTED-SENDERS'; Name='Trusted impersonation-sender exceptions'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='ExcludedSenders'; Kind='EmptyList'; Standard=@(); Strict=@()
            Rationale='Both documented profiles start without trusted sender exceptions.'
            Limitation=$policyLimit+' Microsoft permits organization-specific exceptions for false positives. A nonempty list needs review, not automatic removal or a conclusion that the tenant is insecure. This check does not validate exception justification or bypass of other protections.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-TRUSTED-DOMAINS'; Name='Trusted impersonation-domain exceptions'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='ExcludedDomains'; Kind='EmptyList'; Standard=@(); Strict=@()
            Rationale='Both documented profiles start without trusted domain exceptions.'
            Limitation=$policyLimit+' Microsoft permits organization-specific exceptions for false positives. A nonempty list needs review, not automatic removal or a conclusion that the tenant is insecure. This check does not validate exception justification or bypass of other protections.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-USER-ACTION'; Name='Targeted-user impersonation action'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='TargetedUserProtectionAction'; Kind='Enumeration'; Standard='Quarantine'; Strict='Quarantine'
            # Supported tokens: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps#-targeteduserprotectionaction
            ValidValues=@('NoAction','BccMessage','Delete','MoveToJmf','Quarantine','Redirect')
            Rationale='Microsoft recommends quarantine for targeted-user impersonation in both profiles.'
            Limitation=$policyLimit+' Stored action only, not an effective-protection check. Depends on EnableTargetedUserProtection and organization-specific TargetedUsersToProtect; their configuration and list completeness are not established by an action match. TargetedUserQuarantineTag and quarantine release rights are not collected. An absent optional action field in an older or incomplete snapshot is not assessed.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-DOMAIN-ACTION'; Name='Domain-impersonation action'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='TargetedDomainProtectionAction'; Kind='Enumeration'; Standard='Quarantine'; Strict='Quarantine'
            # Supported tokens: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps#-targeteddomainprotectionaction
            ValidValues=@('NoAction','BccMessage','Delete','MoveToJmf','Quarantine','Redirect')
            Rationale='Microsoft recommends quarantine for domain impersonation in both profiles.'
            Limitation=$policyLimit+' Stored action only, not an effective-protection check. Depends on EnableTargetedDomainsProtection with TargetedDomainsToProtect for custom domains, or EnableOrganizationDomainsProtection for organization domains; their configuration and domain coverage are not established by an action match. TargetedDomainQuarantineTag and quarantine release rights are not collected. An absent optional action field in an older or incomplete snapshot is not assessed.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        },
        [pscustomobject]@{
            Id='MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION'; Name='Mailbox-intelligence impersonation action'; SourceId='exchange-antiphish-policies'; Target='Get-AntiPhishPolicy'
            Field='MailboxIntelligenceProtectionAction'; Kind='Enumeration'; Standard='MoveToJmf'; Strict='Quarantine'
            # Supported tokens: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps#-mailboxintelligenceprotectionaction
            ValidValues=@('NoAction','BccMessage','Delete','MoveToJmf','Quarantine','Redirect')
            Rationale='Microsoft recommends Junk Email for Standard and quarantine for Strict mailbox-intelligence detections.'
            Limitation=$policyLimit+' Stored action only, not an effective-protection check. Meaningful only when EnableMailboxIntelligence and EnableMailboxIntelligenceProtection are both true; an action match does not establish those dependencies. MailboxIntelligenceQuarantineTag and quarantine release rights are not collected. An absent optional action field in an older or incomplete snapshot is not assessed. Workbook row 40 specifies Junk Email: Standard matches that action, but Strict quarantine is a different target and must not count as exact workbook-row equivalence.'
            Reference=$impersonationReference; Access=$defenderAccess; Section='Anti-phishing'
        }
    )
}
