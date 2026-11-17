#requires -Version 7.4
# Fixed recommendations for fields already collected by Catalog.ps1. Safe to dot-source:
# no authentication, collection, remediation, provider calls, or report-data commands.
# Microsoft recommendations and parameter semantics verified 2026-11-17.
function Get-FlapjacksMailBaselineSpamDefinitions {
    $recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    $inboundReference=$recommended+'#anti-spam-policy-settings'
    $outboundReference=$recommended+'#outbound-spam-policy-settings'
    $access='Exchange Online read access to the existing collected policy records; no additional provider or scopes.'
    $policyLimit='Stored values only, including disabled or unassigned policies. Rule state, priority, targeting, exceptions, preset precedence and effective recipient protection are not evaluated.'
    $quarantineLimit=$policyLimit+' Quarantine policy tags, release permissions and notifications are not collected by these checks. Retention is a separate stored-setting comparison.'
    $zapLimit=$policyLimit+' Stored switch only. Verdict actions, allowlists and mail-flow overrides can affect ZAP; applied policy, message read state, post-delivery detection, purge execution and message outcomes are not verified. This is not malware ZAP or Teams protection.'
    $bulkLimit=$policyLimit+' MarkAsSpamBulkMail is not collected; matching the threshold or action does not establish that bulk filtering is enabled.'
    $outboundLimit=$policyLimit+' Outbound spam settings are not part of Standard or Strict preset security policies.'
    $sendingLimit=$outboundLimit+' Zero selects service defaults, so zero is not assessed. This is exact profile alignment; a smaller explicit limit is not automatically a weaker control. Actual sending activity and service-limit enforcement are not tested.'

    # Language/region controls have no specific Microsoft recommendation. Blocklists
    # are business-specific filtering inputs, not allow-list bypasses. Those fields
    # remain inventory only, as do dormant legacy notification-recipient entries.
    # Uncollected ASF, quarantine-policy and bulk-enablement fields are not inferred.
    # Retention/ZAP values may be absent from older saved evidence; never supply defaults.
    @(
        [pscustomobject]@{
            Id='EOP-SPAM-BULK-THRESHOLD'; Name='Inbound bulk email threshold'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='BulkThreshold'; Kind='IntegerExact'; Standard=6; Strict=5; Minimum=1; Maximum=9
            Rationale='Compare the stored bulk complaint threshold with the exact Microsoft Standard or Strict value.'
            Limitation=$bulkLimit+' A lower threshold is more aggressive but is a deviation from the selected exact profile, not proof of weaker protection.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-ACTION'; Name='Inbound spam action'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='SpamAction'; Kind='Enumeration'; Standard='MoveToJmf'; Strict='Quarantine'
            ValidValues=@('AddXHeader','Delete','ModifySubject','MoveToJmf','Quarantine','Redirect')
            Rationale='Compare the action for a spam verdict with the selected Microsoft profile.'
            Limitation=$quarantineLimit
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-HIGH-CONFIDENCE-ACTION'; Name='Inbound high-confidence spam action'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='HighConfidenceSpamAction'; Kind='Enumeration'; Standard='Quarantine'; Strict='Quarantine'
            ValidValues=@('AddXHeader','Delete','ModifySubject','MoveToJmf','Quarantine','Redirect')
            Rationale='Both Microsoft profiles place high-confidence spam in quarantine.'
            Limitation=$quarantineLimit
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-PHISH-ACTION'; Name='Inbound phishing action'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='PhishSpamAction'; Kind='Enumeration'; Standard='Quarantine'; Strict='Quarantine'
            ValidValues=@('AddXHeader','Delete','ModifySubject','MoveToJmf','Quarantine','Redirect')
            Rationale='Both Microsoft profiles place phishing detections in quarantine.'
            Limitation=$quarantineLimit+' This is not the anti-phishing policy spoof or impersonation action.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-HIGH-CONFIDENCE-PHISH-ACTION'; Name='Inbound high-confidence phishing action'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='HighConfidencePhishAction'; Kind='Enumeration'; Standard='Quarantine'; Strict='Quarantine'
            ValidValues=@('Redirect','Quarantine')
            Rationale='Both Microsoft profiles place high-confidence phishing detections in quarantine.'
            Limitation=$quarantineLimit
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-BULK-ACTION'; Name='Inbound bulk email action'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='BulkSpamAction'; Kind='Enumeration'; Standard='MoveToJmf'; Strict='Quarantine'
            ValidValues=@('AddXHeader','Delete','ModifySubject','MoveToJmf','NoAction','Quarantine','Redirect')
            Rationale='Compare the action for the bulk verdict with the selected Microsoft profile.'
            Limitation=$bulkLimit+' Quarantine behavior is not assessed.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-QUARANTINE-RETENTION'; Name='Inbound quarantine retention period'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='QuarantineRetentionPeriod'; Kind='IntegerExact'; Standard=30; Strict=30; Minimum=1; Maximum=30
            Rationale='Both Microsoft profiles retain quarantined spam for 30 days; compare the exact stored duration.'
            Limitation=$policyLimit+' Quarantine tag names select access and notification policies, not this duration. Anti-phishing retention depends on the recipient''s first matching anti-spam policy; that applied policy and actual message expiry are not verified. Zero is outside the valid 1 to 30 day range, not a service-default value.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-SAFETY-TIPS'; Name='Inbound spam safety tips'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='InlineSafetyTipsEnabled'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both Microsoft profiles enable spam safety tips.'
            Limitation=$policyLimit+' The switch does not verify that a tip is rendered for a message or supported client.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-PHISH-ZAP'; Name='Inbound phishing zero-hour auto purge switch'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='PhishZapEnabled'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both Microsoft profiles enable the phishing ZAP switch in anti-spam policies.'
            Limitation=$zapLimit+' This is separate from SpamZapEnabled and is not evidence of a high-confidence-phishing purge.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-ZAP'; Name='Inbound spam zero-hour auto purge switch'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='SpamZapEnabled'; Kind='Boolean'; Standard=$true; Strict=$true
            Rationale='Both Microsoft profiles enable the spam ZAP switch in anti-spam policies.'
            Limitation=$zapLimit+' Spam ZAP considers unread spam; this switch does not describe phishing ZAP.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-ALLOWED-SENDERS'; Name='Inbound allowed senders'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='AllowedSenders'; Kind='EmptyList'; Standard=@(); Strict=@()
            Rationale='Both Microsoft profiles leave the sender allow list empty to avoid these filtering exceptions.'
            Limitation=$policyLimit+' Entries require business review, not automatic removal. This list does not describe every filtering bypass or the Tenant Allow/Block List.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-ALLOWED-DOMAINS'; Name='Inbound allowed sender domains'
            SourceId='exchange-antispam-policies'; Target='Get-HostedContentFilterPolicy'
            Field='AllowedSenderDomains'; Kind='EmptyList'; Standard=@(); Strict=@()
            Rationale='Both Microsoft profiles leave the sender-domain allow list empty to avoid broad filtering exceptions.'
            Limitation=$policyLimit+' Entries require business review, not automatic removal. An empty list does not verify domain authentication or the Tenant Allow/Block List.'
            Reference=$inboundReference; Access=$access; Section='Inbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-EXTERNAL-LIMIT'; Name='Outbound external recipients per hour'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='RecipientLimitExternalPerHour'; Kind='IntegerExact'; Standard=500; Strict=400; Minimum=0; Maximum=10000; ZeroMeansUnknown=$true
            Rationale='Compare the explicit per-user external recipient limit with the exact Microsoft profile value.'
            Limitation=$sendingLimit
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-INTERNAL-LIMIT'; Name='Outbound internal recipients per hour'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='RecipientLimitInternalPerHour'; Kind='IntegerExact'; Standard=1000; Strict=800; Minimum=0; Maximum=10000; ZeroMeansUnknown=$true
            Rationale='Compare the explicit per-user internal recipient limit with the exact Microsoft profile value.'
            Limitation=$sendingLimit
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-DAILY-LIMIT'; Name='Outbound recipients per day'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='RecipientLimitPerDay'; Kind='IntegerExact'; Standard=1000; Strict=800; Minimum=0; Maximum=10000; ZeroMeansUnknown=$true
            Rationale='Compare the explicit per-user daily recipient limit with the exact Microsoft profile value.'
            Limitation=$sendingLimit
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-LIMIT-ACTION'; Name='Outbound recipient-limit action'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='ActionWhenThresholdReached'; Kind='Enumeration'; Standard='BlockUser'; Strict='BlockUser'
            ValidValues=@('Alert','BlockUserForToday','BlockUser')
            Rationale='Both Microsoft profiles restrict sending after a recipient limit is reached, rather than only for the rest of the day.'
            Limitation=$outboundLimit+' This does not verify recipient-limit values, alert policies or that a user has actually been restricted.'
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-FORWARDING'; Name='Outbound automatic external forwarding'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='AutoForwardingMode'; Kind='Enumeration'; Standard='Off'; Strict='Off'
            ValidValues=@('Automatic','Off','On')
            Rationale='Both Microsoft profiles explicitly disable automatic external forwarding; Automatic is not treated as equivalent to Off.'
            Limitation=$outboundLimit+' Automatic can behave differently by organization. Mailbox settings, remote domains, transport rules, internal forwarding and message outcomes are not evaluated.'
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        },
        [pscustomobject]@{
            Id='EOP-SPAM-OUTBOUND-LEGACY-NOTIFY'; Name='Outbound legacy spam notification switch'
            SourceId='exchange-outbound-spam-policies'; Target='Get-HostedOutboundSpamFilterPolicy'
            Field='NotifyOutboundSpam'; Kind='Boolean'; Standard=$false; Strict=$false
            Rationale='Microsoft recommends the replacement User restricted from sending email alert policy instead of this legacy notification switch.'
            Limitation=$outboundLimit+' The replacement alert policy, its recipients and notification delivery are not collected or verified. A false value is not proof that administrators receive alerts. Microsoft Secure Score has a different recommendation for this legacy switch.'
            Reference=$outboundReference; Access=$access; Section='Outbound anti-spam'
        }
    )
}
