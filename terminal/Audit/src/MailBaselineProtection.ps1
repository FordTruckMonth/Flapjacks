#requires -Version 7.4
# Fixed recommendation data only. Dot-sourcing never collects, authenticates or exports.
# Microsoft Learn recommendations reviewed 2026-11-17. A null profile value is
# deliberately unassessed, not false and not an inferred Standard/Strict setting.
function Get-FlapjacksMailBaselineProtectionDefinitions {
    $recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    $policyLimit='Stored policy settings only, including disabled or unassigned policies. Rule state, priority, preset precedence, recipients and exclusions are not resolved; this does not establish effective recipient protection.'
    $defenderLimit=$policyLimit+' Built-in protection policies are not evidence of a matching Standard or Strict policy.'
    $linkAccess='Existing Exchange read access to Get-SafeLinksPolicy, appropriate RBAC and eligible Defender for Office 365 service. No new access is requested.'
    $attachmentAccess='Existing Exchange read access to Get-SafeAttachmentPolicy, appropriate RBAC and eligible Defender for Office 365 service. No new access is requested.'
    $malwareAccess='Existing Exchange read access to Get-MalwareFilterPolicy and appropriate Exchange Online Protection service and RBAC. No new access is requested.'
    $organizationAccess='Existing Exchange read access to Get-AtpPolicyForO365 and appropriate RBAC. Defender for Office 365 and Safe Documents have separate licensing requirements; eligibility is not established by this snapshot.'
    $organizationLimit='Organization-level configuration, not a Standard or Strict preset setting. Licensing, supported clients and actual file handling are not verified; this does not establish effective recipient protection.'
    @(
        [pscustomobject]@{
            Id='MDO-LINK-EMAIL'; Name='Safe Links email switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='EnableSafeLinksForEmail'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Microsoft recommends enabling this switch in both profiles.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-INTERNAL'; Name='Safe Links internal-mail switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='EnableForInternalSenders'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles include internal mail; the Built-in protection value differs.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-SCAN'; Name='Safe Links URL-scanning switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='ScanUrls'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable URL scanning.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-WAIT'; Name='Safe Links scan-before-delivery switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='DeliverMessageAfterScan'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles wait for URL scanning before delivery.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-REWRITE'; Name='Safe Links URL-rewrite configuration'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='DisableUrlRewrite'; Kind='Boolean'; ValidValues=@(); Standard=$false; Strict=$false
            Rationale='Both profiles leave URL rewriting enabled, unlike Built-in protection.'
            Limitation=$defenderLimit+' DoNotRewriteUrls exceptions are not scored; Microsoft gives no specific recommendation for that list.'
            Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-TEAMS'; Name='Safe Links Teams switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='EnableSafeLinksForTeams'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable the Teams switch.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-OFFICE'; Name='Safe Links Office-app switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='EnableSafeLinksForOffice'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable the Office-app switch.'
            Limitation=$defenderLimit+' Supported-client availability is not tested.'
            Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-TRACK'; Name='Safe Links click-tracking switch'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='TrackClicks'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable click tracking.'
            Limitation=$defenderLimit+' No click telemetry is collected or validated.'
            Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-LINK-CLICKTHROUGH'; Name='Safe Links click-through configuration'; SourceId='exchange-safe-links-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeLinksPolicy'; Field='AllowClickThrough'; Kind='Boolean'; ValidValues=@(); Standard=$false; Strict=$false
            Rationale='Both profiles disable click-through, unlike Built-in protection.'
            Limitation=$defenderLimit; Reference=$recommended+'#safe-links-policy-settings'; Access=$linkAccess; Section='Safe Links'
        },
        [pscustomobject]@{
            Id='MDO-ATTACH-ENABLE'; Name='Safe Attachments scanning switch'; SourceId='exchange-safe-attachments-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeAttachmentPolicy'; Field='Enable'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable scanning and select Block.'
            Limitation=$defenderLimit+' This switch is separate from the associated rule being enabled.'
            Reference=$recommended+'#safe-attachments-policy-settings'; Access=$attachmentAccess; Section='Safe Attachments'
        },
        # Enum domain: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-safeattachmentpolicy?view=exchange-ps#-action
        [pscustomobject]@{
            Id='MDO-ATTACH-ACTION'; Name='Safe Attachments stored response'; SourceId='exchange-safe-attachments-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeAttachmentPolicy'; Field='Action'; Kind='Enumeration'; ValidValues=@('Allow','Block','DynamicDelivery'); Standard='Block'; Strict='Block'
            Rationale='Both profiles select Block.'
            Limitation=$defenderLimit+' Action applies only when Enable is true; matching Action alone does not establish scanning.'
            Reference=$recommended+'#safe-attachments-policy-settings'; Access=$attachmentAccess; Section='Safe Attachments'
        },
        [pscustomobject]@{
            Id='MDO-ATTACH-REDIRECT'; Name='Safe Attachments redirection switch'; SourceId='exchange-safe-attachments-policies'; ExcludeBuiltIn=$true
            Target='Get-SafeAttachmentPolicy'; Field='Redirect'; Kind='Boolean'; ValidValues=@(); Standard=$false; Strict=$false
            Rationale='Both profiles disable redirection.'
            Limitation=$defenderLimit+' Redirection applies only to the Allow response. RedirectAddress is not assessed.'
            Reference=$recommended+'#safe-attachments-policy-settings'; Access=$attachmentAccess; Section='Safe Attachments'
        },
        # Enum domain: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-malwarefilterpolicy?view=exchange-ps#-filetypeaction
        [pscustomobject]@{
            Id='EOP-MALWARE-FILE-ACTION'; Name='Common-attachment filter stored response'; SourceId='exchange-malware-policies'
            Target='Get-MalwareFilterPolicy'; Field='FileTypeAction'; Kind='Enumeration'; ValidValues=@('Reject','Quarantine'); Standard='Reject'; Strict='Reject'
            Rationale='Both profiles select Reject for common-attachment matches.'
            Limitation=$policyLimit+' EnableFileFilter is assessed separately by EOP-FILE-FILTER. FileTypes completeness is not assessed.'
            Reference=$recommended+'#anti-malware-policy-settings'; Access=$malwareAccess; Section='Anti-malware'
        },
        [pscustomobject]@{
            Id='EOP-MALWARE-ZAP'; Name='Malware zero-hour auto-purge switch'; SourceId='exchange-malware-policies'
            Target='Get-MalwareFilterPolicy'; Field='ZapEnabled'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable malware ZAP.'
            Limitation=$policyLimit+' No detection, purge or mailbox outcomes are tested.'
            Reference=$recommended+'#anti-malware-policy-settings'; Access=$malwareAccess; Section='Anti-malware'
        },
        # These global values have a separate Built-in protection recommendation,
        # not Standard/Strict expected values. Keep them explicitly unassessed.
        [pscustomobject]@{
            Id='MDO-ORG-COLLAB'; Name='Defender collaboration-file switch'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='EnableATPForSPOTeamsODB'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null
            Rationale='Separate Built-in protection recommendation: EnableATPForSPOTeamsODB = true. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+' The separate SharePoint infected-file download restriction is not assessed here.'
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        },
        [pscustomobject]@{
            Id='MDO-ORG-SAFEDOCS'; Name='Safe Documents switch'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='EnableSafeDocs'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null
            Rationale='Separate Built-in protection recommendation: EnableSafeDocs = true. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+' Safe Documents requires eligible licensing beyond Defender for Office 365.'
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        },
        [pscustomobject]@{
            Id='MDO-ORG-SAFEDOCS-OPEN'; Name='Safe Documents click-through configuration'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='AllowSafeDocsOpen'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null
            Rationale='Separate Built-in protection recommendation: AllowSafeDocsOpen = false. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+' This switch depends on Safe Documents being available and enabled.'
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        }
    )
}
