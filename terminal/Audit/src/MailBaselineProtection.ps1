#requires -Version 7.4
# Fixed recommendation data only. Dot-sourcing never collects, authenticates or exports.
# Microsoft Learn recommendations reviewed 2026-11-17. A null profile value is
# not an inferred Standard/Strict setting; typed Global values are separate recommendations.
function Get-FlapjacksMailBaselineProtectionDefinitions {
    $recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    $policyLimit='Stored policy settings only, including disabled or unassigned policies. Rule state, priority, preset precedence, recipients and exclusions are not resolved; this does not establish effective recipient protection.'
    $defenderLimit=$policyLimit+' Built-in protection policies are not evidence of a matching Standard or Strict policy.'
    $linkAccess='Existing Exchange read access to Get-SafeLinksPolicy, appropriate RBAC and eligible Defender for Office 365 service. No new access is requested.'
    $attachmentAccess='Existing Exchange read access to Get-SafeAttachmentPolicy, appropriate RBAC and eligible Defender for Office 365 service. No new access is requested.'
    $malwareAccess='Existing Exchange read access to Get-MalwareFilterPolicy and appropriate Exchange Online Protection service and RBAC. No new access is requested.'
    $organizationAccess='Existing Exchange read access to Get-AtpPolicyForO365 and appropriate RBAC. No new access is requested. Defender for Office 365 and Safe Documents have separate licensing requirements; eligibility is not established by this snapshot.'
    $organizationLimit='Stored organization-level configuration from Entra-bound Exchange Online evidence only, not a Standard or Strict preset setting. Licensing and actual file handling are not verified; this does not establish effective recipient protection.'
    # Applicability: https://learn.microsoft.com/en-us/defender-office-365/safe-documents-in-e5-plus-security-about
    $safeDocumentsLimit=' Safe Documents separately requires an assigned eligible Office 365 SafeDocs (SAFEDOCS) service plan and supported Microsoft 365 Apps for enterprise clients (version 2004 or later). Defender for Office 365 Plan 1 or Plan 2 alone does not establish Safe Documents eligibility. Service-plan assignment, per-user availability and client applicability are not verified; no licensed or unlicensed verdict is inferred.'
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
            Limitation=$policyLimit+' EnableFileFilter is assessed separately by EOP-FILE-FILTER. The documented baseline type list is compared separately by EOP-MALWARE-FILE-TYPES; custom-list suitability is not assessed.'
            Reference=$recommended+'#anti-malware-policy-settings'; Access=$malwareAccess; Section='Anti-malware'
        },
        [pscustomobject]@{
            Id='EOP-MALWARE-ZAP'; Name='Malware zero-hour auto-purge switch'; SourceId='exchange-malware-policies'
            Target='Get-MalwareFilterPolicy'; Field='ZapEnabled'; Kind='Boolean'; ValidValues=@(); Standard=$true; Strict=$true
            Rationale='Both profiles enable malware ZAP.'
            Limitation=$policyLimit+' No detection, purge or mailbox outcomes are tested.'
            Reference=$recommended+'#anti-malware-policy-settings'; Access=$malwareAccess; Section='Anti-malware'
        },
        # Microsoft recommends these global values in its Built-in protection column.
        # Compare Global separately; never substitute these values into Standard/Strict.
        [pscustomobject]@{
            Id='MDO-ORG-COLLAB'; Name='Defender collaboration-file switch'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='EnableATPForSPOTeamsODB'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null; Global=$true
            Rationale='Microsoft global recommendation: EnableATPForSPOTeamsODB = true, matching the Built-in protection column. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+' The separate SharePoint infected-file download restriction is not assessed here.'
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        },
        [pscustomobject]@{
            Id='MDO-ORG-SAFEDOCS'; Name='Safe Documents switch'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='EnableSafeDocs'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null; Global=$true
            Rationale='Microsoft global recommendation: EnableSafeDocs = true, matching the Built-in protection column. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+$safeDocumentsLimit
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        },
        [pscustomobject]@{
            Id='MDO-ORG-SAFEDOCS-OPEN'; Name='Safe Documents click-through configuration'; SourceId='exchange-atp-organization'
            Target='Get-AtpPolicyForO365'; Field='AllowSafeDocsOpen'; Kind='Boolean'; ValidValues=@(); Standard=$null; Strict=$null; Global=$false
            Rationale='Microsoft global recommendation: AllowSafeDocsOpen = false, matching the Built-in protection column. Not a Standard/Strict recommendation.'
            Limitation=$organizationLimit+$safeDocumentsLimit+' This switch is meaningful only when EnableSafeDocs is true and Safe Documents is available; matching this value alone does not establish enforced blocking.'
            Reference=$recommended+'#global-settings-for-safe-attachments'; Access=$organizationAccess; Section='Defender organization'
        }
    )
}
