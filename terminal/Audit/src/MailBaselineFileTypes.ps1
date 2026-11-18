#requires -Version 7.4
# Fixed recommendation data only. Dot-sourcing never collects, authenticates or exports.
# Microsoft Learn common-attachment defaults reviewed 2026-11-17. The default
# list applies to both Standard and Strict; it is not an exhaustive threat list.
function Get-FlapjacksMailBaselineFileTypesDefinitions {
    # https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies
    # Keep the reviewed defaults fixed here; never obtain them from a live tenant.
    $defaultFileTypes=@(
        'ace','ani','apk','app','appx','arj','bat','cab','cmd','com','deb','dex','dll',
        'docm','elf','exe','hta','img','iso','jar','jnlp','kext','lha','lib','library',
        'lnk','lzh','macho','msc','msi','msix','msp','mst','pif','ppa','ppam','reg',
        'rev','scf','scr','sct','sys','uif','vb','vbe','vbs','vxd','wsc','wsf','wsh',
        'xll','xz','z'
    )
    [pscustomobject]@{
        Id='EOP-MALWARE-FILE-TYPES'; Name='Common-attachment stored default file-type coverage'; SourceId='exchange-malware-policies'
        Target='Get-MalwareFilterPolicy'; Field='FileTypes'; Kind='ContainsAllFileTypes'; ValidValues=@(); Standard=@($defaultFileTypes); Strict=@($defaultFileTypes)
        Rationale='Microsoft documents these 53 default file types for both Standard and Strict. This coverage comparison requires every documented default, while permitting additional configured file types.'
        Limitation='Stored policy settings only, including disabled or unassigned policies. EnableFileFilter is assessed separately by EOP-FILE-FILTER; FileTypeAction is assessed separately by EOP-MALWARE-FILE-ACTION. Rule enablement, priority, preset precedence, recipient targeting and exclusions are not resolved; this does not establish effective recipient protection. Workbook row 168 remains partial: these defaults are not a comprehensive dangerous-extension list and do not establish its custom extension list or enabled-rule requirement. Actual attachment detection, true-type matching and message handling are not tested.'
        Reference='https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies'
        Access='Existing Exchange read access to Get-MalwareFilterPolicy and appropriate Exchange Online Protection service and RBAC. No new access is requested.'
        Section='Anti-malware'
    }
}
