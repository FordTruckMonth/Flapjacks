#requires -Version 7.4
# Fixed, read-only Exchange Online source contracts. Report data never supplies a cmdlet.
# This file is safe to dot-source: no authentication, collection or export is performed.
function Get-FlapjacksWorkbookExchangeSources {
    @(
        [pscustomobject]@{
            Id='exchange-unified-audit-config'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-AdminAuditLogConfig'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','UnifiedAuditLogIngestionEnabled')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-adminauditlogconfig?view=exchange-ps'
            Notes='Exchange Online REST session only. Security & Compliance PowerShell returns a misleading false value for this property. Configuration only; no audit events, searches, retention validation or ingestion test.'
        },
        [pscustomobject]@{
            Id='exchange-external-sender-tagging'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-ExternalInOutlook'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','Enabled','AllowList')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook?view=exchange-ps'
            Notes='Native external-sender identification and exceptions in supported Outlook clients only. Not transport-rule banner coverage, filtering, or proof of phishing protection.'
        },
        [pscustomobject]@{
            Id='exchange-connection-filter-policies'; Group='WorkbookExchange'; Provider='Exchange'
            Target='Get-HostedConnectionFilterPolicy'; Scopes=@(); Shape='Collection'
            Fields=@('Identity','Name','IPAllowList','IPBlockList','EnableSafeList')
            Documentation='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-hostedconnectionfilterpolicy?view=exchange-ps'
            Notes='Selected connection-filter settings only. IP lists may disclose infrastructure. Allow-list and safe-list configuration does not establish effective filtering or message outcomes.'
        }
    )
}

function Get-FlapjacksWorkbookExchangeChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        # Threshold recommendations differ by baseline. Do not silently select one.
        [ValidateSet('None','Standard','Strict')][string]$AntiPhishBaseline='None'
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    $AntiPhishBaseline=switch ($AntiPhishBaseline) { 'Standard' {'Standard'} 'Strict' {'Strict'} default {'None'} }
    function Has($Object,[string]$Name) {
        if ($null -eq $Object) { return $false }
        if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Name) }
        return $null -ne $Object.PSObject.Properties[$Name]
    }
    function Val($Object,[string]$Name,$Default=$null) {
        if (Has $Object $Name) { return ,($Object.$Name) }
        return ,$Default
    }
    function IsList($Value) {
        return $null -ne $Value -and $Value -is [Collections.IEnumerable] -and
            $Value -isnot [string] -and $Value -isnot [Collections.IDictionary]
    }
    $rows=Val $Result 'Evidence' @()
    if ($null -eq $rows -or @($rows).Count -eq 0) { $rows=Val $Result 'Coverage' @() }
    if (-not (IsList $rows) -or @($rows).Count -eq 0) {
        throw 'Full saved Evidence or Coverage source records are required; no tenant reads will be performed.'
    }
    $byId=@{}
    foreach ($row in $rows) {
        $id=Val $row 'SourceId'
        if ($id -isnot [string] -or $id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or $byId.ContainsKey($id)) {
            throw 'Invalid or duplicate source ID; combining runs requires an explicit provenance-aware report.'
        }
        $byId[$id]=$row
    }
    $cmdletRoot='https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/'
    $recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    $connectionReference='https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
    $policyLimit='Stored policy settings only. Disabled or unassigned policies are included. Preset precedence, rule enablement/priority, recipient targeting, exceptions and effective message protection are not evaluated.'
    $definitions=@(
        @{
            Id='EXO-UNIFIED-AUDIT'; Name='Unified audit ingestion configuration'; Source='exchange-unified-audit-config'
            Target='Get-AdminAuditLogConfig'; Field='UnifiedAuditLogIngestionEnabled'; Kind='Boolean'; Desired=$true; Single=$true
            Expected='UnifiedAuditLogIngestionEnabled = true.'
            Why='This selected baseline enables the unified audit ingestion switch, read through Exchange Online PowerShell rather than Security & Compliance PowerShell.'
            Limit='Does not test event ingestion, searchability, log delivery, history, retention, licensing or audited operations. Mailbox auditing is a separate setting.'
            Ref=$cmdletRoot+'get-adminauditlogconfig?view=exchange-ps'; Csf='PR.PS-04'
        },
        @{
            Id='EXO-EXTERNAL-TAG'; Name='Native Outlook external-sender identification'; Source='exchange-external-sender-tagging'
            Target='Get-ExternalInOutlook'; Field='Enabled'; Kind='Boolean'; Desired=$true; Single=$true
            Expected='Enabled = true.'
            Why='This selected baseline enables native external-sender identification in supported Outlook clients.'
            Limit='AllowList exceptions and client support affect display. Does not inspect transport-rule banners or prove phishing protection. Review existing banners before any change to avoid duplicate labels.'
            Ref=$cmdletRoot+'get-externalinoutlook?view=exchange-ps'; Csf='PR.PS-01'
        },
        @{
            Id='EXO-EXTERNAL-TAG-EXCEPTIONS'; Name='Native external-sender identification exceptions'; Source='exchange-external-sender-tagging'
            Target='Get-ExternalInOutlook'; Field='AllowList'; Kind='EmptyList'; Single=$true
            Expected='AllowList contains zero entries.'
            Why='This selected no-exceptions baseline makes native external-sender identification exceptions visible for review. Approved business exceptions require an operator decision, not automatic removal.'
            Limit='An empty list does not establish that tagging is enabled or displayed by every client. This is not a spam or phishing allow-list check.'
            Ref=$cmdletRoot+'get-externalinoutlook?view=exchange-ps'; Csf='PR.PS-01'
        },
        @{
            Id='EOP-CONNECTION-IP-ALLOW'; Name='IP Allow Lists in returned connection-filter policies'; Source='exchange-connection-filter-policies'
            Target='Get-HostedConnectionFilterPolicy'; Field='IPAllowList'; Kind='EmptyList'; Single=$false
            Expected='IPAllowList contains zero entries in every returned policy.'
            Why='This selected baseline uses no IP Allow List entries. Entries can bypass spam filtering; validate intended mail flows and approved exceptions before any change.'
            Limit='No sender, IP reputation, mail-flow, connector, DNS or message test is performed. Malware and high-confidence phishing scanning still apply to allowed IPs. IPBlockList is inventory, not a scored control.'
            Ref=$connectionReference; Csf='PR.PS-01'
        },
        @{
            Id='EOP-CONNECTION-SAFE-LIST'; Name='Safe-list switch in returned connection-filter policies'; Source='exchange-connection-filter-policies'
            Target='Get-HostedConnectionFilterPolicy'; Field='EnableSafeList'; Kind='Boolean'; Desired=$false; Single=$false
            Expected='EnableSafeList = false in every returned policy.'
            Why='This selected baseline disables the dynamic safe list that can skip spam filtering. This is an analyst-selected setting, not a claim that Microsoft recommends it for every organization.'
            Limit='The safe-list membership is service-managed and is not collected. This switch alone does not establish effective spam, phishing or malware filtering.'
            Ref=$connectionReference; Csf='PR.PS-01'
        },
        @{
            Id='EOP-SPOOF-INTELLIGENCE'; Name='Spoof-intelligence switch in returned anti-phishing policies'; Source='exchange-antiphish-policies'
            Target='Get-AntiPhishPolicy'; Field='EnableSpoofIntelligence'; Kind='Boolean'; Desired=$true; Single=$false
            Expected='EnableSpoofIntelligence = true in every returned policy.'
            Why='Microsoft lists this switch as enabled in the Default, Standard and Strict recommendations. This check compares stored values, not which policy applies to a recipient.'
            Limit=$policyLimit+' Spoof actions and DMARC behavior are separate settings.'
            Ref=$recommended+'#anti-phishing-policy-settings-for-all-cloud-mailboxes'; Csf='PR.PS-01'
        },
        @{
            Id='EOP-PHISH-THRESHOLD'; Name='Phishing threshold in returned anti-phishing policies'; Source='exchange-antiphish-policies'
            Target='Get-AntiPhishPolicy'; Field='PhishThresholdLevel'; Kind='Threshold'; Single=$false
            Expected=$(switch ($AntiPhishBaseline) { 'Standard' {'PhishThresholdLevel is 3 or 4 in every returned policy (selected Standard minimum).'} 'Strict' {'PhishThresholdLevel is 4 in every returned policy (selected Strict minimum).'} default {'Select a Standard or Strict threshold baseline before comparison.'} })
            Why='Microsoft recommends threshold 3 for Standard and 4 for Strict; the default threshold is 1. A more aggressive numeric level satisfies the selected minimum only, not the complete Microsoft preset.'
            Limit=$policyLimit+' Defender for Office 365 licensing and suitability of the selected threshold require separate review. No baseline or licensing is inferred from available policies.'
            Ref=$recommended+'#phishing-email-thresholds-in-anti-phishing-policies-in-microsoft-defender-for-office-365'; Csf='PR.PS-01'
        }
    )
    $knownStatuses=@('Collected','Partial','AccessDenied','Unauthorized','InsufficientPermissions','Unavailable','Unlicensed','Error','Throttled','NotConnected','ModuleUnavailable','NotSelected','NotProvided','TenantMismatch','IdentityMismatch','UnsupportedCloud')
    foreach ($definition in $definitions) {
        $source=$byId[$definition.Source]
        $rawStatus=Val $source 'Status' 'Missing'
        $sourceStatus=if ($rawStatus -is [string] -and $rawStatus -cin $knownStatuses) { $rawStatus } elseif ($null -eq $source) { 'Missing' } else { 'Unrecognized' }
        $status='Not assessed'; $observed='No saved source evidence was supplied.'
        $evidenceIds=[Collections.Generic.List[string]]::new()
        $items=Val $source 'Items'
        $count=Val $source 'Count'
        $missing=Val $source 'MissingFields'
        $provider=Val $source 'Provider'; $target=Val $source 'Target'
        if ($null -ne $source) {
            if ($sourceStatus -cne 'Collected') { $observed='Source is not a complete successful read.' }
            elseif ($provider -isnot [string] -or $provider -cne 'Exchange' -or $target -isnot [string] -or $target -cne $definition.Target) {
                $observed='Evidence is not bound to the expected Exchange Online provider and read cmdlet; Security & Compliance evidence is not accepted.'
            }
            elseif (-not (IsList $items)) { $observed='Source lacks a typed Items collection; summary-only coverage is not setting evidence.' }
            elseif (-not (IsList $missing) -or @($missing).Count -gt 0) { $observed='MissingFields is absent, invalid or nonempty; complete selected fields are required.' }
            elseif (($count -isnot [int] -and $count -isnot [long]) -or $count -lt 0 -or $count -ne @($items).Count) { $observed='Source Count is not a matching nonnegative integer; evidence completeness is unresolved.' }
            elseif (@($items).Count -eq 0) { $observed='Successful empty response; this does not establish applicability or a configured setting.' }
            elseif ($definition.Single -and @($items).Count -ne 1) { $observed='Expected exactly one organization settings record; multiple records are ambiguous.' }
            elseif ($definition.Kind -ceq 'Threshold' -and $AntiPhishBaseline -ceq 'None') { $observed='No threshold baseline was selected; Standard and Strict have different recommendations.' }
            else {
                $valid=$true; $matches=0; $entries=0
                foreach ($item in $items) {
                    $identity=Val $item 'Identity' (Val $item 'Name' '')
                    if ($identity -is [string] -and -not [string]::IsNullOrWhiteSpace($identity)) { $evidenceIds.Add($identity) }
                    $value=Val $item $definition.Field
                    switch ($definition.Kind) {
                        'Boolean' {
                            if ($value -isnot [bool]) { $valid=$false }
                            elseif ($value -ceq $definition.Desired) { $matches++ }
                        }
                        'EmptyList' {
                            if (-not (IsList $value)) { $valid=$false }
                            else {
                                foreach ($entry in $value) { if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace($entry)) { $valid=$false } }
                                $entries+=@($value).Count
                                if (@($value).Count -eq 0) { $matches++ }
                            }
                        }
                        'Threshold' {
                            if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1 -or $value -gt 4) { $valid=$false }
                            else {
                                $minimum=if ($AntiPhishBaseline -ceq 'Strict') { 4 } else { 3 }
                                if ($value -ge $minimum) { $matches++ }
                            }
                        }
                    }
                }
                if (-not $valid) {
                    $observed='A required field is absent, null, outside the supported range or has the wrong type; no default is inferred.'
                }
                else {
                    $status=if ($matches -eq @($items).Count) { 'Meets selected setting' } else { 'Needs action' }
                    switch ($definition.Kind) {
                        'Boolean' {
                            if ($definition.Single) { $observed=$definition.Field+' = '+(Val @($items)[0] $definition.Field).ToString().ToLowerInvariant()+'.' }
                            else { $observed=[string]$matches+' of '+@($items).Count+' returned policies have '+$definition.Field+' = '+$definition.Desired.ToString().ToLowerInvariant()+'.' }
                        }
                        'EmptyList' { $observed=[string]$entries+' total '+$definition.Field+' entries across '+@($items).Count+' returned records.' }
                        'Threshold' { $observed=[string]$matches+' of '+@($items).Count+' returned policies meet the selected '+$AntiPhishBaseline+' minimum threshold.' }
                    }
                }
            }
        }
        $stamp=Val $source 'CollectedAtUtc' ''
        if ($stamp -is [datetime] -or $stamp -is [datetimeoffset]) { $stamp=$stamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture) }
        if ($stamp -isnot [string]) { $stamp='' }
        [pscustomobject][ordered]@{
            ControlId=$definition.Id; Control=$definition.Name; Status=$status; SourceId=$definition.Source
            Field=$definition.Field; SourceStatus=$sourceStatus; EvidenceIds=$evidenceIds.ToArray(); EvidenceTime=$stamp
            Observed=$observed; Expected=$definition.Expected; Rationale=$definition.Why; Limitation=$definition.Limit; Reference=$definition.Ref
            ProfileVersion='Flapjacks workbook expansion 0.1'; NistCsf20EvidenceMapping=$definition.Csf; NistFramework='NIST CSF 2.0'
            NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
            NistMappingNote='Analyst-selected supporting evidence only; not proof of CSF outcome attainment or NIST certification.'
        }
    }
}
