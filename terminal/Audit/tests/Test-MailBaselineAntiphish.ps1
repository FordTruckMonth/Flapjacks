#requires -Version 7.4
# Definition/registry contract tests only. No tenant access, file export or module installation.
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Ok) {
    $tests.Add([pscustomobject]@{Test=$Name;Passed=$Ok})
    if (-not $Ok) { throw "FAILED: $Name" }
}
# Traps apply before loading as well as when requesting definitions.
$script:liveCalls=0
function Get-AntiPhishPolicy { $script:liveCalls++; throw 'Unexpected tenant call' }
function Get-AntiPhishRule { $script:liveCalls++; throw 'Unexpected tenant call' }
function Connect-ExchangeOnline { $script:liveCalls++; throw 'Unexpected connection' }
function Invoke-RestMethod { $script:liveCalls++; throw 'Unexpected network call' }
function Invoke-WebRequest { $script:liveCalls++; throw 'Unexpected network call' }
$loadOutput=@(. (Join-Path $PSScriptRoot '../src/MailBaselineAntiphish.ps1'))
. (Join-Path $PSScriptRoot '../src/Catalog.ps1')
Check 'Loading definitions emits nothing and calls no provider' ($loadOutput.Count -eq 0 -and $script:liveCalls -eq 0)

# Keep the independent expected registry explicit so renamed, missing or extra controls fail.
$expected=[ordered]@{
    'MDO-PHISH-FIRST-CONTACT'=@('EnableFirstContactSafetyTips','Boolean',$true,$true,'basic')
    'MDO-PHISH-SPOOF-ACTION'=@('AuthenticationFailAction','Enumeration','MoveToJmf','Quarantine','basic')
    'MDO-PHISH-USER-PROTECTION'=@('EnableTargetedUserProtection','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-CUSTOM-DOMAIN-PROTECTION'=@('EnableTargetedDomainsProtection','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-ORGANIZATION-DOMAINS'=@('EnableOrganizationDomainsProtection','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-MAILBOX-INTELLIGENCE'=@('EnableMailboxIntelligence','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION'=@('EnableMailboxIntelligenceProtection','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-USER-SAFETY-TIP'=@('EnableSimilarUsersSafetyTips','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-DOMAIN-SAFETY-TIP'=@('EnableSimilarDomainsSafetyTips','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-UNUSUAL-CHARACTER-TIP'=@('EnableUnusualCharactersSafetyTips','Boolean',$true,$true,'impersonation')
    'MDO-PHISH-TRUSTED-SENDERS'=@('ExcludedSenders','EmptyList',@(),@(),'impersonation')
    'MDO-PHISH-TRUSTED-DOMAINS'=@('ExcludedDomains','EmptyList',@(),@(),'impersonation')
    'MDO-PHISH-USER-ACTION'=@('TargetedUserProtectionAction','Enumeration','Quarantine','Quarantine','impersonation')
    'MDO-PHISH-DOMAIN-ACTION'=@('TargetedDomainProtectionAction','Enumeration','Quarantine','Quarantine','impersonation')
    'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION'=@('MailboxIntelligenceProtectionAction','Enumeration','MoveToJmf','Quarantine','impersonation')
}
$defs=@(Get-FlapjacksMailBaselineAntiphishDefinitions)
$source=@(Get-AuditSourceCatalog | Where-Object Id -CEQ 'exchange-antiphish-policies')[0]
$sourceFields=@($source.Fields)+@($source.OptionalFields)
$recommended='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
$references=@{
    basic=$recommended+'#anti-phishing-policy-settings-for-all-cloud-mailboxes'
    impersonation=$recommended+'#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365'
}
Check 'Fifteen stable anti-phishing IDs in documented registry order' (($defs.Id -join ',') -ceq ($expected.Keys -join ',') -and $defs.Count -eq 15)
Check 'Control IDs and setting fields are unique' (@($defs.Id | Sort-Object -Unique).Count -eq 15 -and @($defs.Field | Sort-Object -Unique).Count -eq 15)
Check 'Existing source remains read-only Exchange with no Graph scopes' ($source.Target -ceq 'Get-AntiPhishPolicy' -and $source.Provider -ceq 'Exchange' -and $source.Scopes.Count -eq 0)
Check 'Wave-two action projection is optional on the existing source' (($source.OptionalFields -join ',') -ceq 'TargetedUserProtectionAction,TargetedDomainProtectionAction,MailboxIntelligenceProtectionAction')
$properties='Id,Name,SourceId,Target,Field,Kind,Standard,Strict,Rationale,Limitation,Reference,Access,Section'
foreach ($d in $defs) {
    $e=$expected[$d.Id]
    $schema=if ($d.Kind -ceq 'Enumeration') { $properties.Replace('Strict,Rationale','Strict,ValidValues,Rationale') } else { $properties }
    Check ('Closed declarative schema: '+$d.Id) ($d -is [pscustomobject] -and ($d.PSObject.Properties.Name -join ',') -ceq $schema)
    Check ('Only existing source selected or optional field: '+$d.Id) ($d.SourceId -ceq $source.Id -and $d.Target -ceq $source.Target -and $d.Field -cin $sourceFields -and $d.Field -ceq $e[0] -and $d.Kind -ceq $e[1])
    Check ('Official anchored recommendation: '+$d.Id) ($d.Reference -ceq $references[$e[4]])
    foreach ($profile in @('Standard','Strict')) {
        $v=$d.$profile; $want=$e[$(if ($profile -ceq 'Standard') { 2 } else { 3 })]
        $matches=switch ($d.Kind) {
            'Boolean' { $v -is [bool] -and $v -ceq $want }
            'Enumeration' { $v -is [string] -and $v -ceq $want }
            'EmptyList' { $null -ne $v -and $v -is [array] -and $v.Count -eq 0 }
            default { $false }
        }
        Check ('Exact documented '+$profile+' expectation: '+$d.Id) $matches
    }
    Check ('Human-readable rationale/access/section: '+$d.Id) (-not [string]::IsNullOrWhiteSpace($d.Name) -and -not [string]::IsNullOrWhiteSpace($d.Rationale) -and $d.Access -match 'Existing approved Exchange Online read access' -and $d.Section -ceq 'Anti-phishing')
    Check ('Bounded policy-snapshot limitation: '+$d.Id) ($d.Limitation -match 'disabled or unassigned' -and $d.Limitation -match 'priority' -and $d.Limitation -match 'targeting' -and $d.Limitation -match 'preset precedence' -and $d.Limitation -match 'effective recipient protection are not resolved')
    if ($e[4] -ceq 'impersonation') {
        Check ('Licensing is not inferred: '+$d.Id) ($d.Access -match 'Defender for Office 365 licensing' -and $d.Access -match 'recipient licensing are not verified')
    }
}
function Definition([string]$Id) { @($defs | Where-Object Id -CEQ $Id)[0] }
Check 'Spoof action enum contains only documented supported values' (((Definition 'MDO-PHISH-SPOOF-ACTION').ValidValues -join ',') -ceq 'MoveToJmf,Quarantine')
Check 'Unsupported tokens are not part of the spoof action domain' ('Reject' -cnotin (Definition 'MDO-PHISH-SPOOF-ACTION').ValidValues -and 'NoAction' -cnotin (Definition 'MDO-PHISH-SPOOF-ACTION').ValidValues -and 'quarantine' -cnotin (Definition 'MDO-PHISH-SPOOF-ACTION').ValidValues)
foreach ($id in @('MDO-PHISH-USER-ACTION','MDO-PHISH-DOMAIN-ACTION','MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION')) {
    $d=Definition $id
    Check ('Exact supported impersonation action enum: '+$id) (($d.ValidValues -join ',') -ceq 'NoAction,BccMessage,Delete,MoveToJmf,Quarantine,Redirect')
    Check ('Reject and unknown tokens are not impersonation actions: '+$id) ('Reject' -cnotin $d.ValidValues -and 'Unknown' -cnotin $d.ValidValues -and 'quarantine' -cnotin $d.ValidValues)
    Check ('Expected actions are members of supported domain: '+$id) ($d.Standard -cin $d.ValidValues -and $d.Strict -cin $d.ValidValues)
    Check ('Action comparison preserves old-snapshot and quarantine gaps: '+$id) ($d.Limitation -match 'Stored action only' -and $d.Limitation -match 'quarantine release rights are not collected' -and $d.Limitation -match 'older or incomplete snapshot is not assessed')
    Check ('New actions stay out of required-field completeness: '+$id) ($d.Field -cnotin $source.Fields -and $d.Field -cin $source.OptionalFields)
}
Check 'User action states enablement and protected-user dependencies' ((Definition 'MDO-PHISH-USER-ACTION').Limitation -match 'EnableTargetedUserProtection' -and (Definition 'MDO-PHISH-USER-ACTION').Limitation -match 'TargetedUsersToProtect' -and (Definition 'MDO-PHISH-USER-ACTION').Limitation -match 'TargetedUserQuarantineTag')
Check 'Domain action states custom and organization-domain dependencies' ((Definition 'MDO-PHISH-DOMAIN-ACTION').Limitation -match 'EnableTargetedDomainsProtection' -and (Definition 'MDO-PHISH-DOMAIN-ACTION').Limitation -match 'TargetedDomainsToProtect' -and (Definition 'MDO-PHISH-DOMAIN-ACTION').Limitation -match 'EnableOrganizationDomainsProtection' -and (Definition 'MDO-PHISH-DOMAIN-ACTION').Limitation -match 'TargetedDomainQuarantineTag')
Check 'Mailbox action states both required intelligence switches' ((Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION').Limitation -match 'EnableMailboxIntelligence and EnableMailboxIntelligenceProtection are both true' -and (Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION').Limitation -match 'MailboxIntelligenceQuarantineTag')
Check 'Workbook row 40 is exact only for Standard, never Strict' ((Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION').Standard -ceq 'MoveToJmf' -and (Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION').Strict -ceq 'Quarantine' -and (Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-ACTION').Limitation -match 'must not count as exact workbook-row equivalence')
Check 'Does not duplicate existing workbook spoof/threshold rows' ('EnableSpoofIntelligence' -cnotin $defs.Field -and 'PhishThresholdLevel' -cnotin $defs.Field)
Check 'Does not invent fixed business-specific target lists' ('TargetedUsersToProtect' -cnotin $defs.Field -and 'TargetedDomainsToProtect' -cnotin $defs.Field)
Check 'Does not assess fields outside selected/optional source contract' (@($defs | Where-Object Field -CNotIn $sourceFields).Count -eq 0)
Check 'First contact is not dependent on spoof switches' ((Definition 'MDO-PHISH-FIRST-CONTACT').Limitation -match 'independent of spoof')
Check 'User protection is explicitly switch-only, with list/action gaps' ((Definition 'MDO-PHISH-USER-PROTECTION').Limitation -match 'TargetedUsersToProtect' -and (Definition 'MDO-PHISH-USER-PROTECTION').Limitation -match 'empty or incomplete' -and (Definition 'MDO-PHISH-USER-PROTECTION').Limitation -match 'TargetedUserProtectionAction')
Check 'External-domain targets require organization-specific review' ((Definition 'MDO-PHISH-CUSTOM-DOMAIN-PROTECTION').Limitation -match 'TargetedDomainsToProtect' -and (Definition 'MDO-PHISH-CUSTOM-DOMAIN-PROTECTION').Limitation -match 'TargetedDomainProtectionAction')
Check 'Mailbox protection preserves dependency and action limitation' ((Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION').Limitation -match 'Depends on EnableMailboxIntelligence' -and (Definition 'MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION').Limitation -match 'MailboxIntelligenceProtectionAction')
foreach ($id in @('MDO-PHISH-USER-PROTECTION','MDO-PHISH-CUSTOM-DOMAIN-PROTECTION','MDO-PHISH-ORGANIZATION-DOMAINS','MDO-PHISH-MAILBOX-INTELLIGENCE-PROTECTION')) {
    Check ('Existing switch caveat distinguishes separate action comparison: '+$id) ((Definition $id).Limitation -match 'assessed separately when available')
}
Check 'Spoof action is not conflated with DMARC or quarantine policy' ((Definition 'MDO-PHISH-SPOOF-ACTION').Limitation -match 'HonorDmarcPolicy' -and (Definition 'MDO-PHISH-SPOOF-ACTION').Limitation -match 'DmarcQuarantineAction' -and (Definition 'MDO-PHISH-SPOOF-ACTION').Limitation -match 'SpoofQuarantineTag')
foreach ($id in @('MDO-PHISH-TRUSTED-SENDERS','MDO-PHISH-TRUSTED-DOMAINS')) {
    Check ('Exception differences are review, not automatic remediation: '+$id) ((Definition $id).Limitation -match 'false positives' -and (Definition $id).Limitation -match 'not automatic removal')
}
$before=@(Get-FlapjacksMailBaselineAntiphishDefinitions) | ConvertTo-Json -Depth 10
$defs[0].Standard=$false; $defs[0].Target='Set-AntiPhishPolicy'; $defs[10].Standard=@('attacker.invalid')
$defs[12].ValidValues[0]='Reject'
$fresh=@(Get-FlapjacksMailBaselineAntiphishDefinitions)
Check 'Caller mutation cannot alter later definitions or empty-list expectations' (($fresh | ConvertTo-Json -Depth 10) -ceq $before)
Check 'No live calls while loading or enumerating definitions' ($script:liveCalls -eq 0)
$tests | Format-Table -AutoSize
Write-Output ('PASS: '+$tests.Count+' offline anti-phishing definition/registry assertions; no tenant access or exports.')
