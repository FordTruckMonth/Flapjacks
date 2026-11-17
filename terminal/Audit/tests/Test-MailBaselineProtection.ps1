#requires -Version 7.4
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../src/Catalog.ps1')
. (Join-Path $PSScriptRoot '../src/MailBaselineProtection.ps1')
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Ok) {
    $tests.Add([pscustomobject]@{Test=$Name;Passed=$Ok})
    if (-not $Ok) { throw "FAILED: $Name" }
}
function Definition([string]$Id) { @($definitions | Where-Object Id -CEQ $Id)[0] }

# No provider action is permitted when reading the fixed recommendation registry.
$script:liveCalls=0
function Get-SafeLinksPolicy { $script:liveCalls++; throw 'Unexpected tenant read' }
function Get-SafeAttachmentPolicy { $script:liveCalls++; throw 'Unexpected tenant read' }
function Get-MalwareFilterPolicy { $script:liveCalls++; throw 'Unexpected tenant read' }
function Get-AtpPolicyForO365 { $script:liveCalls++; throw 'Unexpected tenant read' }
function Set-SafeLinksPolicy { $script:liveCalls++; throw 'Unexpected tenant write' }
function Set-SafeAttachmentPolicy { $script:liveCalls++; throw 'Unexpected tenant write' }
function Set-MalwareFilterPolicy { $script:liveCalls++; throw 'Unexpected tenant write' }
function Set-AtpPolicyForO365 { $script:liveCalls++; throw 'Unexpected tenant write' }

$definitions=@(Get-FlapjacksMailBaselineProtectionDefinitions)
Check 'Seventeen fixed protection definitions' ($definitions.Count -eq 17)
Check 'Unique fixed control IDs' (@($definitions.Id | Sort-Object -Unique).Count -eq $definitions.Count)
Check 'Only allocated control families used' (@($definitions | Where-Object Id -CNotMatch '^(MDO-LINK|MDO-ATTACH|EOP-MALWARE|MDO-ORG)-[A-Z-]+$').Count -eq 0)
Check 'Existing common-file-filter control is not duplicated' (@($definitions | Where-Object { $_.Id -eq 'EOP-FILE-FILTER' -or $_.Field -eq 'EnableFileFilter' }).Count -eq 0)

$catalog=@(Get-AuditSourceCatalog)
$sourceContract=@{
    'exchange-safe-links-policies'=@{Target='Get-SafeLinksPolicy';Section='Safe Links';Anchor='safe-links-policy-settings';Count=9}
    'exchange-safe-attachments-policies'=@{Target='Get-SafeAttachmentPolicy';Section='Safe Attachments';Anchor='safe-attachments-policy-settings';Count=3}
    'exchange-malware-policies'=@{Target='Get-MalwareFilterPolicy';Section='Anti-malware';Anchor='anti-malware-policy-settings';Count=2}
    'exchange-atp-organization'=@{Target='Get-AtpPolicyForO365';Section='Defender organization';Anchor='global-settings-for-safe-attachments';Count=3}
}
$required=@('Id','Name','SourceId','Target','Field','Kind','ValidValues','Standard','Strict','Rationale','Limitation','Reference','Access','Section')
foreach ($definition in $definitions) {
    Check ($definition.Id+' has the fixed public definition contract') ((@($definition.PSObject.Properties.Name | Where-Object { $_ -cne 'ExcludeBuiltIn' }) -join ',') -ceq ($required -join ','))
    if ($definition.SourceId -in @('exchange-safe-links-policies','exchange-safe-attachments-policies')) {
        Check ($definition.Id+' requires explicit exclusion of Built-in policy rows') ($definition.ExcludeBuiltIn -is [bool] -and $definition.ExcludeBuiltIn -eq $true)
    }
    Check ($definition.Id+' is a PSCustomObject') ($definition -is [pscustomobject])
    Check ($definition.Id+' uses an existing catalog source') $sourceContract.ContainsKey($definition.SourceId)
    $contract=$sourceContract[$definition.SourceId]
    $source=@($catalog | Where-Object Id -CEQ $definition.SourceId)[0]
    Check ($definition.Id+' has the exact catalog target and field') ($definition.Target -ceq $source.Target -and $definition.Target -ceq $contract.Target -and $source.Fields -ccontains $definition.Field)
    Check ($definition.Id+' has no added permission scopes') ($source.Scopes.Count -eq 0)
    Check ($definition.Id+' names a precise Microsoft recommendation section') ($definition.Reference -ceq ('https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#'+$contract.Anchor) -and $definition.Section -ceq $contract.Section)
    Check ($definition.Id+' includes interpretation and access limits') (-not [string]::IsNullOrWhiteSpace($definition.Rationale) -and $definition.Limitation -match 'does not establish effective recipient protection' -and $definition.Access -match 'Existing Exchange read access')
}
foreach ($sourceId in $sourceContract.Keys) {
    Check ($sourceId+' has only the intended fields') (@($definitions | Where-Object SourceId -CEQ $sourceId).Count -eq $sourceContract[$sourceId].Count)
}

$booleanExpected=@{
    'MDO-LINK-EMAIL'=@('EnableSafeLinksForEmail',$true)
    'MDO-LINK-INTERNAL'=@('EnableForInternalSenders',$true)
    'MDO-LINK-SCAN'=@('ScanUrls',$true)
    'MDO-LINK-WAIT'=@('DeliverMessageAfterScan',$true)
    'MDO-LINK-REWRITE'=@('DisableUrlRewrite',$false)
    'MDO-LINK-TEAMS'=@('EnableSafeLinksForTeams',$true)
    'MDO-LINK-OFFICE'=@('EnableSafeLinksForOffice',$true)
    'MDO-LINK-TRACK'=@('TrackClicks',$true)
    'MDO-LINK-CLICKTHROUGH'=@('AllowClickThrough',$false)
    'MDO-ATTACH-ENABLE'=@('Enable',$true)
    'MDO-ATTACH-REDIRECT'=@('Redirect',$false)
    'EOP-MALWARE-ZAP'=@('ZapEnabled',$true)
}
foreach ($id in $booleanExpected.Keys) {
    $definition=Definition $id; $expected=$booleanExpected[$id]
    Check ($id+' exactly matches both Microsoft profiles with typed Booleans') ($definition.Field -ceq $expected[0] -and $definition.Kind -ceq 'Boolean' -and $definition.Standard -is [bool] -and $definition.Strict -is [bool] -and $definition.Standard -eq $expected[1] -and $definition.Strict -eq $expected[1])
}
$action=Definition 'MDO-ATTACH-ACTION'
Check 'Safe Attachments exact Block profile and documented action domain' ($action.Field -ceq 'Action' -and $action.Kind -ceq 'Enumeration' -and $action.Standard -ceq 'Block' -and $action.Strict -ceq 'Block' -and ($action.ValidValues -join ',') -ceq 'Allow,Block,DynamicDelivery')
Check 'Safe Attachments Action cannot imply scanning on its own' ($action.Limitation -match 'only when Enable is true' -and $action.Limitation -match 'alone does not establish scanning')
$action=Definition 'EOP-MALWARE-FILE-ACTION'
Check 'Common-attachment exact Reject profile and documented action domain' ($action.Field -ceq 'FileTypeAction' -and $action.Kind -ceq 'Enumeration' -and $action.Standard -ceq 'Reject' -and $action.Strict -ceq 'Reject' -and ($action.ValidValues -join ',') -ceq 'Reject,Quarantine')
Check 'Common-attachment action defers enablement and file-list coverage' ($action.Limitation -match 'EOP-FILE-FILTER' -and $action.Limitation -match 'FileTypes completeness is not assessed')
Check 'No specific-recommendation exception or notification fields are scored' (@($definitions | Where-Object Field -in @('DoNotRewriteUrls','EnableInternalSenderAdminNotifications','EnableExternalSenderAdminNotifications','RedirectAddress')).Count -eq 0)

$organizationFields=@{
    'MDO-ORG-COLLAB'='EnableATPForSPOTeamsODB'
    'MDO-ORG-SAFEDOCS'='EnableSafeDocs'
    'MDO-ORG-SAFEDOCS-OPEN'='AllowSafeDocsOpen'
}
foreach ($id in $organizationFields.Keys) {
    $definition=Definition $id
    Check ($id+' is explicitly unassessed for Standard and Strict') ($definition.Field -ceq $organizationFields[$id] -and $definition.Kind -ceq 'Boolean' -and $null -eq $definition.Standard -and $null -eq $definition.Strict)
    Check ($id+' distinguishes its separate Built-in recommendation') ($definition.Rationale -match 'Separate Built-in protection recommendation' -and $definition.Rationale -match 'Not a Standard/Strict recommendation' -and $definition.Limitation -match 'not a Standard or Strict preset setting')
}
Check 'Safe Documents licensing is separate' ((Definition 'MDO-ORG-SAFEDOCS').Limitation -match 'licensing beyond Defender for Office 365')
Check 'Global organization values cannot silently become false recommendations' (@($definitions | Where-Object { $null -eq $_.Standard -and $null -eq $_.Strict }).Count -eq 3)
Check 'All policy checks disclaim Built-in-only profile matching' (@($definitions | Where-Object { $_.SourceId -in @('exchange-safe-links-policies','exchange-safe-attachments-policies') -and $_.Limitation -notmatch 'Built-in protection policies are not evidence of a matching Standard or Strict policy' }).Count -eq 0)

$before=Get-FlapjacksMailBaselineProtectionDefinitions | ConvertTo-Json -Depth 10 -Compress
$definitions[0].Standard=$false
(Definition 'MDO-ATTACH-ACTION').ValidValues[0]='InventedAction'
$after=Get-FlapjacksMailBaselineProtectionDefinitions | ConvertTo-Json -Depth 10 -Compress
Check 'Each call returns fresh immutable-by-convention registry data' ($before -ceq $after)
Check 'No tenant reads or writes when constructing recommendation data' ($script:liveCalls -eq 0)
$tests | Format-Table -AutoSize
Write-Output ('PASS: '+$tests.Count+' offline MailBaselineProtection registry checks; no tenant access or file exports.')
