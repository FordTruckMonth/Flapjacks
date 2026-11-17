#requires -Version 7.4
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$definitionPath=Join-Path $PSScriptRoot '../src/MailBaselineSpam.ps1'
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Ok) {
    $tests.Add([pscustomobject]@{Test=$Name;Passed=$Ok})
    if (-not $Ok) { throw "FAILED: $Name" }
}
function FieldDefinition([object[]]$Definitions,[string]$Field) {
    $matches=@($Definitions | Where-Object Field -CEQ $Field)
    if ($matches.Count -ne 1) { throw "Expected exactly one definition for $Field" }
    return $matches[0]
}

# Definitions must be pure data; traps also guard dot-sourcing and repeated calls.
$script:liveCalls=0
function Get-HostedContentFilterPolicy { $script:liveCalls++; throw 'Unexpected live policy collection' }
function Get-HostedOutboundSpamFilterPolicy { $script:liveCalls++; throw 'Unexpected live policy collection' }
function Get-HostedContentFilterRule { $script:liveCalls++; throw 'Unexpected live rule collection' }
function Get-HostedOutboundSpamFilterRule { $script:liveCalls++; throw 'Unexpected live rule collection' }
function Connect-ExchangeOnline { $script:liveCalls++; throw 'Unexpected authentication' }
function Invoke-RestMethod { $script:liveCalls++; throw 'Unexpected network request' }
function Invoke-WebRequest { $script:liveCalls++; throw 'Unexpected network request' }
. $definitionPath
. (Join-Path $PSScriptRoot '../src/Catalog.ps1')

$definitions=@(Get-FlapjacksMailBaselineSpamDefinitions)
$catalog=@(Get-AuditSourceCatalog)
Check 'Eighteen fixed anti-spam controls' ($definitions.Count -eq 18)
Check 'Twelve inbound and six outbound controls' (@($definitions | Where-Object Section -CEQ 'Inbound anti-spam').Count -eq 12 -and @($definitions | Where-Object Section -CEQ 'Outbound anti-spam').Count -eq 6)
Check 'Unique stable anti-spam IDs' (@($definitions.Id | Sort-Object -Unique).Count -eq 18 -and @($definitions | Where-Object Id -CNotMatch '^EOP-SPAM-[A-Z-]+$').Count -eq 0)

$expected=[ordered]@{
    BulkThreshold=@{Id='EOP-SPAM-BULK-THRESHOLD';Kind='IntegerExact';Standard=6;Strict=5}
    SpamAction=@{Id='EOP-SPAM-ACTION';Kind='Enumeration';Standard='MoveToJmf';Strict='Quarantine'}
    HighConfidenceSpamAction=@{Id='EOP-SPAM-HIGH-CONFIDENCE-ACTION';Kind='Enumeration';Standard='Quarantine';Strict='Quarantine'}
    PhishSpamAction=@{Id='EOP-SPAM-PHISH-ACTION';Kind='Enumeration';Standard='Quarantine';Strict='Quarantine'}
    HighConfidencePhishAction=@{Id='EOP-SPAM-HIGH-CONFIDENCE-PHISH-ACTION';Kind='Enumeration';Standard='Quarantine';Strict='Quarantine'}
    BulkSpamAction=@{Id='EOP-SPAM-BULK-ACTION';Kind='Enumeration';Standard='MoveToJmf';Strict='Quarantine'}
    QuarantineRetentionPeriod=@{Id='EOP-SPAM-QUARANTINE-RETENTION';Kind='IntegerExact';Standard=30;Strict=30}
    InlineSafetyTipsEnabled=@{Id='EOP-SPAM-SAFETY-TIPS';Kind='Boolean';Standard=$true;Strict=$true}
    PhishZapEnabled=@{Id='EOP-SPAM-PHISH-ZAP';Kind='Boolean';Standard=$true;Strict=$true}
    SpamZapEnabled=@{Id='EOP-SPAM-ZAP';Kind='Boolean';Standard=$true;Strict=$true}
    AllowedSenders=@{Id='EOP-SPAM-ALLOWED-SENDERS';Kind='EmptyList';Standard=@();Strict=@()}
    AllowedSenderDomains=@{Id='EOP-SPAM-ALLOWED-DOMAINS';Kind='EmptyList';Standard=@();Strict=@()}
    RecipientLimitExternalPerHour=@{Id='EOP-SPAM-OUTBOUND-EXTERNAL-LIMIT';Kind='IntegerExact';Standard=500;Strict=400}
    RecipientLimitInternalPerHour=@{Id='EOP-SPAM-OUTBOUND-INTERNAL-LIMIT';Kind='IntegerExact';Standard=1000;Strict=800}
    RecipientLimitPerDay=@{Id='EOP-SPAM-OUTBOUND-DAILY-LIMIT';Kind='IntegerExact';Standard=1000;Strict=800}
    ActionWhenThresholdReached=@{Id='EOP-SPAM-OUTBOUND-LIMIT-ACTION';Kind='Enumeration';Standard='BlockUser';Strict='BlockUser'}
    AutoForwardingMode=@{Id='EOP-SPAM-OUTBOUND-FORWARDING';Kind='Enumeration';Standard='Off';Strict='Off'}
    NotifyOutboundSpam=@{Id='EOP-SPAM-OUTBOUND-LEGACY-NOTIFY';Kind='Boolean';Standard=$false;Strict=$false}
}
Check 'Definitions retain stable ordering and exact field set' (($definitions.Field -join ',') -ceq ($expected.Keys -join ','))
$required=@('Id','Name','SourceId','Target','Field','Kind','Standard','Strict','Rationale','Limitation','Reference','Access','Section')
$optional=@('ValidValues','Minimum','Maximum','ZeroMeansUnknown')
$baseReference='https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
foreach ($definition in $definitions) {
    Check ('Definition is a PSCustomObject: '+$definition.Field) ($definition -is [pscustomobject])
    Check ('Required definition properties: '+$definition.Field) (@($required | Where-Object { $_ -cnotin $definition.PSObject.Properties.Name }).Count -eq 0)
    Check ('No executable or arbitrary properties: '+$definition.Field) (@($definition.PSObject.Properties.Name | Where-Object { $_ -cnotin ($required+$optional) }).Count -eq 0)
    foreach ($name in @('Name','Rationale','Limitation','Reference','Access','Section')) {
        Check ('Nonempty '+$name+': '+$definition.Field) ($definition.$name -is [string] -and -not [string]::IsNullOrWhiteSpace($definition.$name))
    }
    $mapping=$expected[$definition.Field]
    Check ('Stable ID and kind: '+$definition.Field) ($definition.Id -ceq $mapping.Id -and $definition.Kind -ceq $mapping.Kind)
    foreach ($profile in @('Standard','Strict')) {
        $actual=$definition.$profile
        $wanted=$mapping.$profile
        switch ($definition.Kind) {
            'Boolean' {
                Check ($profile+' exact Boolean: '+$definition.Field) ($actual -is [bool] -and $actual -eq $wanted)
            }
            'Enumeration' {
                Check ($profile+' exact enum: '+$definition.Field) ($actual -is [string] -and $actual -ceq $wanted)
                Check ($profile+' is accepted enum: '+$definition.Field) ($actual -cin $definition.ValidValues)
            }
            'IntegerExact' {
                Check ($profile+' exact integer: '+$definition.Field) ($actual -is [int] -and $actual -eq $wanted)
                Check ($profile+' inside documented bounds: '+$definition.Field) ($actual -ge $definition.Minimum -and $actual -le $definition.Maximum)
            }
            'EmptyList' {
                Check ($profile+' typed empty list is not unassessed null: '+$definition.Field) ($null -ne $actual -and $actual -is [array] -and $actual.Count -eq 0)
            }
            default { throw 'Unexpected comparison kind' }
        }
    }
    $source=@($catalog | Where-Object Id -CEQ $definition.SourceId)
    Check ('Existing collected source only: '+$definition.Field) ($source.Count -eq 1 -and $source[0].Provider -ceq 'Exchange' -and $source[0].Scopes.Count -eq 0)
    $projectedFields=@($source[0].Fields)
    if ($null -ne $source[0].PSObject.Properties['OptionalFields']) { $projectedFields+=@($source[0].OptionalFields) }
    Check ('Exact collected cmdlet and field: '+$definition.Field) ($source[0].Target -ceq $definition.Target -and $definition.Field -cin $projectedFields)
    $inbound=$definition.Field -cin @('BulkThreshold','SpamAction','HighConfidenceSpamAction','PhishSpamAction','HighConfidencePhishAction','BulkSpamAction','QuarantineRetentionPeriod','InlineSafetyTipsEnabled','PhishZapEnabled','SpamZapEnabled','AllowedSenders','AllowedSenderDomains')
    if ($inbound) {
        Check ('Inbound source binding and section anchor: '+$definition.Field) ($definition.SourceId -ceq 'exchange-antispam-policies' -and $definition.Target -ceq 'Get-HostedContentFilterPolicy' -and $definition.Reference -ceq ($baseReference+'#anti-spam-policy-settings'))
    } else {
        Check ('Outbound source binding and section anchor: '+$definition.Field) ($definition.SourceId -ceq 'exchange-outbound-spam-policies' -and $definition.Target -ceq 'Get-HostedOutboundSpamFilterPolicy' -and $definition.Reference -ceq ($baseReference+'#outbound-spam-policy-settings'))
        Check ('Outbound is not confused with a preset: '+$definition.Field) ($definition.Limitation -match 'not part of Standard or Strict preset')
    }
    Check ('Stored-policy and coverage limits retained: '+$definition.Field) ($definition.Limitation -match 'disabled or unassigned' -and $definition.Limitation -match 'priority' -and $definition.Limitation -match 'targeting' -and $definition.Limitation -match 'exceptions' -and $definition.Limitation -match 'preset precedence' -and $definition.Limitation -match 'effective recipient protection are not evaluated')
}

# Enums are fixed documented values, not any nonempty string. Bulk NoAction is
# documented separately and must be a known deviation, not an unknown shape.
$spamEnums='AddXHeader,Delete,ModifySubject,MoveToJmf,Quarantine,Redirect'
foreach ($field in @('SpamAction','HighConfidenceSpamAction','PhishSpamAction')) {
    Check ('Documented spam action set: '+$field) (((FieldDefinition $definitions $field).ValidValues -join ',') -ceq $spamEnums)
}
Check 'Bulk enum additionally recognizes NoAction' (((FieldDefinition $definitions 'BulkSpamAction').ValidValues -join ',') -ceq 'AddXHeader,Delete,ModifySubject,MoveToJmf,NoAction,Quarantine,Redirect')
Check 'High confidence phishing accepts only Redirect and Quarantine' (((FieldDefinition $definitions 'HighConfidencePhishAction').ValidValues -join ',') -ceq 'Redirect,Quarantine')
Check 'Exact outbound limit action enumeration' (((FieldDefinition $definitions 'ActionWhenThresholdReached').ValidValues -join ',') -ceq 'Alert,BlockUserForToday,BlockUser')
Check 'Automatic is recognized but not selected as Off' (((FieldDefinition $definitions 'AutoForwardingMode').ValidValues -join ',') -ceq 'Automatic,Off,On' -and (FieldDefinition $definitions 'AutoForwardingMode').Limitation -match 'Automatic can behave differently')

$bulk=FieldDefinition $definitions 'BulkThreshold'
Check 'Bulk threshold documented range is 1 through 9' ($bulk.Minimum -eq 1 -and $bulk.Maximum -eq 9)
Check 'Bulk threshold does not inherit outbound zero semantics' ($null -eq $bulk.PSObject.Properties['ZeroMeansUnknown'])
Check 'Bulk comparison is exact not a security ranking' ($bulk.Kind -ceq 'IntegerExact' -and $bulk.Limitation -match 'lower threshold is more aggressive' -and $bulk.Limitation -match 'not proof of weaker protection')
foreach ($field in @('BulkThreshold','BulkSpamAction')) {
    Check ('Bulk prerequisite gap explicit: '+$field) ((FieldDefinition $definitions $field).Limitation -match 'MarkAsSpamBulkMail is not collected')
}
$retention=FieldDefinition $definitions 'QuarantineRetentionPeriod'
Check 'Quarantine retention is exact thirty days with bounds one through thirty' ($retention.Kind -ceq 'IntegerExact' -and $retention.Standard -eq 30 -and $retention.Strict -eq 30 -and $retention.Minimum -eq 1 -and $retention.Maximum -eq 30)
Check 'Retention zero is invalid rather than outbound service-default semantics' ($null -eq $retention.PSObject.Properties['ZeroMeansUnknown'] -and $retention.Limitation -match 'Zero is outside the valid 1 to 30 day range')
Check 'Retention duration is distinct from quarantine access and notification tags' ($retention.Limitation -match 'Quarantine tag names select access and notification policies, not this duration')
Check 'Anti-phishing recipient retention and expiry are not inferred' ($retention.Limitation -match 'first matching anti-spam policy' -and $retention.Limitation -match 'actual message expiry are not verified')
foreach ($field in @('SpamZapEnabled','PhishZapEnabled')) {
    $definition=FieldDefinition $definitions $field
    Check ('ZAP true is only stored-switch alignment: '+$field) ($definition.Kind -ceq 'Boolean' -and $definition.Standard -eq $true -and $definition.Strict -eq $true -and $definition.Limitation -match 'Stored switch only' -and $definition.Limitation -match 'message outcomes are not verified')
    Check ('ZAP applied-policy and override limits: '+$field) ($definition.Limitation -match 'Verdict actions, allowlists and mail-flow overrides' -and $definition.Limitation -match 'applied policy' -and $definition.Limitation -match 'not malware ZAP or Teams')
}
Check 'Spam ZAP does not stand in for phishing ZAP' ((FieldDefinition $definitions 'SpamZapEnabled').Limitation -match 'unread spam' -and (FieldDefinition $definitions 'SpamZapEnabled').Limitation -match 'does not describe phishing ZAP')
Check 'Phishing ZAP is distinct from high-confidence-phishing outcomes' ((FieldDefinition $definitions 'PhishZapEnabled').Limitation -match 'separate from SpamZapEnabled' -and (FieldDefinition $definitions 'PhishZapEnabled').Limitation -match 'not evidence of a high-confidence-phishing purge')
Check 'Existing action checks identify retention as separate rather than uncollected' ((FieldDefinition $definitions 'SpamAction').Limitation -match 'Retention is a separate stored-setting comparison' -and (FieldDefinition $definitions 'SpamAction').Limitation -notmatch 'retention.*not collected')
$spamContract=@($catalog | Where-Object Id -CEQ 'exchange-antispam-policies')[0]
Check 'Three second-wave values are optional projections of the same source' ($null -ne $spamContract.PSObject.Properties['OptionalFields'] -and @(@('QuarantineRetentionPeriod','SpamZapEnabled','PhishZapEnabled') | Where-Object { $_ -cnotin $spamContract.OptionalFields }).Count -eq 0)
$outboundLimitFields=@('RecipientLimitExternalPerHour','RecipientLimitInternalPerHour','RecipientLimitPerDay')
foreach ($field in $outboundLimitFields) {
    $definition=FieldDefinition $definitions $field
    Check ('Outbound range and zero semantics: '+$field) ($definition.Minimum -eq 0 -and $definition.Maximum -eq 10000 -and $definition.ZeroMeansUnknown -is [bool] -and $definition.ZeroMeansUnknown)
    Check ('Outbound explicit exact comparison limitation: '+$field) ($definition.Kind -ceq 'IntegerExact' -and $definition.Limitation -match 'Zero selects service defaults' -and $definition.Limitation -match 'smaller explicit limit is not automatically a weaker control')
}
Check 'Zero override is limited to outbound recipient limits' (@($definitions | Where-Object { $null -ne $_.PSObject.Properties['ZeroMeansUnknown'] -and $_.Field -cnotin $outboundLimitFields }).Count -eq 0)

$legacy=FieldDefinition $definitions 'NotifyOutboundSpam'
Check 'Legacy notification choice does not prove alert coverage' ($legacy.Rationale -match 'User restricted from sending email' -and $legacy.Limitation -match 'not collected or verified' -and $legacy.Limitation -match 'not proof' -and $legacy.Limitation -match 'Secure Score')
Check 'Business-specific and no-recommendation fields are inventory only' (@($definitions | Where-Object Field -CIn @('BlockedSenders','BlockedSenderDomains','EnableLanguageBlockList','LanguageBlockList','EnableRegionBlockList','RegionBlockList','NotifyOutboundSpamRecipients')).Count -eq 0)
Check 'No evaluation of uncollected spam settings' (@($definitions | Where-Object Field -CIn @('MarkAsSpamBulkMail','SpamQuarantineTag','HighConfidenceSpamQuarantineTag','PhishQuarantineTag','HighConfidencePhishQuarantineTag','BulkQuarantineTag','BccSuspiciousOutboundMail')).Count -eq 0)

# A caller cannot change subsequent profile definitions or share enum mutations.
(FieldDefinition $definitions 'BulkThreshold').Standard=0
(FieldDefinition $definitions 'SpamAction').ValidValues[0]='Unknown'
(FieldDefinition $definitions 'AllowedSenders').Standard=@('sender@example.test')
$fresh=@(Get-FlapjacksMailBaselineSpamDefinitions)
Check 'Fresh integer values on every call' ((FieldDefinition $fresh 'BulkThreshold').Standard -eq 6)
Check 'Fresh enum arrays on every call' ((FieldDefinition $fresh 'SpamAction').ValidValues[0] -ceq 'AddXHeader')
Check 'Enum arrays not shared between controls' ((FieldDefinition $definitions 'HighConfidenceSpamAction').ValidValues[0] -ceq 'AddXHeader')
Check 'Fresh empty list on every call' ((FieldDefinition $fresh 'AllowedSenders').Standard.Count -eq 0)
$roundtrip=@($fresh | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
Check 'JSON preserves empty profile lists' ((FieldDefinition $roundtrip 'AllowedSenders').Standard -is [array] -and (FieldDefinition $roundtrip 'AllowedSenders').Standard.Count -eq 0)
Check 'JSON preserves false rather than null' ((FieldDefinition $roundtrip 'NotifyOutboundSpam').Standard -is [bool] -and -not (FieldDefinition $roundtrip 'NotifyOutboundSpam').Standard)

# Exercise the real saved-evidence evaluator, not a duplicate of its comparison logic.
. (Join-Path $PSScriptRoot '../src/Collect.ps1')
. (Join-Path $PSScriptRoot '../src/MailBaselineAntiphish.ps1')
. (Join-Path $PSScriptRoot '../src/MailBaselineProtection.ps1')
. (Join-Path $PSScriptRoot '../src/MailBaseline.ps1')
function New-SpamWaveTwoSample {
    [pscustomobject]@{Evidence=@([pscustomobject]@{
        SourceId='exchange-antispam-policies';Provider='Exchange';Target='Get-HostedContentFilterPolicy'
        Status='Collected';Count=1;MissingFields=@();MissingOptionalFields=@();CollectedAtUtc='2026-01-01T00:00:00Z'
        Items=@([pscustomobject]@{
            Identity='synthetic-inbound';BulkThreshold=6;SpamAction='MoveToJmf';HighConfidenceSpamAction='Quarantine'
            PhishSpamAction='Quarantine';HighConfidencePhishAction='Quarantine';BulkSpamAction='MoveToJmf'
            InlineSafetyTipsEnabled=$true;AllowedSenders=@();AllowedSenderDomains=@()
            QuarantineRetentionPeriod=30;SpamZapEnabled=$true;PhishZapEnabled=$true
        })
    })}
}
function Get-SpamWaveTwoRow($Result,[string]$Field,[string]$Baseline='Standard') {
    $rows=@(Get-FlapjacksMailBaselineChecks -Result $Result -Baseline $Baseline | Where-Object { $_.SourceId -ceq 'exchange-antispam-policies' -and $_.Field -ceq $Field })
    if ($rows.Count -ne 1) { throw "Expected exactly one evaluated row for $Field" }
    return $rows[0]
}
$waveTwoFields=@('QuarantineRetentionPeriod','SpamZapEnabled','PhishZapEnabled')
foreach ($profile in @('Standard','Strict')) {
    foreach ($field in $waveTwoFields) {
        $row=Get-SpamWaveTwoRow (New-SpamWaveTwoSample) $field $profile
        Check ($profile+' second-wave selected value matches: '+$field) ($row.Status -ceq 'Meets selected setting')
        Check ($profile+' field provenance retained: '+$field) ($row.EvidenceIds.Count -eq 1 -and $row.EvidenceIds[0] -ceq 'synthetic-inbound' -and $row.EvidenceTime -ceq '2026-01-01T00:00:00Z')
    }
}
foreach ($value in @(1,15,29)) {
    $sample=New-SpamWaveTwoSample; $sample.Evidence[0].Items[0].QuarantineRetentionPeriod=$value
    Check ('Known retention deviation: '+$value) ((Get-SpamWaveTwoRow $sample 'QuarantineRetentionPeriod').Status -ceq 'Needs action')
}
foreach ($value in @($null,0,-1,31,30.0,'30',$true,@(30))) {
    $sample=New-SpamWaveTwoSample; $sample.Evidence[0].Items[0].QuarantineRetentionPeriod=$value
    Check ('Retention invalid value stays unknown: '+[string]$value) ((Get-SpamWaveTwoRow $sample 'QuarantineRetentionPeriod').Status -ceq 'Not assessed')
}
$sample=New-SpamWaveTwoSample; $sample.Evidence[0].Items[0].QuarantineRetentionPeriod=[long]30
Check 'Retention accepts integral JSON roundtrip number' ((Get-SpamWaveTwoRow $sample 'QuarantineRetentionPeriod').Status -ceq 'Meets selected setting')
foreach ($field in @('SpamZapEnabled','PhishZapEnabled')) {
    $sample=New-SpamWaveTwoSample; $sample.Evidence[0].Items[0].$field=$false
    Check ('Explicit false ZAP is a stored-setting deviation: '+$field) ((Get-SpamWaveTwoRow $sample $field).Status -ceq 'Needs action')
    foreach ($value in @($null,0,1,'true','false',@($true))) {
        $sample=New-SpamWaveTwoSample; $sample.Evidence[0].Items[0].$field=$value
        Check ('ZAP malformed value stays unknown: '+$field+' '+[string]$value) ((Get-SpamWaveTwoRow $sample $field).Status -ceq 'Not assessed')
    }
    $sample=New-SpamWaveTwoSample
    $sample.Evidence[0].Items[0].SpamAction='Delete'; $sample.Evidence[0].Items[0].PhishSpamAction='Redirect'
    $row=Get-SpamWaveTwoRow $sample $field
    Check ('ZAP switch alignment does not claim action effectiveness: '+$field) ($row.Status -ceq 'Meets selected setting' -and $row.Limitation -match 'message outcomes are not verified')
}

# Older snapshots remain useful for first-wave controls without invented defaults.
$sample=New-SpamWaveTwoSample
foreach ($field in $waveTwoFields) { $sample.Evidence[0].Items[0].PSObject.Properties.Remove($field) }
foreach ($field in $waveTwoFields) {
    Check ('Absent second-wave field stays unknown: '+$field) ((Get-SpamWaveTwoRow $sample $field).Status -ceq 'Not assessed')
}
Check 'Older snapshot still evaluates previously collected spam action' ((Get-SpamWaveTwoRow $sample 'SpamAction').Status -ceq 'Meets selected setting')
$sample.Evidence[0].MissingOptionalFields=$waveTwoFields
Check 'Missing optional fields do not suppress first-wave action' ((Get-SpamWaveTwoRow $sample 'SpamAction').Status -ceq 'Meets selected setting')
foreach ($field in $waveTwoFields) {
    $sample=New-SpamWaveTwoSample; $sample.Evidence[0].Status='Partial'
    Check ('Incomplete source stays unknown for '+$field) ((Get-SpamWaveTwoRow $sample $field).Status -ceq 'Not assessed')
    Check ('No chosen profile stays unknown for '+$field) ((Get-SpamWaveTwoRow (New-SpamWaveTwoSample) $field 'None').Status -ceq 'Not assessed')
}
$sample=New-SpamWaveTwoSample
$sample.Evidence[0].Items[0] | Add-Member -NotePropertyName SpamQuarantineTag -NotePropertyValue 'Synthetic custom quarantine access'
Check 'Custom quarantine tag does not override stored retention comparison' ((Get-SpamWaveTwoRow $sample 'QuarantineRetentionPeriod').Status -ceq 'Meets selected setting')
$sample.Evidence[0].Items[0].QuarantineRetentionPeriod=15
Check 'Custom quarantine tag does not replace missing duration alignment' ((Get-SpamWaveTwoRow $sample 'QuarantineRetentionPeriod').Status -ceq 'Needs action')

$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($definitionPath,[ref]$tokens,[ref]$errors)
Check 'Definition file parses cleanly' (@($errors).Count -eq 0)
Check 'Definition file has no command invocations' (@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)).Count -eq 0)
Check 'No live calls while loading or obtaining definitions' ($script:liveCalls -eq 0)
Write-Host ("Mail baseline anti-spam definition checks passed: {0}" -f $tests.Count)
