#requires -Version 7.4
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../src/WorkbookExchange.ps1')
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Ok) {
    $tests.Add([pscustomobject]@{Test=$Name;Passed=$Ok})
    if (-not $Ok) { throw "FAILED: $Name" }
}
function Evidence([string]$Id,[string]$Target,$Items) {
    [pscustomobject]@{
        SourceId=$Id; Provider='Exchange'; Target=$Target; Status='Collected'
        Count=@($Items).Count; Items=@($Items); MissingFields=@(); CollectedAtUtc='2026-01-01T00:00:00Z'
    }
}
function Sample {
    [pscustomobject]@{
        Metadata=[pscustomobject]@{Mode='Synthetic';RunId='synthetic-workbook-exchange'}
        Evidence=@(
            (Evidence 'exchange-unified-audit-config' 'Get-AdminAuditLogConfig' @([pscustomobject]@{Identity='synthetic-org';UnifiedAuditLogIngestionEnabled=$true})),
            (Evidence 'exchange-external-sender-tagging' 'Get-ExternalInOutlook' @([pscustomobject]@{Identity='synthetic-org';Enabled=$true;AllowList=@()})),
            (Evidence 'exchange-connection-filter-policies' 'Get-HostedConnectionFilterPolicy' @([pscustomobject]@{Identity='synthetic-default';Name='Default';IPAllowList=@();IPBlockList=@();EnableSafeList=$false})),
            (Evidence 'exchange-antiphish-policies' 'Get-AntiPhishPolicy' @(
                [pscustomobject]@{Identity='synthetic-default';EnableSpoofIntelligence=$true;PhishThresholdLevel=3},
                [pscustomobject]@{Identity='synthetic-custom';EnableSpoofIntelligence=$true;PhishThresholdLevel=4}
            ))
        )
    }
}
function By($Rows,[string]$Id) { @($Rows | Where-Object ControlId -eq $Id)[0] }
function Status($Result,[string]$Id) { (By @(Get-FlapjacksWorkbookExchangeChecks -Result $Result) $Id).Status }
function Throws([scriptblock]$Action) { try { $null=& $Action; return $false } catch { return $true } }

# Trap accidental live commands. The evaluator must consume only supplied data.
$script:liveCalls=0
function Get-AdminAuditLogConfig { $script:liveCalls++; throw 'Unexpected live command' }
function Get-ExternalInOutlook { $script:liveCalls++; throw 'Unexpected live command' }
function Get-HostedConnectionFilterPolicy { $script:liveCalls++; throw 'Unexpected live command' }
function Get-AntiPhishPolicy { $script:liveCalls++; throw 'Unexpected live command' }
function Search-UnifiedAuditLog { $script:liveCalls++; throw 'Unexpected event collection' }

$sources=@(Get-FlapjacksWorkbookExchangeSources)
Check 'Three fixed WorkbookExchange sources' ($sources.Count -eq 3)
Check 'Source IDs unique' (@($sources.Id | Sort-Object -Unique).Count -eq 3)
Check 'EXO only and no extra delegated Graph scopes' (@($sources | Where-Object { $_.Group -cne 'WorkbookExchange' -or $_.Provider -cne 'Exchange' -or $_.Shape -cne 'Collection' -or $_.Scopes.Count -ne 0 }).Count -eq 0)
$expected=@{
    'exchange-unified-audit-config'=@{Target='Get-AdminAuditLogConfig';Fields='Identity,UnifiedAuditLogIngestionEnabled'}
    'exchange-external-sender-tagging'=@{Target='Get-ExternalInOutlook';Fields='Identity,Enabled,AllowList'}
    'exchange-connection-filter-policies'=@{Target='Get-HostedConnectionFilterPolicy';Fields='Identity,Name,IPAllowList,IPBlockList,EnableSafeList'}
}
foreach ($source in $sources) {
    Check ('Fixed cmdlet and fields: '+$source.Id) ($source.Target -ceq $expected[$source.Id].Target -and ($source.Fields -join ',') -ceq $expected[$source.Id].Fields)
    Check ('Official cmdlet documentation: '+$source.Id) ($source.Documentation -ceq ('https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/'+$source.Target.ToLowerInvariant()+'?view=exchange-ps'))
}
Check 'Ingestion warning documents wrong-session false' ($sources[0].Notes -match 'Security & Compliance' -and $sources[0].Notes -match 'no audit events')
$sources[0].Target='Search-UnifiedAuditLog'
Check 'Catalog is fresh and cannot be mutated by prior output' ((@(Get-FlapjacksWorkbookExchangeSources)[0]).Target -ceq 'Get-AdminAuditLogConfig')

$r=Sample; $rows=@(Get-FlapjacksWorkbookExchangeChecks -Result $r)
Check 'Seven stable control IDs' (($rows.ControlId -join ',') -ceq 'EXO-UNIFIED-AUDIT,EXO-EXTERNAL-TAG,EXO-EXTERNAL-TAG-EXCEPTIONS,EOP-CONNECTION-IP-ALLOW,EOP-CONNECTION-SAFE-LIST,EOP-SPOOF-INTELLIGENCE,EOP-PHISH-THRESHOLD')
Check 'Six selected-setting matches, threshold left unknown by default' (@($rows | Where-Object Status -ceq 'Meets selected setting').Count -eq 6 -and (By $rows 'EOP-PHISH-THRESHOLD').Status -ceq 'Not assessed')
Check 'Unified audit observation is bounded typed value' ((By $rows 'EXO-UNIFIED-AUDIT').Observed -ceq 'UnifiedAuditLogIngestionEnabled = true.')
Check 'Exception observation is only bounded count' ((By $rows 'EXO-EXTERNAL-TAG-EXCEPTIONS').Observed -ceq '0 total AllowList entries across 1 returned records.')
Check 'Ingestion source timestamp and identity retained' ((By $rows 'EXO-UNIFIED-AUDIT').EvidenceTime -ceq '2026-01-01T00:00:00Z' -and (By $rows 'EXO-UNIFIED-AUDIT').EvidenceIds[0] -ceq 'synthetic-org')
$expectedColumns='ControlId,Control,Status,SourceId,Field,SourceStatus,EvidenceIds,EvidenceTime,Observed,Expected,Rationale,Limitation,Reference,ProfileVersion,NistCsf20EvidenceMapping,NistFramework,NistReference,NistMappingNote'
Check 'Matches posture row schema exactly' (($rows[0].PSObject.Properties.Name -join ',') -ceq $expectedColumns)
foreach ($row in $rows) {
    Check ('Closed status and official references: '+$row.ControlId) ($row.Status -cin @('Meets selected setting','Needs action','Not assessed') -and $row.Reference -like 'https://learn.microsoft.com/*' -and $row.NistReference -like 'https://csrc.nist.gov/*' -and $row.NistMappingNote -match 'not proof')
}
Check 'Ingestion limitation retains evidence gaps' ((By $rows 'EXO-UNIFIED-AUDIT').Limitation -match 'event ingestion' -and (By $rows 'EXO-UNIFIED-AUDIT').Limitation -match 'retention')
Check 'Native tagging does not claim banner coverage or anti-phish enforcement' ((By $rows 'EXO-EXTERNAL-TAG').Limitation -match 'transport-rule banners' -and (By $rows 'EXO-EXTERNAL-TAG').Limitation -match 'prove phishing protection')
Check 'IP allow-list caveat does not claim all filtering bypass' ((By $rows 'EOP-CONNECTION-IP-ALLOW').Limitation -match 'Malware and high-confidence phishing scanning still apply')
Check 'Anti-phish limit includes disabled policies and precedence' ((By $rows 'EOP-SPOOF-INTELLIGENCE').Limitation -match 'Disabled or unassigned' -and (By $rows 'EOP-SPOOF-INTELLIGENCE').Limitation -match 'Preset precedence')

foreach ($state in @('Partial','AccessDenied','Unauthorized','NotConnected','Error','Unlicensed','NotSelected','ModuleUnavailable','NotProvided','Throttled','Unavailable','InsufficientPermissions')) {
    $r=Sample; $r.Evidence[0].Status=$state
    Check ($state+' is not assessed, not failed or passed') ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
foreach ($state in @('collected','Unexpected',$null,123)) {
    $r=Sample; $r.Evidence[0].Status=$state
    $row=By @(Get-FlapjacksWorkbookExchangeChecks -Result $r) 'EXO-UNIFIED-AUDIT'
    Check ('Invalid source status remains unknown: '+[string]$state) ($row.Status -ceq 'Not assessed' -and $row.SourceStatus -ceq 'Unrecognized')
}
foreach ($provider in @('Purview','Graph','exchange','',$null)) {
    $r=Sample; $r.Evidence[0].Provider=$provider; $r.Evidence[0].Items[0].UnifiedAuditLogIngestionEnabled=$false
    Check ('False from wrong provider is never an ingestion failure: '+[string]$provider) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].PSObject.Properties.Remove('Provider')
Check 'Missing provider does not silently accept ingestion evidence' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
foreach ($target in @('Search-UnifiedAuditLog','Get-OrganizationConfig','get-adminauditlogconfig','',$null)) {
    $r=Sample; $r.Evidence[0].Target=$target
    Check ('Wrong or absent cmdlet provenance is unknown: '+[string]$target) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].Items[0].UnifiedAuditLogIngestionEnabled=$false
Check 'Explicit false in correct EXO source needs action' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Needs action')
foreach ($value in @('false','true',0,1,$null,@($true))) {
    $r=Sample; $r.Evidence[0].Items[0].UnifiedAuditLogIngestionEnabled=$value
    Check ('Non-Boolean never coerced: '+[string]$value) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].Items[0].PSObject.Properties.Remove('UnifiedAuditLogIngestionEnabled')
Check 'Missing ingestion property is unknown' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
foreach ($value in @($true,1.0,'1',-1,2,$null)) {
    $r=Sample; $r.Evidence[0].Count=$value
    Check ('Count must be matching nonnegative integer: '+[string]$value) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].PSObject.Properties.Remove('Count')
Check 'Missing Count is unknown' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
$r=Sample; $r.Evidence[0].Count=[long]1
Check 'Long integer Count supported after JSON roundtrip' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Meets selected setting')
$r=Sample; $r.Evidence[0].Items=@(); $r.Evidence[0].Count=0
Check 'Successful empty singleton is not assessed, not N/A' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
$r=Sample; $r.Evidence[0].Items+=@($r.Evidence[0].Items[0]); $r.Evidence[0].Count=2
Check 'Multiple singleton results remain ambiguous' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
foreach ($value in @($null,'bad',@{Identity='fake'},[pscustomobject]@{Identity='fake'})) {
    $r=Sample; $r.Evidence[0].Items=$value
    Check ('Items shape checked: '+[string]$value) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].PSObject.Properties.Remove('Items')
Check 'Summary-only source is not assessed' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
foreach ($value in @($null,'',@{},@('UnifiedAuditLogIngestionEnabled'))) {
    $r=Sample; $r.Evidence[0].MissingFields=$value
    Check ('MissingFields shape/completeness checked: '+[string]$value) ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[0].PSObject.Properties.Remove('MissingFields')
Check 'Absent completeness metadata is unknown' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')
$r=Sample; $r.Evidence=@($r.Evidence | Where-Object SourceId -ne 'exchange-unified-audit-config')
Check 'Absent source is not assessed' ((Status $r 'EXO-UNIFIED-AUDIT') -ceq 'Not assessed')

$r=Sample; $r.Evidence[1].Items[0].Enabled=$false
Check 'Native tags false needs selected-setting action only' ((Status $r 'EXO-EXTERNAL-TAG') -ceq 'Needs action')
$r=Sample; $r.Evidence[1].Items[0].AllowList=@('sender@example.test')
Check 'Native tag exceptions require review and do not expose addresses in observation' ((Status $r 'EXO-EXTERNAL-TAG-EXCEPTIONS') -ceq 'Needs action' -and (By @(Get-FlapjacksWorkbookExchangeChecks -Result $r) 'EXO-EXTERNAL-TAG-EXCEPTIONS').Observed -notmatch 'example.test')
foreach ($value in @($null,'sender@example.test',@{Bad='value'},@(42),@(''))) {
    $r=Sample; $r.Evidence[1].Items[0].AllowList=$value
    Check ('Invalid exception list is not assessed: '+[string]$value) ((Status $r 'EXO-EXTERNAL-TAG-EXCEPTIONS') -ceq 'Not assessed')
}
$r=Sample; $r.Evidence[1].Items[0].PSObject.Properties.Remove('AllowList')
Check 'Missing exception list not mistaken for empty' ((Status $r 'EXO-EXTERNAL-TAG-EXCEPTIONS') -ceq 'Not assessed')
$r=Sample; $r.Evidence[2].Items[0].IPAllowList=@('192.0.2.0/24'); $r.Evidence[2].Items[0].EnableSafeList=$true
Check 'IP allow-list populated needs review' ((Status $r 'EOP-CONNECTION-IP-ALLOW') -ceq 'Needs action')
Check 'Safe-list enabled needs selected-baseline review' ((Status $r 'EOP-CONNECTION-SAFE-LIST') -ceq 'Needs action')
$r=Sample; $r.Evidence[2].Items[0].IPBlockList=@('198.51.100.10')
Check 'IP block-list inventory is not erroneously scored' ((Status $r 'EOP-CONNECTION-IP-ALLOW') -ceq 'Meets selected setting')
$r=Sample; $r.Evidence[2].Items+=@([pscustomobject]@{Identity='synthetic-second';IPAllowList=@('192.0.2.10');EnableSafeList=$null}); $r.Evidence[2].Count=2
Check 'Multiple connection policies counted rather than first-only' ((Status $r 'EOP-CONNECTION-IP-ALLOW') -ceq 'Needs action')
Check 'Any missing Boolean blocks aggregate assessment' ((Status $r 'EOP-CONNECTION-SAFE-LIST') -ceq 'Not assessed')
$r=Sample; $r.Evidence[3].Items[1].EnableSpoofIntelligence=$false
Check 'Mixed stored anti-phish switches not all selected setting' ((Status $r 'EOP-SPOOF-INTELLIGENCE') -ceq 'Needs action')
$r=Sample; $r.Evidence[3].Items[1].EnableSpoofIntelligence='true'
Check 'Anti-phish string true does not coerce' ((Status $r 'EOP-SPOOF-INTELLIGENCE') -ceq 'Not assessed')
$r=Sample
Check 'Standard accepts stored integer 3 and 4 only as minimum threshold' ((By @(Get-FlapjacksWorkbookExchangeChecks -Result $r -AntiPhishBaseline Standard) 'EOP-PHISH-THRESHOLD').Status -ceq 'Meets selected setting')
Check 'Strict rejects lower stored threshold 3' ((By @(Get-FlapjacksWorkbookExchangeChecks -Result $r -AntiPhishBaseline Strict) 'EOP-PHISH-THRESHOLD').Status -ceq 'Needs action')
$r.Evidence[3].Items[0].PhishThresholdLevel=4
Check 'Strict accepts all stored integer 4 values' ((By @(Get-FlapjacksWorkbookExchangeChecks -Result $r -AntiPhishBaseline Strict) 'EOP-PHISH-THRESHOLD').Status -ceq 'Meets selected setting')
foreach ($value in @($null,'4',4.0,$true,0,5,-1)) {
    $r=Sample; $r.Evidence[3].Items[1].PhishThresholdLevel=$value
    Check ('Invalid threshold never coerced or accepted: '+[string]$value) ((By @(Get-FlapjacksWorkbookExchangeChecks -Result $r -AntiPhishBaseline Standard) 'EOP-PHISH-THRESHOLD').Status -ceq 'Not assessed')
}
Check 'Lowercase none cannot accidentally select Standard threshold' ((By @(Get-FlapjacksWorkbookExchangeChecks -Result (Sample) -AntiPhishBaseline none) 'EOP-PHISH-THRESHOLD').Status -ceq 'Not assessed')
Check 'Invalid baseline rejected' (Throws { Get-FlapjacksWorkbookExchangeChecks -Result (Sample) -AntiPhishBaseline Custom })

$r=Sample; $before=$r | ConvertTo-Json -Depth 50; $null=Get-FlapjacksWorkbookExchangeChecks -Result $r
Check 'Evaluator never mutates source evidence' (($r | ConvertTo-Json -Depth 50) -ceq $before)
$r=Sample; $json=$r | ConvertTo-Json -Depth 50
Check 'JSON deserialized evidence supported' ((Status ($json | ConvertFrom-Json -Depth 50) 'EXO-UNIFIED-AUDIT') -ceq 'Meets selected setting')
Check 'Dictionary evidence supported' ((Status ($json | ConvertFrom-Json -Depth 50 -AsHashtable) 'EXO-UNIFIED-AUDIT') -ceq 'Meets selected setting')
$r=Sample; $saved=[pscustomobject]@{Coverage=$r.Evidence}
Check 'Full Coverage fallback supported' ((Status $saved 'EXO-UNIFIED-AUDIT') -ceq 'Meets selected setting')
$r=Sample; $r.Evidence[0].CollectedAtUtc=[datetime]'2026-01-01T00:00:00Z'
Check 'DateTime timestamp serialized UTC' ((By @(Get-FlapjacksWorkbookExchangeChecks -Result $r) 'EXO-UNIFIED-AUDIT').EvidenceTime.StartsWith('2026-01-01T00:00:00'))
$r=Sample; $r.Evidence+=$r.Evidence[0]
Check 'Duplicate source records rejected' (Throws { Get-FlapjacksWorkbookExchangeChecks -Result $r })
$r=Sample; $r.Evidence[0].SourceId='EXCHANGE-UNIFIED-AUDIT-CONFIG'
Check 'Source ID domain is exact and closed' (Throws { Get-FlapjacksWorkbookExchangeChecks -Result $r })
Check 'Missing evidence refuses rather than collecting' (Throws { Get-FlapjacksWorkbookExchangeChecks -Result @{} })
Check 'No provider commands or audit-event queries invoked' ($script:liveCalls -eq 0)
$tests | Format-Table -AutoSize
Write-Output ('PASS: '+$tests.Count+' offline synthetic WorkbookExchange checks; no tenant access or file exports.')
