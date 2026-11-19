#requires -Version 7.4
[CmdletBinding()]
param([string]$PassiveJsonPath=(Join-Path $PSScriptRoot '../workbook-fixture/PassiveJson.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $PassiveJsonPath
. (Join-Path $PSScriptRoot '../workbook-fixture/Compare-SharePointReauthentication.ps1')
$passed = 0
$switchField = 'EmailAttestationRequired'
$daysField = 'EmailAttestationReAuthDays'
function New-Source {
    return @{
        SourceId='workbook-spo-tenant'; Target='Get-SPOTenant'; Group='WorkbookCollaboration'
        Provider='OfflineSnapshot'; Status='OfflineSnapshot'; CollectedAtUtc='2026-11-01T12:34:56Z'
        Provenance=@{Kind='AlreadyCollected'; ScopeVerification='Unverified'; OriginalStatus='Collected'; RequiredNativeCommand='Get-SPOTenant'}
        SnapshotComplete=$true; Count=1; PageCount=0; RequestCount=0; MissingFields=@()
        Items=@(@{EmailAttestationRequired=$true; EmailAttestationReAuthDays=15})
    }
}
function Json($Value) { ConvertTo-Json -InputObject $Value -Depth 30 -Compress }
function Assert-Json([string]$Name, [string]$Text, [string]$Expected) {
    $doc = [Text.Json.JsonDocument]::Parse($Text)
    try { $actual = @(Get-FlapjacksSyntheticSharePointReauthenticationComparison -ProjectedJson $doc.RootElement) }
    finally { $doc.Dispose() }
    $reason = if ($Expected -ceq 'Unknown') { 'IncompleteProjectedEvidence' } else { 'ComparedProjectedSetting' }
    if ($actual.Count -ne 1 -or $actual[0].Row -ne 141 -or $actual[0].Comparison -cne $Expected -or $actual[0].Reason -cne $reason) {
        throw "$Name expected $Expected; received $(Json $actual)."
    }
    $script:passed++
}
function Check([string]$Name, [string]$Expected, [scriptblock]$Adjust) {
    $source = New-Source
    & $Adjust $source $source.Items[0]
    Assert-Json $Name (Json @($source)) $Expected
}
$record = Json (New-Source)
foreach ($days in 1..365) {
    $expected = if ($days -le 15) { 'Matches' } else { 'Differs' }
    Check "active day $days" $expected { param($s,$item) $item[$daysField] = $days }
}
Check 'switch false without duration' Differs { param($s,$item) $item[$switchField]=$false; $item.Remove($daysField) }
Check 'disabled with a reported missing duration' Differs { param($s,$item) $item[$switchField]=$false; $s.MissingFields=@($daysField) }
Check 'missing switch' Unknown { param($s,$item) $item.Remove($switchField) }
Check 'missing duration' Unknown { param($s,$item) $item.Remove($daysField) }
Check 'ordinary product projection lacks both fields' Unknown { param($s,$item) $item.Clear(); $item['CoreDefaultShareLinkRole']='View' }
Check 'unrelated projected fields may be missing' Matches { param($s) $s.MissingFields=@('SharingCapability','CoreDefaultShareLinkScope') }
foreach ($token in '0','-1','366','9223372036854775807','15.0','1.5e1','15.5','"15"','true','null','[15]','{}') {
    $text = '[' + $record.Replace('"EmailAttestationReAuthDays":15','"EmailAttestationReAuthDays":'+$token) + ']'
    Assert-Json "invalid active interval $token" $text Unknown
    Assert-Json "dormant interval $token" ($text.Replace('"EmailAttestationRequired":true','"EmailAttestationRequired":false')) Differs
}
foreach ($token in '"true"','"false"','1','0','null','[true]','{}') {
    Assert-Json "mistyped switch $token" ('['+$record.Replace('"EmailAttestationRequired":true','"EmailAttestationRequired":'+$token)+']') Unknown
}
foreach ($field in 'SourceId','Target','Group','Provider','Status','CollectedAtUtc','SnapshotComplete','Provenance','Count','PageCount','RequestCount','Items','MissingFields') {
    Check "missing $field" Unknown { param($s) $s.Remove($field) }
}
foreach ($patch in @(
    @{SourceId='another-id'},@{SourceId='WORKBOOK-SPO-TENANT'},@{Target='Get-SPOSite'},@{Group='Core'},@{Provider='Graph'},
    @{Status='Collected'},@{Status='Partial'},@{Status='Unavailable'},@{SnapshotComplete=$false},@{SnapshotComplete=1},@{SnapshotComplete='true'},
    @{Count=2},@{Count='1'},@{PageCount=1},@{RequestCount=1},@{RequestCount='0'},@{PageCount=$false},
    @{Items=@()},@{Items=@('bad')},@{Items=@(@{},@{})},@{Items=@{}},@{MissingFields=$null},@{MissingFields=''},
    @{MissingFields=@('')},@{MissingFields=@($null)},@{MissingFields=@(' EmailAttestationRequired ')},
    @{MissingFields=@(' emailattestationreauthdays ')},@{Provenance=$null},@{Provenance=@{}},
    @{CollectedAtUtc='2026-02-30T14:11:12Z'},@{CollectedAtUtc='2026-11-01T12:34:56+01:00'},@{CollectedAtUtc='2026-11-01'},
    @{CollectedAtUtc="2026-11-01T12:34:56Z`n"},@{CollectedAtUtc='2026-11-01T12:34:56-00:00'}
)) {
    Check "bad source $($patch.Keys)" Unknown { param($s) foreach ($key in $patch.Keys) { $s[$key]=$patch[$key] } }
}
Check 'valid UTC offset' Matches { param($s) $s.CollectedAtUtc='2026-11-01T12:34:56.9999999+00:00' }
Check 'site-specific object carrying the pair' Unknown { param($s,$item) $item['Url']='https://invented.invalid/sites/fixture' }
Check 'existing tenant default fields' Matches { param($s,$item) $item['DisallowInfectedFileDownload']=$true; $item['ExternalUserExpirationRequired']=$false }
Check 'uncased field name is not the property' Unknown { param($s,$item) $item.Remove($daysField); $item['emailattestationreauthdays']=15 }
foreach ($key in 'Command','RequiredNativeCommand','NativeModule','OriginalProvider') {
    Check "wrong source $key" Unknown { param($s) $s[$key]='Get-SPOSite' }
    Check "wrong provenance $key" Unknown { param($s) $s.Provenance[$key]='Get-SPOSite' }
    $aliasValue = if ($key -in 'NativeModule','OriginalProvider') { 'Microsoft.Online.SharePoint.PowerShell' } else { 'Get-SPOTenant' }
    Check "matching aliases $key" Matches { param($s) $s[$key]=$aliasValue; $s.Provenance[$key]=$aliasValue }
}
Check 'empty diagnostic strings' Matches { param($s) $s['Reason']=''; $s['Notes']=''; $s.Provenance['Note']='' }
Check 'complete native diagnostics' Matches { param($s)
    $s['Reason']='Unverified offline scope; never a successful tenant collection. '
    $s['Notes']='Offline snapshot only. Exact current tenant and account cannot be verified by this adapter. No live collector, authentication, installation, permission grant, or coverage pass.'
    $s.Provenance['Note']='OriginalStatus and timestamp are supplier claims. RequiredNativeCommand is a requirement, not proof of execution. Tenant, account and freshness have not been verified.'
}
foreach ($diagnostic in 'truncated','verified live',$null,1,@('Invented')) {
    Check 'conflicting reason' Unknown { param($s) $s['Reason']=$diagnostic }
    Check 'conflicting notes' Unknown { param($s) $s['Notes']=$diagnostic }
    Check 'conflicting provenance note' Unknown { param($s) $s.Provenance['Note']=$diagnostic }
}
foreach ($key in 'Kind','ScopeVerification','OriginalStatus','RequiredNativeCommand') {
    Check "wrong provenance $key" Unknown { param($s) $s.Provenance[$key]='Wrong' }
    Check "missing provenance $key" Unknown { param($s) $s.Provenance.Remove($key) }
}
Assert-Json 'duplicate active interval' ('['+$record.Replace('"EmailAttestationReAuthDays":15','"EmailAttestationReAuthDays":15,"EmailAttestationReAuthDays":45')+']') Unknown
Assert-Json 'case-colliding switch' ('['+$record.Replace('"EmailAttestationRequired":true','"EmailAttestationRequired":true,"emailattestationrequired":false')+']') Unknown
Assert-Json 'absent source' '[]' Unknown
Assert-Json 'wrong wrapper' ('{"Coverage":['+$record+']}') Unknown
Assert-Json 'duplicate full source' ('['+$record+','+$record+']') Unknown
foreach ($claim in @(
    '{"SourceId":"WORKBOOK-SPO-TENANT"}','{"SourceId":" workbook-spo-tenant "}',
    '{"SourceId":"other","Target":"get-spotenant"}','{"target":"Get-SPOTenant"}',
    '{"Target":"Microsoft.Online.SharePoint.PowerShell\\Get-SPOTenant"}','{"Command":"Get-SPOTenant"}',
    '{"Provenance":{"RequiredNativeCommand":"GET-SPOTENANT"}}',
    '{"SourceId":"other","SourceId":"other2","Target":"Get-SPOTenant"}',
    '{"target":"Get-SPOTenant","Target":"Get-SPOSite"}',
    '{"Provenance":{"Command":"Get-SPOTenant"},"Provenance":{"Command":"Get-SPOSite"}}'
)) {
    Assert-Json "competing claimant $claim" ('['+$record+','+$claim+']') Unknown
    Assert-Json "reversed competing claimant $claim" ('['+$claim+','+$record+']') Unknown
}
Assert-Json 'unrelated malformed Teams record coexists' ('['+$record+',{"SourceId":"workbook-teams-client","Target":"Get-CsTeamsClientConfiguration","x":1,"x":2}]') Matches
Write-Output "PASS $passed SharePoint reauthentication fixture cases. All 365 active provider intervals checked (15 Matches, 350 Differs)."
