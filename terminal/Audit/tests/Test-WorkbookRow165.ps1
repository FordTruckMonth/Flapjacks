#requires -Version 7.4
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../workbook-fixture/WorkbookRow165.ps1')
function Sample {
    @{Mode='Synthetic';Metadata=@{Mode='Synthetic'};Evidence=@(@{SourceId='exchange-connection-filter-policies'; Group='WorkbookExchange'
        Provider='Exchange'; Target='Get-HostedConnectionFilterPolicy'; Status='Collected'
        Count=1; PageCount=1; RequestCount=0; MissingFields=@()
        Items=@(@{Name='Default'; Identity='synthetic-a'; EnableSafeList=$false
                  IPAllowList=@('192.0.2.10'); IPBlockList=@()})})}
}
$script:checks=0
function Check([string]$name, $result, [string]$expected) {
    $actual=Get-FlapjacksWorkbookRow165 -Result $result
    if ($actual.Status -cne $expected -or $actual.PhysicalRow -ne 165 -or $actual.ControlId -cne 'WB-REF-92B9-ROW-165') {
        throw "Failed $name [$($actual.Status), $($actual.ReasonCode)]"
    }
    if (($actual | ConvertTo-Json) -match '192\.0\.2|synthetic-a') { throw 'Output contained raw item data' }
    $script:checks++
    Write-Output "PASS $name"
}
$yes='Meets selected setting'; $no='Needs action'; $unknown='Not assessed'
$r=Sample
Check 'native false' $r $yes
Check 'JSON round trip' ($r | ConvertTo-Json -Depth 10 | ConvertFrom-Json) $yes
Check 'Coverage fallback' @{Metadata=$r.Metadata;Coverage=$r.Evidence} $yes
Check 'empty Evidence with full Coverage' @{Metadata=$r.Metadata;Evidence=@();Coverage=$r.Evidence} $yes
$s=$r.Evidence[0]
$s.Items[0].EnableSafeList=$true
Check 'native true' $r $no
$s.Items[0].Name='dEfAuLt'
Check 'case-independent Default' $r $no
$s.Items+=@{Identity='synthetic-b';Name='Other';EnableSafeList=$false};$s.Count=2
Check 'other policy ignored' $r $no
$s.Items=@($s.Items[1],$s.Items[0])
Check 'order independence' $r $no
$s.Items[0].Identity='SYNTHETIC-A'
Check 'duplicate opaque identity' $r $unknown
$s.Items[0].Identity='synthetic-b';$s.Items[0].Name='DEFAULT'
Check 'duplicate Default name' $r $unknown
foreach ($value in @('false',0,1,@($false),$null)) {
    $r=Sample; $r.Evidence[0].Items[0].EnableSafeList=$value
    Check 'incorrect Boolean type' $r $unknown
}
foreach ($spec in @(
    @('Status','Partial'),@('SourceId','other'),@('Group','other'),@('Provider','Graph'),
    @('Target','Get-Fake'),@('Count',$true),@('Count',0),@('Count','1'),
    @('Items','summary'),@('MissingFields',''),@('MissingFields',@('Name')),
    @('PageCount',2),@('RequestCount',2),@('PageCount','1'),@('RequestCount',$true),
    @('Continuation','next')
)) {
    $r=Sample; $r.Evidence[0][$spec[0]]=$spec[1]; Check "invalid $($spec[0])" $r $unknown
}
foreach ($key in @('Count','Items','MissingFields','Target','Provider','SourceId','Status')) {
    $r=Sample; $r.Evidence[0].Remove($key); Check "missing $key" $r $unknown
}
foreach ($key in @('Identity','Name','EnableSafeList')) {
    $r=Sample; $r.Evidence[0].Items[0].Remove($key); Check "missing item $key" $r $unknown
}
foreach ($spec in @(@('Identity',' '),@('Name','default '),@('Identity',1),@('Name',1),@('SourceId','other'))) {
    $r=Sample; $r.Evidence[0].Items[0][$spec[0]]=$spec[1]; Check "invalid item $($spec[0])" $r $unknown
}
$r=Sample;$r.Evidence[0].Items[0].Identity='Default';$r.Evidence[0].Items[0].Name='Custom'
Check 'identity alone cannot select Default' $r $unknown
$r=Sample;$r.Evidence+= $r.Evidence[0].Clone()
Check 'duplicate source' $r $unknown
$r=Sample;$r.Evidence[0].Items=@();$r.Evidence[0].Count=0
Check 'empty successful collection' $r $unknown
$r=Sample;$r.Evidence[0].MissingFields=$null
Check 'null missing field marker' $r $unknown
$r=Sample;$r.Evidence[0].Items=@(@{} | ConvertTo-Json | ConvertFrom-Json)
Check 'empty JSON record' $r $unknown
Check 'no source' $null $unknown
foreach ($key in @('Mode','TenantId','RunId')) {
    $r=Sample; $r[$key]='one'; $r.Metadata[$key]='two'; Check "conflicting $key" $r $unknown
}
$r=Sample;$r.Mode='Saved';$r.Metadata.Mode='Saved'
Check 'non-synthetic zero requests' $r $unknown
$r.Evidence[0].RequestCount=1
Check 'non-synthetic one request' $r $yes
$r.Evidence[0].Reason='Fixture evidence'
Check 'non-synthetic fixture reason' $r $unknown
$r=Sample;$r.Evidence[0].Reason='RecordLimit'; Check 'contradictory collector reason' $r $unknown
foreach ($reason in @('','Synthetic fixture, not tenant data.','Fixture evidence','Synthetic fixture')) {
    $r.Evidence[0].Reason=$reason; Check 'known fixture reason' $r $yes
}
$r=Sample;$r.Evidence[0].Items[0].Identity="opaque`tvalue";Check 'embedded control character' $r $unknown
$r=Sample;$r.Evidence+=@{SourceId='another-source'};$r.Evidence+=@{SourceId='another-source'}
Check 'duplicate unrelated source' $r $unknown
$r=Sample;$r.Evidence+=@{SourceId='MALFORMED'};Check 'invalid unrelated source' $r $unknown
$r=Sample;$r.Evidence[0].CollectedAtUtc='untrusted text'
$row=Get-FlapjacksWorkbookRow165 -Result $r
if ($row.EvidenceTime -cne '' -or $row.EvidenceIds.Count -ne 1 -or $row.EvidenceIds[0] -cne 'Default') { throw 'Unsafe evidence display fields' }
Check 'invalid timestamp omitted' $r $yes
$r.Evidence[0].CollectedAtUtc='2026-11-01T12:00:00Z'
$row=Get-FlapjacksWorkbookRow165 -Result $r
if ($row.EvidenceTime -cne '2026-11-01T12:00:00.0000000Z') { throw 'UTC timestamp normalization failed' }
Check 'normalized timestamp' $r $yes
$r=Sample;$r.Metadata.SelectedGroups=@('Core');Check 'group absent from explicit selection' $r $unknown
$r.Metadata.SelectedGroups='WorkbookExchange';Check 'scalar selection' $r $unknown
$r.Metadata.SelectedGroups=@('Core','WorkbookExchange');Check 'explicit group selection' $r $yes
Write-Output "Passed $script:checks checks on PowerShell $($PSVersionTable.PSVersion)"
