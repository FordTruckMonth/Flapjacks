#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../workbook-fixture/Compare-CollaborationSettings.ps1')

function New-Projection([int]$Row) {
    if ($Row -eq 140) {
        $id = 'workbook-spo-tenant'
        $target = 'Get-SPOTenant'
        $item = @{ExternalUserExpirationRequired=$true; ExternalUserExpireInDays=30}
    } else {
        $id = 'workbook-teams-protection'
        $target = 'Get-TeamsProtectionPolicy'
        $item = @{Name='Invented custom policy'; ZapEnabled=$true}
    }
    @{
        SourceId=$id; Target=$target; Group='WorkbookCollaboration'; Provider='OfflineSnapshot'
        Status='OfflineSnapshot'; CollectedAtUtc='2026-03-01T01:02:03.4567890Z'
        SnapshotComplete=$true; Count=[long]1; RequestCount=0; PageCount=[long]0
        Items=@($item); MissingFields=@()
        Provenance=@{Kind='AlreadyCollected'; ScopeVerification='Unverified'; OriginalStatus='Collected'; RequiredNativeCommand=$target}
    }
}

$script:cases = 0
function Assert-Pair([string]$Label, $Evidence, [string]$Expiry, [string]$Zap) {
    $before = ConvertTo-Json -InputObject $Evidence -Depth 12 -Compress
    $rows = @(Get-FlapjacksAdditionalCollaborationComparison -Evidence $Evidence)
    if ($rows.Count -ne 2 -or $rows[0].Row -ne 140 -or $rows[1].Row -ne 176 -or
        $rows[0].Comparison -cne $Expiry -or $rows[1].Comparison -cne $Zap) {
        throw "$Label expected $Expiry/$Zap. Got $($rows.Comparison -join '/')."
    }
    foreach ($row in $rows) {
        if (($row.PSObject.Properties.Name -join ',') -cne 'Row,Comparison') { throw 'Unexpected observation detail.' }
    }
    if ($before -cne (ConvertTo-Json -InputObject $Evidence -Depth 12 -Compress)) { throw 'Fixture was changed.' }
    $script:cases++
}

Assert-Pair 'omitted input' $null Unknown Unknown
Assert-Pair 'empty array' @() Unknown Unknown
Assert-Pair 'explicit projected singletons' @((New-Projection 176),(New-Projection 140)) Matches Matches
foreach ($row in 140,176) {
    $s = New-Projection $row
    $other = if ($row -eq 140) { New-Projection 176 } else { New-Projection 140 }
    $for140 = if ($row -eq 140) { 'Unknown' } else { 'Matches' }
    $for176 = if ($row -eq 176) { 'Unknown' } else { 'Matches' }
    foreach ($patch in @(
        @{SourceId=$s.SourceId.ToUpperInvariant()}, @{Target='Get-Other'}, @{Group='WorkbookExchange'},
        @{Provider='Exchange'}, @{Status='Collected'}, @{Status='Partial'}, @{Status='NotSelected'},
        @{Status='AccessDenied'}, @{Status='Unavailable'}, @{SnapshotComplete=$false}, @{SnapshotComplete='true'},
        @{Count='1'}, @{Count=[decimal]1}, @{Count=$true}, @{Count=0}, @{Items=@()}, @{Items=@(@{},@{})},
        @{Items=@($null)}, @{Items=@{}}, @{MissingFields=$null}, @{MissingFields='non-array'},
        @{RequestCount=1}, @{PageCount='0'}, @{PageCount=$false}, @{Command='Get-Other'},
        @{RequiredNativeCommand='Get-Other'}, @{Provenance=@{}}, @{Provenance='text'},
        @{CollectedAtUtc='12:00Z'}, @{CollectedAtUtc='2026-02-30T01:02:03Z'},
        @{CollectedAtUtc='2026-03-01T01:02:03-01:00'}, @{CollectedAtUtc='2026-03-01T01:02:03'},
        @{CollectedAtUtc="2026-03-01T01:02:03Z`n"}
    )) {
        $s = New-Projection $row
        foreach ($k in $patch.Keys) { $s[$k] = $patch[$k] }
        Assert-Pair "row $row incompatible $($patch.Keys)" @($s,$other) $for140 $for176
    }
    foreach ($key in 'Kind','ScopeVerification','OriginalStatus','RequiredNativeCommand','Command') {
        $s = New-Projection $row
        $s.Provenance[$key] = 'Contradictory'
        Assert-Pair "row $row inconsistent provenance $key" @($s,$other) $for140 $for176
    }
    $s = New-Projection $row
    foreach ($key in 'Group','SnapshotComplete','CollectedAtUtc','MissingFields','Provenance') {
        $without = $s.Clone()
        $without.Remove($key)
        Assert-Pair "row $row requires $key" @($without,$other) $for140 $for176
    }
    $duplicate = @{SourceId=$s.SourceId.ToUpperInvariant()}
    Assert-Pair "row $row duplicate malformed record" @($duplicate,$other,$s) $for140 $for176
    Assert-Pair "row $row duplicate complete record" @($s,$other,$s) $for140 $for176
    $s.Command = $s.Target
    $s.RequiredNativeCommand = $s.Target
    $s.Provenance.Command = $s.Target
    $s.CollectedAtUtc = '2026-03-01T01:02:03+00:00'
    Assert-Pair "row $row matching aliases and UTC offset" @($s,$other) Matches Matches
}

$s = New-Projection 140
$z = New-Projection 176
$s.Remove('RequestCount')
$s.Remove('PageCount')
Assert-Pair 'optional zero counters for guest expiry' @($s,$z) Matches Matches
foreach ($key in 'RequestCount','PageCount') {
    $zap = $z.Clone()
    $zap.Remove($key)
    Assert-Pair "required zero $key for Teams policy" @($s,$zap) Matches Unknown
}
foreach ($days in 30,[long]90,730) {
    $s.Items[0].ExternalUserExpireInDays = $days
    Assert-Pair "valid active duration $days" @($s,$z) Matches Matches
}
foreach ($days in -1,0,29,731,[long]2147483648,[decimal]30,'90',$true,$null,@(180),@{Days=90}) {
    $s.Items[0].ExternalUserExpireInDays = $days
    Assert-Pair 'invalid active duration' @($s,$z) Unknown Matches
}
$s = New-Projection 140
$s.Items[0].ExternalUserExpirationRequired = $false
$s.Items[0].Remove('ExternalUserExpireInDays')
$s.MissingFields = @('ExternalUserExpireInDays')
Assert-Pair 'disabled switch, dormant duration absent' @($s,$z) Differs Matches
foreach ($raw in 'false',0,$null,@($false)) {
    $s.Items[0].ExternalUserExpirationRequired = $raw
    Assert-Pair 'malformed expiry switch' @($s,$z) Unknown Matches
}
$s = New-Projection 140
foreach ($field in 'ExternalUserExpirationRequired','  externaluserexpireindays  ','',$null) {
    $s.MissingFields = @($field)
    Assert-Pair 'unavailable active field' @($s,$z) Unknown Matches
}
$s.MissingFields = @('DisallowInfectedFileDownload')
Assert-Pair 'unrelated projected omissions' @($s,$z) Matches Matches
$s.Items[0].OverrideTenantExternalUserExpirationPolicy = $true
$s.Items[0].ExternalUserExpirationInDays = 0
Assert-Pair 'site exception outside tenant-default comparison' @($s,$z) Matches Matches
$s.Items[0].Remove('ExternalUserExpireInDays')
$s.Items[0].RequireAnonymousLinksExpireInDays = 60
Assert-Pair 'site or link duration cannot substitute' @($s,$z) Unknown Matches

$s = New-Projection 140
$z = New-Projection 176
$z.Items[0].ExceptIfRecipientDomainIs = @('invented.invalid')
$z.Items[0].ZapEnabled = $false
Assert-Pair 'stored policy false, exception present' @($s,$z) Matches Differs
foreach ($name in '', ' ', $null, @('Invented'), 1) {
    $z.Items[0].Name = $name
    Assert-Pair 'missing or mistyped policy name' @($s,$z) Matches Unknown
}
$z = New-Projection 176
foreach ($enabled in 1,0,'true','false',$null,@($true)) {
    $z.Items[0].ZapEnabled = $enabled
    Assert-Pair 'mistyped stored ZAP switch' @($s,$z) Matches Unknown
}
$z = New-Projection 176
$z.MissingFields = @('Unrelated')
Assert-Pair 'incomplete policy projection' @($s,$z) Matches Unknown
foreach ($cmd in 'Get-MalwareFilterPolicy','Get-HostedContentFilterPolicy','Get-TeamsProtectionPolicyRule','Get-CsTeamsClientConfiguration') {
    $z = New-Projection 176
    $z.Target = $cmd
    $z.Provenance.RequiredNativeCommand = $cmd
    Assert-Pair "unrelated command $cmd" @($s,$z) Matches Unknown
}
Write-Output "PASS $script:cases projected collaboration fixture cases, with expected results for both rows in each case."
