#requires -Version 7.4
[CmdletBinding()]
param([string]$AuditRoot=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../workbook-fixture/WorkbookRow169.ps1')
. (Join-Path $AuditRoot 'src/Collect.ps1')
$checks=[Collections.Generic.List[object]]::new()
$met='Meets selected setting'; $unmet='Needs action'; $unknown='Not assessed'
function Policy($Name='Default',$Id='sample-1') { return @{Name=$Name;Identity=$Id;IPAllowList=@();IPBlockList=@();EnableSafeList=$false} }
function Sample {
    $source=@{SourceId='exchange-connection-filter-policies';Target='Get-HostedConnectionFilterPolicy';Provider='Exchange'
        Group='WorkbookExchange';Status='Collected';MissingFields=@();Count=1;PageCount=1;RequestCount=0;Items=@((Policy))}
    return @{Metadata=@{Mode='Synthetic'}; Mode='Synthetic';Evidence=@($source)}
}
function AssertCase($Title,$InputReport,$Expected) {
    # Deliberately use both the native report and its JSON representation.
    $roundTrip=ConvertFrom-Json -InputObject (ConvertTo-Json $InputReport -Depth 20)
    foreach($record in @($InputReport,$roundTrip)){
        $r=Get-FlapjacksWorkbookRow169 -Result $record
        if ($r.Status -cne $Expected -or $r.ControlId -cne 'WB-REF-92B9-ROW-169') { throw "$Title expected $Expected, got $($r.Status) ($($r.Observed))" }
    }
    $checks.Add([pscustomobject]@{Case=$Title;Status=$Expected})
}
$x=Sample; AssertCase 'opaque identity' $x $met
$x=Sample; $x.Evidence[0].Items+=Policy 'Other' 'sample-2';$x.Evidence[0].Count=2;$x.Evidence[0].Items[1].IPAllowList=@('192.0.2.1')
AssertCase 'other policy cannot override Default' $x $met
$x.Evidence[0].Items[0].IPAllowList=@('198.51.100.1');$x.Evidence[0].Items[1].IPAllowList=@()
AssertCase 'other policy cannot mask Default' $x $unmet
$x.Evidence[0].Items[1].Name='deFaUlt'; AssertCase 'duplicate name' $x $unknown
$x.Evidence[0].Items[1].Name='Other';$x.Evidence[0].Items[1].Identity='SAMPLE-1'; AssertCase 'duplicate identity' $x $unknown
$x=Sample; $x.Evidence[0].Items[0].Name='DEFAULT';AssertCase 'case-insensitive name' $x $met
$x=Sample; $x.Evidence[0].Items[0].Name='Other';$x.Evidence[0].Items[0].Identity='Default';AssertCase 'identity cannot establish name' $x $unknown
foreach($key in @('Name','Identity')){
    foreach($v in @($null,'',' ',' Default',1,@{sample='Default'})){
        $x=Sample;$x.Evidence[0].Items[0][$key]=$v; AssertCase ("invalid {0} {1}" -f $key,$checks.Count) $x $unknown
    }
}
foreach($bad in @(
    @{Provider='Purview'},@{Target='Sample'},@{Status='Partial'},@{Status=@('Collected')},@{Group='Other'},
    @{Count='1'},@{Count=2},@{Items=@()},@{MissingFields=@('Name')},@{MissingFields=$null},
    @{PageCount=0},@{RequestCount=2},@{RequestCount='1'},@{SourceId='other'},@{Items='Summary'}
)){
    $x=Sample
    foreach($k in $bad.Keys){$x.Evidence[0][$k]=$bad[$k]}
    AssertCase ("bad source {0} {1}" -f $k,$checks.Count) $x $unknown
}
$x=Sample;$x.Evidence[0].Reason='RecordLimit';AssertCase 'contradictory reason' $x $unknown
$x=Sample;$x.Evidence[0].Reason='Synthetic fixture, not tenant data.';AssertCase 'released fixture reason' $x $met
foreach($note in @('Synthetic fixture','Fixture evidence')){
    $x=Sample;$x.Evidence[0].Reason=$note;AssertCase "known fixture note $note" $x $met
}
$x=Sample;$x.Evidence[0].Items[0].TenantId='fixture-2';AssertCase 'nested policy tenant id' $x $unknown
$x=Sample;$x.Evidence[0].TenantId='fixture-2';AssertCase 'nested source tenant id' $x $unknown
$x=Sample;$x.Remove('Mode');$x.Metadata.Mode=@('Synthetic');AssertCase 'array synthetic mode' $x $unknown
$x=Sample;$x.Metadata.SelectedGroups=@('Core');AssertCase 'contradictory group selection' $x $unknown
$x=Sample;$x.Metadata.SelectedGroups=@('Core','WorkbookExchange');AssertCase 'selected group' $x $met
$x=Sample;$x.Metadata.SelectedGroups='WorkbookExchange';AssertCase 'malformed group selection' $x $unknown
$x=Sample;$x.Mode='Live'; AssertCase 'report mode conflict' $x $unknown
$x=Sample;$x.Evidence+= $x.Evidence[0];AssertCase 'duplicated source' $x $unknown
$x=Sample;$x.Coverage=@(@{SourceId=$x.Evidence[0].SourceId});$x.Remove('Evidence');AssertCase 'summary only' $x $unknown
$x=Sample;$x.Coverage=$x.Evidence;$x.Remove('Evidence');AssertCase 'full evidence in Coverage' $x $met
$x=Sample;$x.Evidence[0].Items[0].Remove('IPAllowList');AssertCase 'missing selected field' $x $unknown
foreach($entry in @('192.0.2.1','0.0.0.0','255.255.255.255','192.0.2.1/24','192.0.2.1/32','192.0.2.0-192.0.2.255','255.255.255.254-255.255.255.255')){
    $x=Sample;$x.Evidence[0].Items[0].IPAllowList=@($entry); AssertCase "valid entry $entry" $x $unmet
}
foreach($entry in @('','junk','1.2.3','01.2.3.4','192.0.2.999','192.0.2.0/23','192.0.2.0/33','192.0.2.0/24/24',
    '192.0.2.2-192.0.2.1','192.0.2.0-192.0.3.0','2001:db8::1',1,$null,@{Address='192.0.2.1'})){
    $x=Sample;$x.Evidence[0].Items[0].IPAllowList=@('192.0.2.1',$entry)
    AssertCase ("malformed member {0}" -f $checks.Count) $x $unknown
}
$x=Sample;$x.Evidence[0].Items[0].IPAllowList='192.0.2.1';AssertCase 'scalar address' $x $unknown
$x=Sample;$x.Evidence[0].Items[0].IPAllowList=@('192.0.2.1')*1274;AssertCase 'collection over maximum' $x $unknown
foreach($case in @(
    @{Label='native empty';Value=[Collections.Generic.List[string]]::new();Expected=$met},
    @{Label='native null';Value=$null;Expected=$unknown},
    @{Label='null member';Value=@($null);Expected=$unknown},
    @{Label='invalid object member';Value=@(@{Address='192.0.2.1'});Expected=$unknown},
    @{Label='valid address';Value=@('203.0.113.1');Expected=$unmet}
)){
    $x=Sample
    $x.Evidence[0].Items[0].IPAllowList=ConvertTo-AuditCommandValue $case.Value
    AssertCase "released projection $($case.Label)" $x $case.Expected
}
$x=Sample
$o=[pscustomobject]@{Name='Default';Identity='sample-1'}
$script:accessed=$false
$o | Add-Member -MemberType ScriptProperty -Name IPAllowList -Value {$script:accessed=$true; return ,@()}
$x.Evidence[0].Items=@($o)
$guard=Get-FlapjacksWorkbookRow169 -Result $x
if ($script:accessed -or $guard.Status -cne $unknown) { throw 'Executable accessor accepted or invoked' }
[pscustomobject]@{AccessorGuardPassed=$true;PowerShell=$PSVersionTable.PSVersion.ToString();Fixtures=$checks.Count;Assertions=(2*$checks.Count+1);Results=$checks.ToArray()} | ConvertTo-Json -Depth 5
