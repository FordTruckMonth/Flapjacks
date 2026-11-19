#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '../workbook-fixture'
$dependencies = @{
    'WorkbookOutboundForwarding.ps1' = @{
        Hash='b53dced27ed1d9107f1df985eeb894369ba54d1cfd36ed18553d43b5993f1878'
        Commands=@('CompareSavedValues','Field','FindSource','HasField','IsInteger','IsList','Set-StrictMode','UtcTime','ValidateSource')
    }
    'Compare-OutboundForwarding.ps1' = @{
        Hash='36cf28e434938beeb74fd88aee4ba7f3d2c79b9a4ee6bb577ec3effec9b2f095'
        Commands=@('ExactText','Get-FlapjacksWorkbookOutboundForwarding','HasOnlyFields','IsIdentifier','IsInteger','Join-Path',
            '. (Join-Path $PSScriptRoot ''WorkbookOutboundForwarding.ps1'')')
    }
}
foreach ($name in $dependencies.Keys) {
    $path = Join-Path $lib $name
    $spec = $dependencies[$name]
    if ((Get-FileHash -LiteralPath $path).Hash -ine $spec.Hash) { throw "Unreviewed row 76 dependency in $name." }
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Could not parse $name." }
    $found=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($call in $ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true)) {
        $command=$call.GetCommandName()
        if ($null -eq $command) { $command=$call.Extent.Text }
        if ($command -cnotin $spec.Commands) { throw "Unreviewed row 76 command in $name." }
        [void]$found.Add($command)
    }
    if (-not $found.SetEquals([string[]]$spec.Commands)) { throw "Unexpected row 76 command inventory in $name." }
}
$parser=Join-Path $lib 'PassiveJson.ps1'
if ((Get-FileHash -LiteralPath $parser).Hash -ine '3fd29eb4e69eb25be59119a0a1cda562af5f8273623046c9884aeb787d09e8ec') {
    throw 'Unreviewed row 76 passive JSON parser.'
}
. $parser
. (Join-Path $lib 'Compare-OutboundForwarding.ps1')

function New-Report {
    @{
        Metadata=@{SchemaVersion='1.1'; Mode='Synthetic'; TenantId='SYNTHETIC-NOT-A-TENANT'; SelectedGroups=@('Core','Exchange')
            StartedAtUtc='2001-01-01T12:00:00.0000000Z'; FinishedAtUtc='2001-01-01T12:00:00.0000002Z'
            MaxPages=10; MaxRecords=30; OrganizationWideConfirmed=$false; AccountVerification='Synthetic: not applicable'}
        Coverage=@(@{SourceId='exchange-outbound-spam-policies'; Group='Exchange'; Provider='Exchange'; Target='Get-HostedOutboundSpamFilterPolicy'
            Status='Collected'; Reason='Synthetic fixture, not tenant data.'; CollectedAtUtc='2001-01-01T12:00:00.0000001Z'
            PageCount=1; RequestCount=0; Count=1; Notes=''; MissingFields=@()
            Items=@(@{Identity='Invented A'; Name='Policy A'; AutoForwardingMode='Automatic'})})
        Observations=@()
    }
}
$count=0
function Check($Label,$Report,[string]$Expected='Unknown') {
    $wire=ConvertTo-Json -InputObject $Report -Depth 30 -Compress
    $inputReport=ConvertFrom-FjcJson $wire
    $before=ConvertTo-Json -InputObject $inputReport -Depth 30 -Compress
    $actual=@(Get-FlapjacksSyntheticOutboundForwardingComparison -Result $inputReport)
    $reason=if ($Expected -ceq 'Unknown') {'IncompleteSyntheticOutboundPolicyEvidence'} else {'ComparedStoredOutboundForwardingMode'}
    if ($actual.Count -ne 1 -or $actual[0].Row -ne 76 -or $actual[0].Comparison -cne $Expected -or $actual[0].Reason -cne $reason -or
        ($actual[0].PSObject.Properties.Name -join ',') -cne 'Row,Comparison,Reason') { throw "Unexpected row 76 result for $Label, expected $Expected." }
    if ($before -cne (ConvertTo-Json -InputObject $inputReport -Depth 30 -Compress)) { throw "Input changed for $Label." }
    $script:count++
}
foreach ($mode in 'Automatic','On','Off') {
    $r=New-Report
    $r.Coverage[0].Items[0].AutoForwardingMode=$mode
    Check "saved $mode" $r ($mode -ceq 'Automatic' ? 'Matches' : 'Differs')
}
foreach ($field in 'Metadata','Coverage','Observations') {
    $r=New-Report; $r.Remove($field); Check "missing $field" $r
}
foreach ($source in 'Evidence','Items','Mode','RunId','Snapshot') {
    $r=New-Report; $r[$source]=$r.Coverage; Check "alternative bank or provenance $source" $r
}
foreach ($field in (New-Report).Metadata.Keys) {
    $r=New-Report; $r.Metadata.Remove($field); Check "missing metadata $field" $r
}
foreach ($changes in @(@{SchemaVersion=1.1},@{Mode='Live'},@{TenantId='invented-wrong'},@{SelectedGroups=@('Exchange')},
    @{SelectedGroups=@('Core','WorkbookExchange')},@{SelectedGroups=@('Core','exchange')},@{SelectedGroups=@('Core','Exchange','Exchange')},
    @{OrganizationWideConfirmed=$true},@{OrganizationWideConfirmed='false'},@{AccountVerification='Verified'},
    @{Scope='Effective enforcement'},@{Privacy='live'},@{RunId='invented-other'},@{ToolVersion='different'},
    @{PowerShellVersion=@('7.6.9')},@{WorkbookAntiPhishBaseline='Standard'},@{MaxRecords='1'},@{MaxRecords=0},@{MaxPages=0},
    @{MaxPages=$true},@{MaxPages=10001},@{FinishedAtUtc='2000-01-01T12:00:00Z'},@{StartedAtUtc='bad'},
    @{StartedAtUtc='2001-01-01T12:00:00'},@{FinishedAtUtc='2001-02-30T12:00:00Z'})) {
    $r=New-Report
    foreach ($key in $changes.Keys) { $r.Metadata[$key]=$changes[$key] }
    Check "metadata $($changes.Keys)" $r
}
foreach ($key in (New-Report).Coverage[0].Keys) {
    $r=New-Report; $r.Coverage[0].Remove($key); Check "source omits $key" $r
}
foreach ($changes in @(@{SourceId='exchange-outbound-spam-rules'},@{Group='WorkbookExchange'},@{Provider='Graph'},
    @{Target='Get-HostedOutboundSpamFilterRule'},@{Target='ExchangeOnlineManagement\Get-HostedOutboundSpamFilterPolicy'},
    @{Status='Partial'},@{Status='NotSelected'},@{Status='Unavailable'},@{Status='AccessDenied'},@{Reason='RecordLimit'},
    @{MissingFields=@('AutoForwardingMode')},@{MissingFields=@{}},@{Notes='Truncated'},@{Count=2},@{Count=$true},@{Count='1'},@{Count=@(1)},@{Count=@{value=1}},
    @{PageCount=1.0},@{PageCount=2},@{RequestCount='0'},@{RequestCount=1},@{Items=@{}},@{Items=@();Count=0},
    @{CollectedAtUtc='2001-01-01T12:00:00.0000003Z'},@{CollectedAtUtc='2001-02-30T12:00:00Z'},
    @{RunId='invented-other'},@{TenantId='invented-other'},@{'@odata.nextLink'='invented-continuation'})) {
    $r=New-Report
    foreach ($key in $changes.Keys) { $r.Coverage[0][$key]=$changes[$key] }
    Check "source $($changes.Keys)" $r
}
$r=New-Report; $r.Coverage+=@($r.Coverage[0].Clone()); Check 'duplicate source' $r
foreach ($route in 'Get-HostedOutboundSpamFilterPolicy','  get-hostedoutboundspamfilterpolicy ','ExchangeOnlineManagement\Get-HostedOutboundSpamFilterPolicy') {
    $r=New-Report; $alias=$r.Coverage[0].Clone(); $alias.SourceId='other-source'; $alias.Target=$route
    $r.Coverage+=@($alias); Check 'alternate source for same target' $r
}
foreach ($malformed in @(@{},(,@('row')),@{SourceId='other';Target='Get-Other';Items=@();Count=@{value=0};MissingFields=@()})) {
    $r=New-Report; $r.Coverage+=@($malformed); Check 'malformed mixed source inventory' $r
}
$r=New-Report; $r.Coverage[0].Remove('Items'); Check 'summary alone' $r
$r=New-Report; $r.Evidence=$r.Coverage; Check 'competing full bank' $r
foreach ($field in 'Identity','AutoForwardingMode') {
    $r=New-Report; $r.Coverage[0].Items[0].Remove($field); Check "missing policy $field" $r
}
foreach ($value in @($null,0,$false,'','automatic','On ','System-controlled','FutureValue',@{Mode='Automatic'},(,'Automatic'))) {
    $r=New-Report; $r.Coverage[0].Items[0].AutoForwardingMode=$value; Check 'invalid enum' $r
}
foreach ($changes in @(@{Identity=''},@{Identity=' Unknown'},@{Identity='00000000-0000-0000-0000-000000000000'},
    @{Name='Not assessed'},@{Identity="a`nb"},@{Identity=@('Invented A')},@{Group='Exchange'},@{IsDefault='false'},
    @{AutoForwardEnabled=$true},@{NotifyOutboundSpam=0},@{RecipientLimitPerDay=-1},@{RecipientLimitInternalPerHour='4'},
    @{ActionWhenThresholdReached=@('BlockUser')},@{NotifyOutboundSpamRecipients=@{}},@{NotifyOutboundSpamRecipients=@(1)})) {
    $r=New-Report
    foreach ($key in $changes.Keys) { $r.Coverage[0].Items[0][$key]=$changes[$key] }
    Check "weak policy $($changes.Keys)" $r
}
foreach ($second in @(@{Identity='INVENTED A';Name='Policy B'},@{Identity='policy a';Name='Policy B'},
    @{Identity='Invented B';Name='INVENTED A'},@{Identity='Invented B';Name='POLICY A'})) {
    $r=New-Report; $second.AutoForwardingMode='Off'; $r.Coverage[0].Items+=@($second); $r.Coverage[0].Count=2
    Check 'ambiguous policy identity or display alias' $r
}
$r=New-Report
$r.Coverage[0].Items[0].Name='invented a'
$r.Coverage[0].Items[0].IsDefault=$true
$r.Coverage[0].Items[0].NotifyOutboundSpam=$false
$r.Coverage[0].Items[0].NotifyOutboundSpamRecipients=@()
$r.Coverage[0].Items[0].RecipientLimitPerDay=7
$r.Coverage[0].Items[0].ActionWhenThresholdReached='BlockUser'
Check 'typed optional projection and identical name/identity on same policy' $r 'Matches'
$r.Coverage[0].Items+=@(@{Identity='Invented B';AutoForwardingMode='Automatic'}); $r.Coverage[0].Count=2
Check 'two Automatic values' $r 'Matches'
$r.Coverage[0].Items[0].AutoForwardingMode='On'
Check 'known On plus Automatic' $r 'Differs'
$r.Coverage[0].Items[1].AutoForwardingMode='Unknown'; Check 'On plus unknown' $r
[array]::Reverse($r.Coverage[0].Items); Check 'unknown plus On' $r
$r.Metadata.MaxRecords=1; $r.Coverage[0].Items[0].AutoForwardingMode='Off'; Check 'more items than run cap' $r
Write-Output "$count synthetic stored outbound forwarding comparisons passed."
