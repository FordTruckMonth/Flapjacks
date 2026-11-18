#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$audit=Split-Path $PSScriptRoot -Parent
$lib=Join-Path $audit 'workbook-fixture'

# These pins and AST inventories apply only to the opt-in fixture components.
# The ordinary mail gate keeps its own reviewed command set.
$permitted=@{
    'WorkbookGlobalSettings.ps1'=@{
        Hash='078977a9f64b6b3f6a2f92ee3a0413ad8e6efc9a1a004e66e981baeeaee6dbc8'
        Commands=@('CheckSource','Field','FindSource','Get-FlapjacksMailBaselineProtectionDefinitions',
            'HasField','IsInteger','IsList','ReadOrganization','Set-StrictMode','UtcTime')
    }
    'MailOrganizationSettings.ps1'=@{
        Hash='b5687315c9d54721ee7ca9735c6e770beb1007bda639ce40ab869f30e83b8574'
        Commands=@('ConvertTo-Json','Get-FlapjacksWorkbookGlobalSettings','Get-SourceInventory','Has-OnlyFields',
            'Join-Path','Test-OrganizationFixture','Test-WorkbookPin',
            '. (Join-Path $PSScriptRoot ''../src/MailBaselineProtection.ps1'')',
            '. (Join-Path $PSScriptRoot ''WorkbookGlobalSettings.ps1'')')
    }
}
foreach ($file in $permitted.Keys) {
    $spec=$permitted[$file]
    $path=Join-Path $lib $file
    if ((Get-FileHash -LiteralPath $path).Hash -ine $spec.Hash) { throw "Unreviewed fixture bytes in $file." }
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Fixture parse error in $file." }
    $found=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true)) {
        $name=$node.GetCommandName()
        if ($null -eq $name) { $name=$node.Extent.Text }
        if ($name -cnotin $spec.Commands) { throw "Unreviewed fixture command in $file." }
        [void]$found.Add($name)
    }
    if (-not $found.SetEquals([string[]]$spec.Commands)) { throw "Unexpected fixture command inventory in $file." }
}
$definitionFile=Join-Path $audit 'src/MailBaselineProtection.ps1'
if ((Get-FileHash -LiteralPath $definitionFile).Hash -ine '807e53af2c2c56a978f262d5a176aa36a79ad7ffc5cea91aea64e048c62cfcd5') {
    throw 'The reviewed fixture definition dependency changed.'
}
. (Join-Path $lib 'PassiveJson.ps1')
. (Join-Path $lib 'MailOrganizationSettings.ps1')

function New-Report {
    @{
        Metadata=@{Mode='Synthetic';TenantId='SYNTHETIC-NOT-A-TENANT';RunId='invented-run'
            SelectedGroups=@('Exchange','WorkbookExchange');StartedAtUtc='2026-01-10T10:00:00Z';FinishedAtUtc='2026-01-10T10:02:00Z'}
        Evidence=@(@{SourceId='exchange-atp-organization';Group='Exchange';Provider='Exchange';Target='Get-AtpPolicyForO365'
            Status='Collected';PageCount=1;RequestCount=0;Count=1;MissingFields=@();Reason='Synthetic fixture';Notes=''
            CollectedAtUtc='2026-01-10T10:01:00Z';Items=@(@{Identity='invented-organization';EnableATPForSPOTeamsODB=$true
                EnableSafeDocs=$true;AllowSafeDocsOpen=$false})})
    }
}
function Add-Summary($Report) {
    $row=@{}
    foreach ($key in 'SourceId','Group','Provider','Status','Count','Reason','MissingFields','Notes') {
        $row[$key]=$Report.Evidence[0][$key]
    }
    $Report.Coverage=@($row)
}
$cases=0
function Check([string]$Label,$Report,[string]$Expected83,[string]$Expected84) {
    $data=ConvertFrom-FjcJson (ConvertTo-Json -InputObject $Report -Depth 45 -Compress)
    $before=ConvertTo-Json -InputObject $data -Depth 45 -Compress
    $rows=@(Get-FlapjacksSyntheticMailOrganizationComparison -Result $data)
    if ($rows.Count -ne 2 -or ($rows.Row -join ',') -cne '83,84' -or $rows[0].Comparison -cne $Expected83 -or
        $rows[1].Comparison -cne $Expected84) { throw "Unexpected comparison for $Label ($($rows.Comparison -join ','))." }
    foreach ($row in $rows) {
        if (($row.psobject.Properties.Name -join ',') -cne 'Row,Comparison,Reason' -or $row.Reason -cnotmatch '\A[A-Za-z]{1,64}\z') {
            throw "Unexpected fixture fields for $Label."
        }
    }
    if ((ConvertTo-Json -InputObject $data -Depth 45 -Compress) -cne $before) { throw "Mutation of $Label." }
    $script:cases++
}
$yes='Matches'; $no='Differs'; $unknown='Unknown'
$r=New-Report; Check 'positive' $r $yes $yes
$r.Evidence[0].Items[0].EnableSafeDocs=$false; Check 'different SafeDocs' $r $yes $no
$r.Evidence[0].Items[0].EnableATPForSPOTeamsODB=$false; Check 'both different' $r $no $no
$r.Evidence[0].Items[0].EnableSafeDocs='false'; Check 'invalid SafeDocs' $r $no $unknown
$r.Evidence[0].Items[0].Remove('EnableSafeDocs'); Check 'missing SafeDocs' $r $no $unknown
$r.Evidence[0].Items[0].EnableATPForSPOTeamsODB=1; $r.Evidence[0].Items[0].EnableSafeDocs=$true
Check 'numeric collaboration switch' $r $unknown $yes
foreach ($key in 'Mode','TenantId','SelectedGroups','StartedAtUtc','FinishedAtUtc') {
    $r=New-Report; $r.Metadata.Remove($key); Check "missing metadata $key" $r $unknown $unknown
}
foreach ($key in 'Group','Provider','Target','Count','MissingFields','Status','CollectedAtUtc','PageCount','RequestCount','Items') {
    $r=New-Report; $r.Evidence[0].Remove($key); Check "missing source $key" $r $unknown $unknown
}
foreach ($key in 'Provenance','Command','ScopeVerified','SourceCommand','mode','SnapshotComplete','RunIDAlias','CollectedUtc') {
    $r=New-Report; $r.Evidence[0][$key]=$false; Check "source annotation or alias $key" $r $unknown $unknown
}
foreach ($key in 'status','collectedatutc','target') {
    $r=New-Report; $value=$r.Evidence[0][$key]; $r.Evidence[0].Remove($key); $r.Evidence[0][$key]=$value
    Check "source field case alias $key" $r $unknown $unknown
}
foreach ($key in 'mode','startedatutc','runid') {
    $r=New-Report; $value=$r.Metadata[$key]; $r.Metadata.Remove($key); $r.Metadata[$key]=$value
    Check "metadata field case alias $key" $r $unknown $unknown
}
foreach ($identity in @('',' ',' padded ','00000000-0000-0000-0000-000000000000','{00000000-0000-0000-0000-000000000000}',"ab`tcd")) {
    $r=New-Report; $r.Evidence[0].Items[0].Identity=$identity; Check 'unusable ID' $r $unknown $unknown
}
foreach ($identity in @('unknown','<UNKNOWN>','none','NULL','N/a','Not Applicable','Not provided','Not assessed','Unavailable',
    [string][char]0x200B,('ab'+[char]0x200B+'cd'))) {
    $r=New-Report; $r.Evidence[0].Items[0].Identity=$identity; Check 'absent or nonprintable ID' $r $unknown $unknown
}
$r=New-Report; $r.Evidence[0].Items+=@($r.Evidence[0].Items[0]); $r.Evidence[0].Count=2
Check 'two agreeing records' $r $unknown $unknown
$r=New-Report; $r.Evidence+=@($r.Evidence[0]); Check 'duplicate source' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Warnings=@('fixture warning'); Check 'warning' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Truncated=$true; Check 'truncation' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Items[0].RunId='other'; Check 'unbound organization annotation' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].RunId='other'; Check 'contradictory run' $r $unknown $unknown
$r.Metadata.Remove('RunId'); Check 'unbound source run' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].TenantId='other'; Check 'contradictory tenant' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Mode='Live'; Check 'contradictory source mode' $r $unknown $unknown
$r=New-Report; $r.Metadata.Mode='Live'; Check 'live metadata' $r $unknown $unknown
$r=New-Report; $r.Metadata.TenantId='11111111-1111-4111-8111-111111111111'; Check 'unexpected tenant' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].RequestCount=1; Check 'external request' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].RequestCount='0'; Check 'untyped request' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].PageCount=0; Check 'zero pages' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].PageCount=$true; Check 'noninteger pages' $r $unknown $unknown
$r=New-Report; $r.Metadata.AccountVerification='Verified live'; Check 'conflicting verification' $r $unknown $unknown
$r=New-Report; $r.Metadata.OrganizationWideConfirmed=$true; Check 'conflicting scope' $r $unknown $unknown
$r=New-Report; $r.Metadata.ReferenceWorkbookSha256='wrong'; Check 'conflicting workbook' $r $unknown $unknown
$r=New-Report; $r.Metadata.SelectedGroups=@('Exchange'); Check 'missing workbook group' $r $unknown $unknown
$r.Metadata.SelectedGroups=@('WorkbookExchange'); Check 'missing Exchange group' $r $unknown $unknown
$r=New-Report; $r.Metadata.SelectedGroups+=@('Exchange'); Check 'duplicate group' $r $unknown $unknown
$r=New-Report; $r.Metadata.SelectedGroups+=@('Other'); Check 'foreign group' $r $unknown $unknown
$r=New-Report; $r.Metadata.SelectedGroups+=@('Core','Authentication','Consent','Administration','TenantInventory','Intune',
    'Purview','WorkbookIdentity','WorkbookCollaboration'); Check 'all catalog groups' $r $yes $yes
$r.Metadata.SchemaVersion='1.1'; Check 'recognized optional report schema' $r $yes $yes
foreach ($version in @('1.0','2.0',1.1,'',$null)) {
    $r=New-Report; $r.Metadata.SchemaVersion=$version; Check 'unsupported supplied schema' $r $unknown $unknown
}
$r=New-Report; $r.Evidence[0].CollectedAtUtc='2026-01-10T10:03:00Z'; Check 'outside run window' $r $unknown $unknown
$r=New-Report; $r.Metadata.FinishedAtUtc='invalid'; Check 'invalid timestamp' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Status='NotSelected'; Check 'skipped' $r $unknown $unknown
$r.Evidence[0].Status='Partial'; Check 'partial' $r $unknown $unknown
$r.Evidence[0].Status='NotConnected'; Check 'unavailable' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].MissingFields=@('EnableSafeDocs'); Check 'source lacks field' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Provider='Graph'; Check 'wrong provider' $r $unknown $unknown
$r=New-Report; $r.Evidence[0].Target='Get-Other'; Check 'wrong command' $r $unknown $unknown
$r=New-Report; Add-Summary $r; Check 'synchronized Coverage' $r $yes $yes
$r.Coverage[0].Count=0; Check 'stale count in summary' $r $unknown $unknown
$r=New-Report; Add-Summary $r; $r.Coverage[0].Remove('Reason'); Check 'incomplete summary' $r $unknown $unknown
$r=New-Report; Add-Summary $r; $r.Coverage[0].CollectedAtUtc='2026-01-10T10:00:30Z'
Check 'conflicting summary time' $r $unknown $unknown
$r=New-Report; Add-Summary $r; $r.Coverage[0].SnapshotComplete=$false; Check 'unsupported summary marker' $r $unknown $unknown
$r=New-Report; $r.Coverage=@(); Check 'missing parallel source' $r $unknown $unknown
$r=New-Report; $r.Coverage=$r.Evidence; Check 'two complete records' $r $unknown $unknown
$r.Remove('Evidence'); Check 'persisted full Coverage' $r $yes $yes
$r.Evidence=@(); Check 'contradictory empty Evidence' $r $unknown $unknown
$r=New-Report; $r.Metadata.Mode='synthetic'; $r.Metadata.SelectedGroups=@('exchange','workbookexchange')
Check 'noncanonical fixture mode' $r $unknown $unknown
$r.Metadata.Mode='Synthetic'; Check 'noncanonical group selection' $r $unknown $unknown
Check 'null input' $null $unknown $unknown
Write-Output "PASS: two pinned fixture command inventories and one pinned definition dependency; $cases passive fixtures, $($cases*2) stored comparisons."
