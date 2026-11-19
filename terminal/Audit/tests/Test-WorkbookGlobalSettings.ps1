#requires -Version 7.4
[CmdletBinding()]
param([string]$AuditRoot = (Join-Path $PSScriptRoot '..'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../workbook-fixture/WorkbookGlobalSettings.ps1')
. (Join-Path $AuditRoot 'src/Catalog.ps1')
. (Join-Path $AuditRoot 'src/Collect.ps1')
. (Join-Path $AuditRoot 'src/MailBaselineProtection.ps1')

$matchSetting = 'Meets selected setting'
$different = 'Needs action'
$unknown = 'Not assessed'
$collaboration = 'EnableATPForSPOTeamsODB'
$safeDocs = 'EnableSafeDocs'
$sourceId = 'exchange-atp-organization'
$profiles = @('None', 'Standard', 'Strict')
$fixtures = [Collections.Generic.List[object]]::new()
$registrations = [Collections.Generic.HashSet[string]]::new()
$evaluations = 0
$verifiedRows = 0
$collectorChecks = 0

function New-Report {
    $item = @{ Identity = 'Fixture organization 12'; EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
    $source = @{
        SourceId = $sourceId; Group = 'Exchange'; Target = 'Get-AtpPolicyForO365'; Provider = 'Exchange'
        Status = 'Collected'; Reason = ''; Count = 1; PageCount = 1; RequestCount = 0
        MissingFields = @(); Items = @($item)
    }
    @{
        Mode = 'Synthetic'; TenantId = 'SYNTHETIC-NOT-A-TENANT'
        Metadata = @{ Mode = 'Synthetic'; TenantId = 'SYNTHETIC-NOT-A-TENANT'; SelectedGroups = @('Core','Exchange','WorkbookExchange') }
        Evidence = @($source)
    }
}

function Test-Report($Name, $Report, [string]$Expected83, [string]$Expected84) {
    if (-not $registrations.Add($Name)) { throw "Duplicate fixture label $Name" }
    foreach ($profile in $profiles) {
        $Report.Metadata.WorkbookAntiPhishBaseline = $profile
        $restored = $Report | ConvertTo-Json -Depth 15 | ConvertFrom-Json
        foreach ($sample in @($Report, $restored)) {
            $rows = @(Get-FlapjacksWorkbookGlobalSettings -Result $sample)
            if ($rows.Count -ne 2) { throw "$Name / $profile returned $($rows.Count) controls." }
            $script:evaluations++
            foreach ($expected in @(
                @{ Anchor=83; Id='MDO-ORG-COLLAB'; Field=$collaboration; Status=$Expected83 },
                @{ Anchor=84; Id='MDO-ORG-SAFEDOCS'; Field=$safeDocs; Status=$Expected84 }
            )) {
                $found = @($rows | Where-Object ControlId -ceq $expected.Id)
                if ($found.Count -ne 1) { throw "$Name / $profile requires exactly one $($expected.Id)." }
                $row = $found[0]
                if ($row.PhysicalRow -ne $expected.Anchor -or $row.Field -cne $expected.Field -or $row.SourceId -cne $sourceId -or
                    $row.Status -cne $expected.Status -or [string]::IsNullOrWhiteSpace($row.Observed) -or
                    [string]::IsNullOrWhiteSpace($row.ReasonCode)) {
                    throw "$Name / $profile / $($expected.Id) expected $($expected.Status), got $($row.Status) ($($row.ReasonCode))."
                }
                $script:verifiedRows++
            }
        }
    }
    $fixtures.Add([ordered]@{ Fixture=$Name; Row83=$Expected83; Row84=$Expected84 })
}

# Sibling failures in a saved envelope with empty MissingFields are row-local.
# A collector that actually observes a missing required field marks the entire source Partial (below).
foreach ($first in @($true, $false)) {
    foreach ($second in @($true, $false)) {
        $r = New-Report
        $r.Evidence[0].Items[0][$collaboration] = $first
        $r.Evidence[0].Items[0][$safeDocs] = $second
        $r.Evidence[0].Items[0].AllowSafeDocsOpen = -not $second
        Test-Report "Boolean 83=$first 84=$second" $r ($first ? $matchSetting : $different) ($second ? $matchSetting : $different)
    }
}
foreach ($field in @($collaboration, $safeDocs)) {
    foreach ($variant in @('absent','null','string-true','string-false','numeric','array','object')) {
        $r = New-Report
        $item = $r.Evidence[0].Items[0]
        $item.AllowSafeDocsOpen = $true
        switch ($variant) {
            'absent'       { $item.Remove($field) }
            'null'         { $item[$field] = $null }
            'string-true'  { $item[$field] = 'true' }
            'string-false' { $item[$field] = 'false' }
            'numeric'      { $item[$field] = 1 }
            'array'        { $item[$field] = @($true) }
            'object'       { $item[$field] = @{ Value = $true } }
        }
        $isFirst = $field -ceq $collaboration
        Test-Report "$field $variant" $r ($isFirst ? $unknown : $matchSetting) ($isFirst ? $matchSetting : $unknown)
    }
    $r = New-Report
    $r.Evidence[0].Items[0].EnableATPForSPOTeamsODB = $false
    $r.Evidence[0].Items[0].EnableSafeDocs = $false
    $r.Evidence[0].Items[0].Remove($field)
    $isFirst = $field -ceq $collaboration
    Test-Report "$field missing beside false" $r ($isFirst ? $unknown : $different) ($isFirst ? $different : $unknown)
}
foreach ($variant in @('absent','null','empty','whitespace','numeric','array','object')) {
    $r = New-Report
    $item = $r.Evidence[0].Items[0]
    switch ($variant) {
        'absent' { $item.Remove('Identity') }
        'null' { $item.Identity = $null }
        'empty' { $item.Identity = '' }
        'whitespace' { $item.Identity = " `t" }
        'numeric' { $item.Identity = 1 }
        'array' { $item.Identity = @('Fixture organization 12') }
        'object' { $item.Identity = @{ Name='Fixture organization 12' } }
    }
    Test-Report "Identity $variant" $r $unknown $unknown
}
foreach ($sameIdentity in @($true, $false)) {
    foreach ($agrees in @($true, $false)) {
        $r = New-Report
        $second = $r.Evidence[0].Items[0].Clone()
        if (-not $sameIdentity) { $second.Identity = 'Fixture organization 13' }
        if (-not $agrees) { $second.EnableSafeDocs = $false }
        $r.Evidence[0].Items += $second
        $r.Evidence[0].Count = 2
        Test-Report "Two records same identity=$sameIdentity same values=$agrees" $r $unknown $unknown
    }
}

$invalidSources = [ordered]@{
    'wrong source ID'=@{SourceId='other-setting'}; 'wrong cmdlet'=@{Target='Get-OtherSetting'}
    'wrong provider'=@{Provider='Graph'}; 'wrong group'=@{Group='WorkbookExchange'}
    'unavailable'=@{Status='Unavailable'}; 'not selected'=@{Status='NotSelected'}
    'partial'=@{Status='Partial'}; 'collected with a limit reason'=@{Reason='RecordLimit'}
    'missing fields list nonempty'=@{MissingFields=@('AllowSafeDocsOpen')}; 'null missing fields'=@{MissingFields=$null}
    'string count'=@{Count='1'}; 'Boolean count'=@{Count=$true}; 'too large count'=@{Count=2}
    'zero items'=@{Items=@();Count=0}; 'not an item list'=@{Items=@{Identity='other'}}
    'no completed page'=@{PageCount=0}; 'extra requests'=@{RequestCount=2}
}
foreach ($entry in $invalidSources.GetEnumerator()) {
    $r = New-Report
    foreach ($change in $entry.Value.GetEnumerator()) { $r.Evidence[0][$change.Key] = $change.Value }
    Test-Report $entry.Key $r $unknown $unknown
}
foreach ($key in @('SourceId','Group','Provider','Target','Status','Count','MissingFields','Items')) {
    $r = New-Report
    $r.Evidence[0].Remove($key)
    Test-Report "Source omits $key" $r $unknown $unknown
}
$r = New-Report
$r.Evidence += $r.Evidence[0].Clone()
Test-Report 'Duplicate source envelope, same values' $r $unknown $unknown
$r = New-Report
$r.Evidence[0].Items += $r.Evidence[0].Items[0].Clone()
Test-Report 'Two records despite declared singleton' $r $unknown $unknown
$r = New-Report
$r.Evidence = @()
Test-Report 'Empty evidence' $r $unknown $unknown
$r = New-Report
$r.TenantId = 'SYNTHETIC-DIFFERENT-RUN-TENANT'
Test-Report 'Conflicting report tenant markers' $r $unknown $unknown
foreach ($leftOut in @('Exchange','WorkbookExchange')) {
    $r = New-Report
    $r.Metadata.SelectedGroups = @($r.Metadata.SelectedGroups | Where-Object { $_ -cne $leftOut })
    Test-Report "Missing group $leftOut" $r $unknown $unknown
}
$r = New-Report
$r.Coverage = $r.Evidence
$r.Remove('Evidence')
Test-Report 'Saved Coverage with full records' $r $matchSetting $matchSetting
$r = New-Report
$r.Coverage = @(@{SourceId=$sourceId; Group='Exchange'; Provider='Exchange'; Status='Collected'; Count=1; MissingFields=@(); Reason=''; Notes=''})
Test-Report 'In-memory evidence and matching coverage summary' $r $matchSetting $matchSetting
$r.Remove('Evidence')
Test-Report 'Coverage summary alone' $r $unknown $unknown
$r = New-Report
$r.Evidence[0].Items[0].AllowSafeDocsOpen = 'invalid'
Test-Report 'Invalid click-through field is independent' $r $matchSetting $matchSetting

# Exercise the existing projection and missing-field code with an in-memory mock.
# The mocked module alone is bound to the reader. Its body only returns an invented object.
$definition = @(Get-AuditSourceCatalog | Where-Object Id -ceq $sourceId)
if ($definition.Count -ne 1) { throw 'Expected one organization source in the audit catalog.' }
$mock = New-Module -Name SyntheticWorkbookOrganization -ScriptBlock {
    $script:Record = $null
    $script:Calls = 0
    function Get-AtpPolicyForO365 {
        [CmdletBinding()]param()
        $script:Calls++
        $script:Record
    }
    Export-ModuleMember -Function Get-AtpPolicyForO365
}
Import-Module $mock -DisableNameChecking
try {
    foreach ($omit in @('none', $collaboration, $safeDocs, 'AllowSafeDocsOpen')) {
        $r = New-Report
        $inputItem = $r.Evidence[0].Items[0]
        if ($omit -cne 'none') { $inputItem.Remove($omit) }
        & $mock { param($object) $script:Record = $object; $script:Calls = 0 } ([pscustomobject]$inputItem)
        $source = Read-AuditCommandSource -Source $definition[0] -Session @{ Connection=@{ModuleName=$mock.Name} }
        $complete = $omit -ceq 'none'
        if ((& $mock { $script:Calls }) -ne 1 -or $source.Count -ne 1 -or $source.PageCount -ne 1 -or $source.RequestCount -ne 1 -or
            $source.Status -cne ($complete ? 'Collected' : 'Partial') -or
            $source.MissingFields.Count -ne ($complete ? 0 : 1) -or (-not $complete -and $source.MissingFields[0] -cne $omit)) {
            throw "Unexpected synthetic collector projection for omission $omit."
        }
        $collectorChecks++
        $r.Evidence = @($source)
        $status = $complete ? $matchSetting : $unknown
        Test-Report "Projected local mock omits $omit" $r $status $status
    }
} finally { Remove-Module $mock }

[ordered]@{
    PowerShell = $PSVersionTable.PSVersion.ToString()
    CandidateSHA256 = (Get-FileHash (Join-Path $PSScriptRoot '../workbook-fixture/WorkbookGlobalSettings.ps1')).Hash.ToLowerInvariant()
    FixtureSHA256 = (Get-FileHash $PSCommandPath).Hash.ToLowerInvariant()
    CatalogSHA256 = (Get-FileHash (Join-Path $AuditRoot 'src/Catalog.ps1')).Hash.ToLowerInvariant()
    CollectorSHA256 = (Get-FileHash (Join-Path $AuditRoot 'src/Collect.ps1')).Hash.ToLowerInvariant()
    Profiles = $profiles; Representations = @('native','JSON round trip')
    Fixtures = $fixtures.Count; Evaluations = $evaluations; VerifiedRowVerdicts = $verifiedRows
    VerifiedLocalCollectorProjections = $collectorChecks; Results = $fixtures.ToArray()
} | ConvertTo-Json -Depth 5
