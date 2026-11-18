#requires -Version 7.4
. (Join-Path $PSScriptRoot 'WorkbookRow165.ps1')
. (Join-Path $PSScriptRoot 'WorkbookRow169.ps1')

function Get-FlapjacksSyntheticConnectionFilterComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    # The caller parses this saved report with ConvertFrom-FjcJson. The released
    # audit.json carries full Coverage. The in-memory form carries full Evidence
    # and a summary projection in Coverage. Do not ignore a conflicting summary.
    function Test-ConnectionReportFields($Map, [string[]]$Allowed) {
        if ($Map -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Map.psbase.Keys) {
            if ($key -isnot [string] -or $key -cnotin $Allowed) { return $false }
        }
        if ($Map.Contains('ReferenceWorkbookSha256')) {
            $pin = $Map['ReferenceWorkbookSha256']
            return $pin -is [string] -and $pin -ceq '92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
        }
        return $true
    }
    function Test-ConnectionFilterSummary($Evidence, $Coverage) {
        $summaryFields = @('SourceId','Group','Provider','Status','Count','Reason','MissingFields','Notes')
        $id = 'exchange-connection-filter-policies'
        $sourceRecords = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($record in $Evidence) {
            if ($record -isnot [Collections.IDictionary] -or $record['SourceId'] -isnot [string] -or
                -not $sourceRecords.TryAdd($record['SourceId'], $record)) { return $false }
        }
        if (-not $sourceRecords.ContainsKey($id)) { return $false }
        foreach ($summary in $Coverage) {
            if ($summary -isnot [Collections.IDictionary] -or $summary['SourceId'] -isnot [string] -or
                -not $sourceRecords.ContainsKey($summary['SourceId'])) { return $false }
            $source = $sourceRecords[$summary['SourceId']]
            [void]$sourceRecords.Remove($summary['SourceId'])
            if ($summary['SourceId'] -cne $id) { continue }
            if ($summary.psbase.Count -ne $summaryFields.Count) { return $false }
            foreach ($key in $summary.psbase.Keys) {
                if ($key -cnotin $summaryFields) { return $false }
            }
            foreach ($field in $summaryFields) {
                if (-not $source.Contains($field) -or -not $summary.Contains($field)) { return $false }
                $expected = ConvertTo-Json -InputObject $source[$field] -Compress -Depth 40 -WarningAction Stop
                $actual = ConvertTo-Json -InputObject $summary[$field] -Compress -Depth 40 -WarningAction Stop
                if ($actual -cne $expected) { return $false }
            }
        }
        return $sourceRecords.Count -eq 0
    }

    $reportFields = @('Metadata','Evidence','Coverage','Observations','Mode','TenantId','RunId','ReferenceWorkbookSha256',
        'OutputPath','SelectedCount','CollectedCount','IncompleteCount','FindingCount')
    $metadataFields = @('SchemaVersion','ToolVersion','Mode','TenantId','RunId','ReferenceWorkbookSha256','StartedAtUtc',
        'FinishedAtUtc','PowerShellVersion','SelectedGroups','MaxPages','MaxRecords','OrganizationWideConfirmed',
        'AccountVerification','Scope','Privacy','WorkbookAntiPhishBaseline')
    $eligible = (Test-ConnectionReportFields $Result $reportFields) -and
        (Test-ConnectionReportFields $Result['Metadata'] $metadataFields) -and
        $Result['Metadata']['Mode'] -is [string] -and $Result['Metadata']['Mode'] -ceq 'Synthetic'
    if ($eligible -and $Result['Metadata'].Contains('OrganizationWideConfirmed')) {
        $confirmed = $Result['Metadata']['OrganizationWideConfirmed']
        $eligible = $confirmed -is [bool] -and -not $confirmed
    }
    if ($eligible) {
        foreach ($name in 'Evidence','Coverage') {
            if ($Result.Contains($name) -and $Result[$name] -isnot [Collections.IList]) { $eligible = $false }
        }
    }
    if ($eligible -and $Result.Contains('Evidence') -and $Result['Evidence'].Count -gt 0 -and $Result.Contains('Coverage')) {
        $eligible = Test-ConnectionFilterSummary $Result['Evidence'] $Result['Coverage']
    }

    if (-not $eligible) {
        foreach ($id in 165,169) {
            [pscustomobject]@{Row=$id; Comparison='Unknown'; Reason='ConnectionFixtureContractRefused'}
        }
        return
    }
    $outcomes = @(
        Get-FlapjacksWorkbookRow165 -Result $Result
        Get-FlapjacksWorkbookRow169 -Result $Result
    )
    foreach ($outcome in $outcomes) {
        $comparison = switch -CaseSensitive ($outcome.Status) {
            'Meets selected setting' { 'Matches' }
            'Needs action' { 'Differs' }
            'Not assessed' { 'Unknown' }
            default { throw 'Unexpected saved connection-filter result.' }
        }
        $reason = if ($comparison -ceq 'Unknown') { 'IncompleteSavedConnectionEvidence' } else { 'ComparedSavedDefaultPolicy' }
        [pscustomobject]@{Row=$outcome.PhysicalRow; Comparison=$comparison; Reason=$reason}
    }
}
