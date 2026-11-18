#requires -Version 7.4
# Receives the bounded passive JSON representation of a synthetic schema 1.1 result.
function Get-FlapjacksSyntheticLockboxComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    $unknown = [pscustomobject]@{Row=157; Comparison='Unknown'; Reason='IncompleteSyntheticOrganizationEvidence'}
    function HasOnlyFields($Record, [string[]]$Fields) {
        if ($Record -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Record.psbase.Keys) {
            if ($key -isnot [string] -or $key -cnotin $Fields) { return $false }
        }
        return $true
    }
    function IsInteger($Value, [long]$Expected) {
        return ($Value -is [int] -or $Value -is [long]) -and $Value -eq $Expected
    }
    function IsText($Value, [string]$Expected) {
        return $Value -is [string] -and $Value -ceq $Expected
    }
    function ReadUtc($Value) {
        $time = [datetimeoffset]::MinValue
        if ($Value -is [string] -and
            $Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)\z' -and
            [datetimeoffset]::TryParse($Value,[cultureinfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$time)) {
            return $time
        }
    }

    $reportFields = @('Metadata','Mode','TenantId','Evidence','Coverage','Observations','OutputPath','SelectedCount',
        'CollectedCount','IncompleteCount','FindingCount')
    $metadataFields = @('SchemaVersion','Mode','TenantId','SelectedGroups','OrganizationWideConfirmed','AccountVerification',
        'StartedAtUtc','FinishedAtUtc','ToolVersion','PowerShellVersion','MaxPages','MaxRecords','Scope','Privacy',
        'WorkbookAntiPhishBaseline','WorkbookMailBaseline')
    if (-not (HasOnlyFields $Result $reportFields)) { return $unknown }
    $metadata = $Result['Metadata']
    if (-not (HasOnlyFields $metadata $metadataFields) -or
        -not (IsText $metadata['Mode'] 'Synthetic') -or -not (IsText $metadata['SchemaVersion'] '1.1') -or
        -not (IsText $metadata['TenantId'] 'SYNTHETIC-NOT-A-TENANT') -or
        -not (IsText $metadata['AccountVerification'] 'Synthetic: not applicable') -or
        $metadata['OrganizationWideConfirmed'] -isnot [bool] -or $metadata['OrganizationWideConfirmed']) { return $unknown }
    foreach ($key in 'Mode','TenantId') {
        if ($Result.Contains($key) -and -not (IsText $Result[$key] $metadata[$key])) { return $unknown }
    }
    $groups = $metadata['SelectedGroups']
    if ($groups -isnot [Collections.IList] -or 'Exchange' -cnotin $groups -or 'WorkbookExchange' -cnotin $groups) { return $unknown }
    $seenGroups = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($group in $groups) {
        if ($group -isnot [string] -or $group -cnotin @('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange',
            'Purview','WorkbookExchange','WorkbookIdentity','WorkbookCollaboration') -or -not $seenGroups.Add($group)) { return $unknown }
    }

    # Native audit.json has full records in Coverage. In-memory reports instead
    # have full Evidence and a separate, exact summary projection in Coverage.
    $hasEvidence = $Result.Contains('Evidence')
    $records = if ($hasEvidence) { ,$Result['Evidence'] } else { ,$Result['Coverage'] }
    if ($records -isnot [Collections.IList] -or $records.Count -eq 0) { return $unknown }
    $indexed = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($r in $records) {
        if ($r -isnot [Collections.IDictionary] -or $r['SourceId'] -isnot [string] -or
            $r['SourceId'] -cnotmatch '\A[a-z][a-z0-9-]{0,99}\z' -or -not $indexed.TryAdd($r['SourceId'],$r)) { return $unknown }
    }
    $totals = @{SelectedCount=0; CollectedCount=0; IncompleteCount=0}
    foreach ($r in $records) {
        if ($r['Status'] -ceq 'NotSelected') { continue }
        $totals.SelectedCount++
        if ($r['Status'] -ceq 'Collected') { $totals.CollectedCount++ } else { $totals.IncompleteCount++ }
    }
    foreach ($key in $totals.Keys) {
        if ($Result.Contains($key) -and -not (IsInteger $Result[$key] $totals[$key])) { return $unknown }
    }
    if ($Result.Contains('Observations') -and $Result['Observations'] -isnot [Collections.IList]) { return $unknown }
    if ($Result.Contains('FindingCount') -and (-not $Result.Contains('Observations') -or
        -not (IsInteger $Result['FindingCount'] $Result['Observations'].Count))) { return $unknown }
    if (-not $indexed.ContainsKey('exchange-organization')) { return $unknown }
    $source = $indexed['exchange-organization']
    $summaryFields = @('SourceId','Group','Provider','Status','Count','Reason','MissingFields','Notes')
    if ($hasEvidence -and $Result.Contains('Coverage')) {
        $summaries = $Result['Coverage']
        if ($summaries -isnot [Collections.IList] -or $summaries.Count -ne $indexed.Count) { return $unknown }
        foreach ($summary in $summaries) {
            if (-not (HasOnlyFields $summary $summaryFields) -or $summary.psbase.Count -ne $summaryFields.Count -or
                $summary['SourceId'] -isnot [string] -or -not $indexed.ContainsKey($summary['SourceId'])) { return $unknown }
            $original = $indexed[$summary['SourceId']]
            [void]$indexed.Remove($summary['SourceId'])
            foreach ($key in $summaryFields) {
                if (-not $original.Contains($key)) { return $unknown }
                $left = ConvertTo-Json -InputObject $original[$key] -Compress -Depth 40 -WarningAction Stop
                $right = ConvertTo-Json -InputObject $summary[$key] -Compress -Depth 40 -WarningAction Stop
                if ($left -cne $right) { return $unknown }
            }
        }
    }

    $sourceFields = $summaryFields + @('Target','PageCount','RequestCount','CollectedAtUtc','Items')
    if (-not (HasOnlyFields $source $sourceFields) -or -not (IsText $source['Group'] 'Exchange') -or
        -not (IsText $source['Provider'] 'Exchange') -or -not (IsText $source['Target'] 'Get-OrganizationConfig') -or
        -not (IsText $source['Status'] 'Collected') -or -not (IsInteger $source['RequestCount'] 0) -or
        -not (IsInteger $source['PageCount'] 1) -or -not (IsInteger $source['Count'] 1) -or
        $source['Items'] -isnot [Collections.IList] -or $source['Items'].Count -ne 1 -or
        $source['MissingFields'] -isnot [Collections.IList] -or $source['MissingFields'].Count -ne 0) { return $unknown }
    if ($source.Contains('Reason') -and -not (IsText $source['Reason'] 'Synthetic fixture, not tenant data.') -and
        -not (IsText $source['Reason'] '')) { return $unknown }
    if ($source.Contains('Notes') -and -not (IsText $source['Notes'] 'Selected organization settings only; no mailbox collection.') -and
        -not (IsText $source['Notes'] '')) { return $unknown }
    $captured = ReadUtc $source['CollectedAtUtc']
    if ($null -eq $captured) { return $unknown }
    foreach ($key in 'StartedAtUtc','FinishedAtUtc') {
        $bound = ReadUtc $metadata[$key]
        if ($null -eq $bound -or ($key -ceq 'StartedAtUtc' -and $captured -lt $bound) -or
            ($key -ceq 'FinishedAtUtc' -and $captured -gt $bound)) { return $unknown }
    }

    $item = $source['Items'][0]
    $fields = @('Identity','OAuth2ClientProfileEnabled','AuditDisabled','DefaultAuthenticationPolicy',
        'AutoExpandingArchiveEnabled','RejectDirectSend','CustomerLockboxEnabled')
    if (-not (HasOnlyFields $item $fields) -or $item.psbase.Count -ne $fields.Count) { return $unknown }
    $id = $item['Identity']
    if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id) -or $id.Trim() -cne $id -or $id -match '[\p{Cc}\p{Cf}]') { return $unknown }
    $guid = [guid]::Empty
    if (([guid]::TryParse($id,[ref]$guid) -and $guid -eq [guid]::Empty) -or
        $id -in @('Unknown','<unknown>','None','Null','N/A','Not applicable','Not provided','Not assessed','Unavailable')) { return $unknown }
    foreach ($key in 'OAuth2ClientProfileEnabled','AuditDisabled','AutoExpandingArchiveEnabled','RejectDirectSend') {
        if ($null -ne $item[$key] -and $item[$key] -isnot [bool]) { return $unknown }
    }
    if ($null -ne $item['DefaultAuthenticationPolicy'] -and $item['DefaultAuthenticationPolicy'] -isnot [string]) { return $unknown }
    $enabled = $item['CustomerLockboxEnabled']
    if ($enabled -isnot [bool]) { return $unknown }
    $comparison = if ($enabled) { 'Matches' } else { 'Differs' }
    return [pscustomobject]@{Row=157; Comparison=$comparison; Reason='ComparedStoredOrganizationSwitch'}
}
