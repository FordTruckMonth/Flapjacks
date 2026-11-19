#requires -Version 7.4
# Read a deserialized Flapjacks audit result. This function never collects evidence.
function Get-FlapjacksWorkbookRow165 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    Set-StrictMode -Version Latest
    $sourceId = 'exchange-connection-filter-policies'
    $target = 'Get-HostedConnectionFilterPolicy'
    function Field($record, [string]$name) {
        if ($record -is [System.Collections.IDictionary]) { return ,$record[$name] }
        if ($record -is [pscustomobject]) {
            $property = $record.PSObject.Properties[$name]
            if ($null -ne $property -and $property.MemberType -eq 'NoteProperty') {
                return ,$property.Value
            }
        }
        return $null
    }
    function Keys($record) {
        if ($record -is [System.Collections.IDictionary]) { return $record.psbase.Keys }
        if ($record -is [pscustomobject]) { foreach ($property in $record.PSObject.Properties) { $property.Name } }
    }
    function Collection($value) { return $value -is [System.Collections.IList] -and ($value -isnot [array] -or $value.Rank -eq 1) }
    function Integer($value) { return $value -is [int] -or $value -is [long] }
    function TextEquals($value, [string]$expected) { return $value -is [string] -and $value -ceq $expected }
    $sourceStatus = 'Unknown'
    $evidenceTime = ''
    function Outcome([string]$reason, [string]$status='Not assessed') {
        $observation = switch ($status) {
            'Meets selected setting' { 'EnableSafeList = false on Default.' }
            'Needs action' { 'EnableSafeList = true on Default.' }
            default { 'Insufficient or conflicting saved configuration evidence.' }
        }
        [pscustomobject][ordered]@{
            ControlId='WB-REF-92B9-ROW-165'; PhysicalRow=165; Status=$status; ReasonCode=$reason
            Control='Default connection-filter safe-list switch'; SourceStatus=$sourceStatus
            Observed=$observation; EvidenceTime=$evidenceTime
            EvidenceIds=@(if ($status -cne 'Not assessed') { 'Default' })
            Rationale='The selected setting disables the service-managed safe list on Default.'
            SourceId=$sourceId; Provider='Exchange'; Target=$target; Field='EnableSafeList'
            Expected='Boolean false on the uniquely named Default policy.'
            Reference='https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
            Limitation='Stored setting in supplied records. Tenant authenticity and effective filtering are unverified.'
        }
    }

    $metadata = Field $Result 'Metadata'
    $outerKeys = @(Keys $Result)
    $innerKeys = @(Keys $metadata)
    foreach ($key in @('Mode','TenantId','RunId')) {
        if ($key -in $outerKeys -and $key -in $innerKeys) {
            $outer = Field $Result $key
            $inner = Field $metadata $key
            if ($outer -isnot [string] -or $inner -isnot [string] -or $outer -cne $inner) {
                return Outcome 'ConflictingReportIdentity'
            }
        }
    }
    if ('SelectedGroups' -in $innerKeys) {
        $groups = Field $metadata 'SelectedGroups'
        if (-not (Collection $groups) -or @($groups | Where-Object { $_ -isnot [string] }).Count -or
            'WorkbookExchange' -cnotin $groups) { return Outcome 'GroupSelectionMismatch' }
    }
    $synthetic = TextEquals (Field $metadata 'Mode') 'Synthetic'
    $rows = Field $Result 'Evidence'
    if ($null -eq $rows -or ((Collection $rows) -and $rows.Count -eq 0)) {
        $rows = Field $Result 'Coverage'
    }
    if (-not (Collection $rows)) { return Outcome 'MissingSourceCollection' }
    $source = $null
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        $id = Field $row 'SourceId'
        if ($id -isnot [string] -or $id -cnotmatch '\A[a-z][a-z0-9-]{0,99}\z' -or -not $seen.Add($id)) {
            return Outcome 'MissingOrAmbiguousSource'
        }
        if ($id -ceq $sourceId) { $source = $row }
    }
    if ($null -eq $source) { return Outcome 'MissingOrAmbiguousSource' }
    $keys = @(Keys $source)
    $allowed = @('SourceId','Provider','Target','Group','Status','Count','Items','MissingFields',
                 'PageCount','RequestCount','Reason','CollectedAtUtc','Notes')
    if (@($keys | Where-Object { $_ -cnotin $allowed }).Count) { return Outcome 'UnexpectedSourceField' }
    if (-not (TextEquals (Field $source 'SourceId') $sourceId) -or
        -not (TextEquals (Field $source 'Provider') 'Exchange') -or
        -not (TextEquals (Field $source 'Target') $target) -or
        ('Group' -cin $keys -and -not (TextEquals (Field $source 'Group') 'WorkbookExchange'))) {
        return Outcome 'SourceContractMismatch'
    }
    if (-not (TextEquals (Field $source 'Status') 'Collected')) { return Outcome 'IncompleteSource' }
    if ('Reason' -cin $keys) {
        $reason = Field $source 'Reason'
        $fixtureReasons = @('Synthetic fixture, not tenant data.','Synthetic fixture','Fixture evidence')
        if ($reason -isnot [string] -or ($reason -cne '' -and (-not $synthetic -or $reason -cnotin $fixtureReasons))) {
            return Outcome 'ConflictingCollectionReason'
        }
    }
    $pages = Field $source 'PageCount'
    $requests = Field $source 'RequestCount'
    if (('PageCount' -cin $keys -and (-not (Integer $pages) -or $pages -ne 1)) -or
        ('RequestCount' -cin $keys -and (-not (Integer $requests) -or ($requests -ne 1 -and -not ($synthetic -and $requests -eq 0))))) {
        return Outcome 'IncompleteCommandEvidence'
    }
    $count = Field $source 'Count'
    $items = Field $source 'Items'
    $missing = Field $source 'MissingFields'
    if (-not (Collection $items) -or -not (Integer $count) -or
        $count -ne $items.Count -or $count -lt 1 -or
        -not (Collection $missing) -or $missing.Count -ne 0) {
        return Outcome 'IncompleteProjection'
    }

    $sourceStatus = 'Collected'
    $stamp = Field $source 'CollectedAtUtc'
    if ($stamp -is [datetimeoffset] -or ($stamp -is [datetime] -and $stamp.Kind -ne [DateTimeKind]::Unspecified)) {
        $evidenceTime = $stamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    } elseif ($stamp -is [string] -and $stamp -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\z') {
        $parsed = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse($stamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            $evidenceTime = $parsed.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
        }
    }
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $selected = $null
    foreach ($item in $items) {
        if ($item -isnot [pscustomobject] -and $item -isnot [System.Collections.IDictionary]) {
            return Outcome 'InvalidPolicyShape'
        }
        $itemKeys = @(Keys $item)
        if (@($itemKeys | Where-Object { $_ -cnotin @('Identity','Name','IPAllowList','IPBlockList','EnableSafeList') }).Count) {
            return Outcome 'UnexpectedPolicyField'
        }
        $name = Field $item 'Name'
        $id = Field $item 'Identity'
        if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $name.Trim() -cne $name -or $name -match '\p{Cc}' -or
            $id -isnot [string] -or [string]::IsNullOrWhiteSpace($id) -or $id.Trim() -cne $id -or $id -match '\p{Cc}' -or
            -not $names.Add($name) -or -not $ids.Add($id)) {
            return Outcome 'MissingOrAmbiguousPolicyIdentity'
        }
        if ([string]::Equals($name, 'Default', [StringComparison]::OrdinalIgnoreCase)) { $selected = $item }
    }
    if ($null -eq $selected) { return Outcome 'DefaultPolicyMissing' }
    $enabled = Field $selected 'EnableSafeList'
    if ($enabled -isnot [bool]) { return Outcome 'MissingOrInvalidBoolean' }
    if ($enabled) { return Outcome 'DefaultSafeListEnabled' 'Needs action' }
    return Outcome 'DefaultSafeListDisabled' 'Meets selected setting'
}
