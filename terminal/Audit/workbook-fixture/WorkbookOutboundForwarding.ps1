#requires -Version 7.4
# Explicitly invoke this function with a synthetic result from Run.ps1 or its audit.json.
function Get-FlapjacksWorkbookOutboundForwarding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    Set-StrictMode -Version Latest
    $sourceId = 'exchange-outbound-spam-policies'
    $commandName = 'Get-HostedOutboundSpamFilterPolicy'
    $counts = @{ Matched = $null; Differing = $null }

    # Read data properties only. A case-colliding dictionary key is ambiguous.
    function HasField($record, [string]$name) {
        if ($record -is [Collections.IDictionary]) { return $name -in $record.psbase.Keys }
        return $record -is [pscustomobject] -and $null -ne $record.PSObject.Properties[$name]
    }
    function Field($record, [string]$name) {
        if ($record -is [Collections.IDictionary]) {
            $found = $false
            foreach ($key in $record.psbase.Keys) {
                if ($key -is [string] -and [string]::Equals($key,$name,[StringComparison]::OrdinalIgnoreCase)) {
                    if ($found -or -not $key.Equals($name)) { return $null }
                    $found = $true
                }
            }
            if ($found) { return ,$record[$name] }
        } elseif ($record -is [pscustomobject]) {
            $member = $record.PSObject.Properties[$name]
            if ($member -is [System.Management.Automation.PSNoteProperty] -and $member.Name.Equals($name)) {
                return ,$member.Value
            }
        }
        return $null
    }
    function IsList($value) {
        return $value -is [Collections.IList] -and ($value -isnot [array] -or $value.Rank -eq 1)
    }
    function IsInteger($value) {
        return $value -is [int] -or $value -is [long] -or $value -is [uint32] -or
            $value -is [uint64] -or $value -is [int16] -or $value -is [uint16] -or
            $value -is [byte] -or $value -is [sbyte]
    }
    function FindSource($rows) {
        if (-not (IsList $rows)) { return $null }
        $found = $null
        foreach ($row in $rows) {
            $id = Field $row 'SourceId'
            if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id)) { return $null }
            if ([string]::Equals($id.Trim(),$sourceId,[StringComparison]::OrdinalIgnoreCase)) {
                if ($null -ne $found -or -not $id.Equals($sourceId)) { return $null }
                $found = $row
            }
        }
        return ,$found
    }
    function UtcTime($value) {
        if ($value -is [datetimeoffset]) { return $value.UtcDateTime }
        if ($value -is [datetime] -and $value.Kind -ne [DateTimeKind]::Unspecified) { return $value.ToUniversalTime() }
        if ($value -is [string] -and $value -cmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z') {
            $stamp = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse($value,[Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None,[ref]$stamp)) { return $stamp.UtcDateTime }
        }
        return $null
    }
    function ValidateSource($record, [bool]$summary) {
        foreach ($binding in @{Group='Exchange'; Provider='Exchange'; Target=$commandName; Status='Collected'}.GetEnumerator()) {
            if ($summary -and $binding.Key -eq 'Target' -and -not (HasField $record 'Target')) { continue }
            $value = Field $record $binding.Key
            if ($value -isnot [string] -or -not $value.Equals($binding.Value)) { return 'IncompleteOrMisboundSource' }
        }
        $missing = Field $record 'MissingFields'
        if (-not (IsList $missing) -or $missing.Count -ne 0) { return 'IncompleteProjection' }
        $n = Field $record 'Count'
        if (-not (IsInteger $n) -or $n -lt 1) { return 'InvalidRecordCount' }
        foreach ($name in @('PageCount','RequestCount')) {
            if ($summary -and -not (HasField $record $name)) { continue }
            $value = Field $record $name
            if (-not (IsInteger $value) -or ($value -ne 1 -and -not ($name -eq 'RequestCount' -and $value -eq 0))) {
                return 'IncompleteCommandEvidence'
            }
        }
        if (HasField $record 'Reason') {
            $reason = Field $record 'Reason'
            $acceptedReasons = [string[]]@('','Synthetic fixture, not tenant data.','Synthetic fixture','Fixture evidence')
            if ($reason -isnot [string] -or [array]::IndexOf($acceptedReasons,$reason) -lt 0) {
                return 'ConflictingCollectionReason'
            }
        }
        if (HasField $record 'Truncated') {
            $truncated = Field $record 'Truncated'
            if ($truncated -isnot [bool] -or $truncated) { return 'IncompleteSource' }
        }
        if (HasField $record 'Warnings') {
            $warnings = Field $record 'Warnings'
            if (-not (IsList $warnings) -or $warnings.Count -ne 0) { return 'IncompleteSource' }
        }
        foreach ($name in @('@odata.nextLink','NextLink','ContinuationToken')) {
            if (HasField $record $name) { return 'UnexpectedContinuation' }
        }
    }
    function CompareSavedValues {
        $metadata = Field $Result 'Metadata'
        if ((HasField $Result 'Metadata') -and $metadata -isnot [Collections.IDictionary] -and $metadata -isnot [pscustomobject]) {
            return 'InvalidReportMetadata'
        }
        $hasMode = $false
        foreach ($report in @($metadata,$Result)) {
            if (HasField $report 'Mode') { $hasMode = $true }
            if (HasField $report 'SelectedGroups') {
                $groups = Field $report 'SelectedGroups'
                if (-not (IsList $groups)) { return 'ExchangeNotSelected' }
                $exchange = $false
                foreach ($group in $groups) {
                    if ($group -isnot [string] -or [string]::IsNullOrWhiteSpace($group)) { return 'ExchangeNotSelected' }
                    if ([string]::Equals($group,'Exchange',[StringComparison]::OrdinalIgnoreCase)) { $exchange = $true }
                }
                if (-not $exchange) { return 'ExchangeNotSelected' }
            }
        }
        if (-not $hasMode) { return 'SyntheticModeRequired' }

        $summary = $null
        if (HasField $Result 'Evidence') {
            $source = FindSource (Field $Result 'Evidence')
            if (HasField $Result 'Coverage') {
                $summary = FindSource (Field $Result 'Coverage')
                if ($null -eq $summary -or (HasField $summary 'Items')) { return 'ConflictingCoverage' }
            }
        } else {
            $source = FindSource (Field $Result 'Coverage')
        }
        if ($null -eq $source) { return 'MissingOrAmbiguousSource' }
        $runId = $null
        foreach ($record in @($metadata,$Result,$source,$summary)) {
            if (HasField $record 'Mode') {
                $value = Field $record 'Mode'
                if ($value -isnot [string] -or -not [string]::Equals($value,'Synthetic',[StringComparison]::OrdinalIgnoreCase)) {
                    return 'SyntheticModeRequired'
                }
            }
            if (HasField $record 'TenantId') {
                $value = Field $record 'TenantId'
                if ($value -isnot [string] -or -not $value.Equals('SYNTHETIC-NOT-A-TENANT')) { return 'SyntheticIdentityMismatch' }
            }
            if (HasField $record 'RunId') {
                $id = Field $record 'RunId'
                if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id) -or
                    ($null -ne $runId -and -not $id.Equals($runId))) { return 'ConflictingReportIdentity' }
                $runId = $id
            }
        }
        $problem = ValidateSource $source $false
        if ($problem) { return $problem }
        if ($null -ne $summary) {
            $problem = ValidateSource $summary $true
            if ($problem) { return $problem }
            foreach ($name in @('Count','PageCount','RequestCount','Reason')) {
                if ((HasField $summary $name) -and (Field $summary $name) -cne (Field $source $name)) { return 'ConflictingCoverage' }
            }
        }
        $times = @{}
        foreach ($name in @('StartedAtUtc','FinishedAtUtc')) {
            if (HasField $metadata $name) {
                $times[$name] = UtcTime (Field $metadata $name)
                if ($null -eq $times[$name]) { return 'InvalidRunTime' }
            }
        }
        if ($times.Count -eq 2 -and $times.StartedAtUtc -gt $times.FinishedAtUtc) { return 'ConflictingRunTime' }
        $collected = $null
        foreach ($record in @($source,$summary)) {
            if (HasField $record 'CollectedAtUtc') {
                $time = UtcTime (Field $record 'CollectedAtUtc')
                if ($null -eq $time -or ($null -ne $collected -and $collected -ne $time) -or
                    ($times.ContainsKey('StartedAtUtc') -and $time -lt $times.StartedAtUtc) -or
                    ($times.ContainsKey('FinishedAtUtc') -and $time -gt $times.FinishedAtUtc)) { return 'ConflictingCollectionTime' }
                $collected = $time
            }
        }

        $items = Field $source 'Items'
        if (-not (IsList $items) -or $items.Count -ne (Field $source 'Count')) { return 'InvalidPolicyCollection' }
        $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $matched = 0
        foreach ($policy in $items) {
            # These markers belong to a collection envelope, never a projected policy.
            foreach ($name in @('SourceId','Group','Provider','Target','Mode','TenantId','RunId','Evidence','Coverage',
                                'Timeline','Collections','CasePath','@odata.nextLink','NextLink','ContinuationToken')) {
                if (HasField $policy $name) { return 'ConflictingPolicyProvenance' }
            }
            $identity = Field $policy 'Identity'
            if ($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or
                $identity -match '\p{Cc}' -or -not $identities.Add($identity.Trim())) { return 'MissingOrDuplicatePolicyIdentity' }
            $value = Field $policy 'AutoForwardingMode'
            if ($value -isnot [string]) { return 'MissingOrInvalidEnum' }
            if ($value.Equals('Automatic')) { $matched++ }
            elseif (-not $value.Equals('Off') -and -not $value.Equals('On')) { return 'MissingOrInvalidEnum' }
        }
        $counts.Matched = $matched
        $counts.Differing = $items.Count - $matched
        return 'ComparedAllSuppliedPolicies'
    }

    $reason = CompareSavedValues
    $status = 'Not assessed'
    $comparison = 'Unknown'
    $assessed = $null
    if ($reason -eq 'ComparedAllSuppliedPolicies') {
        $assessed = $counts.Matched + $counts.Differing
        if ($counts.Differing -eq 0) {
            $status = 'Meets selected setting'
            $comparison = 'MatchesWorkbookPredicate'
        } else {
            $status = 'Needs action'
            $comparison = 'DiffersFromWorkbookPredicate'
        }
    }
    [pscustomobject][ordered]@{
        PSTypeName = 'Flapjacks.WorkbookOutboundForwardingComparison'
        ControlId = 'WB-REF-92B9-ROW-076'; PhysicalRow = 76; RecommendationAuthority = 'Workbook'
        SourceId = $sourceId; Provider = 'Exchange'; Target = $commandName; Field = 'AutoForwardingMode'; Expected = 'Automatic'
        Status = $status; Comparison = $comparison; ReasonCode = $reason
        AssessedPolicyCount = $assessed; MatchedPolicies = $counts.Matched; DifferingPolicies = $counts.Differing
        Scope = 'Stored setting on every identified policy supplied in this synthetic source, including unassigned policies.'
        Limitation = 'Rule state, priority, assignment, exceptions, remote domains, mailbox settings and message delivery are unassessed.'
        EffectiveAccessVerified = $false; CompleteTenantCoverageVerified = $false
    }
}
