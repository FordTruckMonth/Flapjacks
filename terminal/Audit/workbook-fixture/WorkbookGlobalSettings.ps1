#requires -Version 7.4
# Compare two global settings in a single saved audit. The protection definitions supply
# the existing control IDs, display labels and Microsoft references.
function Get-FlapjacksWorkbookGlobalSettings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    Set-StrictMode -Version Latest
    $sourceId = 'exchange-atp-organization'
    $commandName = 'Get-AtpPolicyForO365'
    $context = @{ Organization = $null; SourceStatus = 'Unknown'; EvidenceTime = '' }

    function Field($record, [string]$name) {
        if ($record -is [Collections.IDictionary]) {
            # ConvertFrom-Json -AsHashtable preserves case-colliding JSON keys.
            # A bound field must have one unambiguous spelling in this report.
            $found = $false
            foreach ($key in $record.psbase.Keys) {
                if ($key -is [string] -and [string]::Equals($key,$name,[StringComparison]::OrdinalIgnoreCase)) {
                    if ($found -or $key -cne $name) { return $null }
                    $found = $true
                }
            }
            if ($found) { return ,$record[$name] }
            return $null
        }
        if ($record -is [pscustomobject]) {
            $member = $record.PSObject.Properties[$name]
            if ($member -is [System.Management.Automation.PSNoteProperty] -and $member.Name -ceq $name) { return ,$member.Value }
        }
        return $null
    }
    function HasField($record, [string]$name) {
        if ($record -is [Collections.IDictionary]) { return $name -in $record.psbase.Keys }
        return $record -is [pscustomobject] -and $null -ne $record.PSObject.Properties[$name]
    }
    function IsList($value) {
        return $value -is [Collections.IList] -and ($value -isnot [array] -or $value.Rank -eq 1)
    }
    function IsInteger($value) {
        return $value -is [int] -or $value -is [long] -or $value -is [uint32] -or
            $value -is [uint64] -or $value -is [int16] -or $value -is [uint16] -or
            $value -is [byte] -or $value -is [sbyte]
    }
    function UtcTime($value) {
        if ($value -is [datetimeoffset]) { return $value.UtcDateTime }
        if ($value -is [datetime] -and $value.Kind -ne [DateTimeKind]::Unspecified) { return $value.ToUniversalTime() }
        if ($value -is [string] -and $value -cmatch '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z') {
            $time = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse($value, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$time)) { return $time.UtcDateTime }
        }
        return $null
    }
    function FindSource($rows) {
        if (-not (IsList $rows)) { return $null }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $source = $null
        foreach ($row in $rows) {
            $id = Field $row 'SourceId'
            if ($id -isnot [string] -or $id -cnotmatch '\A[a-z][a-z0-9-]{0,99}\z' -or -not $seen.Add($id)) { return $null }
            if ($id -ceq $sourceId) { $source = $row }
        }
        return ,$source
    }
    function CheckSource($source, [bool]$summary) {
        foreach ($binding in @{Group='Exchange'; Provider='Exchange'; Target=$commandName}.GetEnumerator()) {
            if ($summary -and $binding.Key -ceq 'Target' -and -not (HasField $source 'Target')) { continue }
            $value = Field $source $binding.Key
            if ($value -isnot [string] -or $value -cne $binding.Value) {
                return 'SourceBindingMismatch', 'The source does not match the expected Exchange group, provider and command.'
            }
        }
        $state = Field $source 'Status'
        if ($state -isnot [string] -or $state -cne 'Collected') {
            return 'IncompleteSource', 'The saved source does not record a complete successful read.'
        }
        if (HasField $source 'Truncated') {
            $truncated = Field $source 'Truncated'
            if ($truncated -isnot [bool] -or $truncated) {
                return 'IncompleteSource', 'The saved source does not confirm an untruncated read.'
            }
        }
        if (HasField $source 'Warnings') {
            $warnings = Field $source 'Warnings'
            if (-not (IsList $warnings) -or $warnings.Count -ne 0) {
                return 'IncompleteSource', 'The saved source has warnings or malformed warning metadata.'
            }
        }
        $missing = Field $source 'MissingFields'
        if (-not (IsList $missing) -or $missing.Count -ne 0) {
            return 'IncompleteProjection', 'The source does not confirm a complete projection.'
        }
        $count = Field $source 'Count'
        if (-not (IsInteger $count) -or $count -ne 1) {
            return 'InvalidRecordCount', 'The source must report exactly one organization record.'
        }
        if (HasField $source 'Reason') {
            $reason = Field $source 'Reason'
            $fixtureReasons = @('Synthetic fixture, not tenant data.','Synthetic fixture','Fixture evidence')
            if ($reason -isnot [string] -or ($reason.Length -gt 0 -and (-not $synthetic -or $reason -cnotin $fixtureReasons))) {
                return 'ConflictingCollectionReason', 'The collection reason conflicts with a successful source read.'
            }
        }
        foreach ($name in @('PageCount','RequestCount')) {
            if (HasField $source $name) {
                $number = Field $source $name
                if (-not (IsInteger $number) -or ($number -ne 1 -and -not ($synthetic -and $name -ceq 'RequestCount' -and $number -eq 0))) {
                    return 'IncompleteCommandEvidence', 'Collection counters do not support a complete organization read.'
                }
            }
        }
    }
    function ReadOrganization {
        $metadata = Field $Result 'Metadata'
        if ((HasField $Result 'Metadata') -and $metadata -isnot [Collections.IDictionary] -and $metadata -isnot [pscustomobject]) {
            return 'InvalidReportMetadata', 'The saved report metadata is malformed.'
        }
        foreach ($container in @($metadata,$Result)) {
            if (HasField $container 'SelectedGroups') {
                $groups = Field $container 'SelectedGroups'
                if (-not (IsList $groups) -or 'Exchange' -notin $groups -or 'WorkbookExchange' -notin $groups) {
                    return 'GroupSelectionMismatch', 'The saved selection does not include both Exchange and WorkbookExchange.'
                }
                foreach ($group in $groups) {
                    if ($group -isnot [string] -or [string]::IsNullOrWhiteSpace($group)) {
                        return 'GroupSelectionMismatch', 'The saved group selection is malformed.'
                    }
                }
            }
        }
        $rows = Field $Result 'Evidence'
        $coverage = Field $Result 'Coverage'
        if ((HasField $Result 'Evidence') -and $null -eq $rows) {
            return 'InvalidEvidenceCollection', 'The saved evidence collection is malformed.'
        }
        $hasEvidence = $null -ne $rows -and -not ((IsList $rows) -and $rows.Count -eq 0)
        if (-not $hasEvidence) { $rows = $coverage }
        $source = FindSource $rows
        if ($null -eq $source) { return 'MissingOrAmbiguousSource', 'The saved report lacks a uniquely identified organization source.' }
        # In-memory reports carry a coverage summary alongside evidence. audit.json
        # instead puts full records in Coverage. Never combine two full projections.
        $summary = $null
        if ($hasEvidence -and (HasField $Result 'Coverage')) {
            $summary = FindSource $coverage
            if ($null -eq $summary -or (HasField $summary 'Items')) {
                return 'ConflictingCoverage', 'The coverage summary is absent, ambiguous or conflicts with the evidence.'
            }
        }
        $identityMarkers = @{}
        foreach ($container in @($metadata,$Result,$source,$summary)) {
            foreach ($key in @('Mode','TenantId','RunId')) {
                if (-not (HasField $container $key)) { continue }
                $marker = Field $container $key
                if ($marker -isnot [string] -or [string]::IsNullOrWhiteSpace($marker)) {
                    return 'InvalidReportIdentity', 'The saved report contains malformed run or organization metadata.'
                }
                if ($key -ceq 'Mode') { $marker = $marker.ToUpperInvariant() }
                if ($identityMarkers.ContainsKey($key) -and $identityMarkers[$key] -cne $marker) {
                    return 'ConflictingReportIdentity', 'The saved report contains conflicting run or organization metadata.'
                }
                $identityMarkers[$key] = $marker
            }
        }
        $synthetic = $identityMarkers['Mode'] -ceq 'SYNTHETIC'
        $problem = @(CheckSource $source $false)
        if ($problem.Count) { return $problem }
        if ($null -ne $summary) {
            $problem = @(CheckSource $summary $true)
            if ($problem.Count) { return $problem }
        }
        $items = Field $source 'Items'
        if (-not (IsList $items) -or $items.Count -ne 1) {
            return 'InvalidOrganizationCollection', 'The returned collection must contain exactly one organization record.'
        }
        $organization = $items[0]
        $identity = Field $organization 'Identity'
        if ($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or $identity -match '\p{Cc}') {
            return 'InvalidOrganizationIdentity', 'The single organization record lacks a usable identity.'
        }

        $bounds = @{}
        foreach ($key in @('StartedAtUtc','FinishedAtUtc')) {
            if (HasField $metadata $key) {
                $bounds[$key] = UtcTime (Field $metadata $key)
                if ($null -eq $bounds[$key]) { return 'InvalidEvidenceTime', 'The supplied collection or run timestamp is invalid.' }
            }
        }
        if ($bounds.Count -eq 2 -and $bounds.StartedAtUtc -gt $bounds.FinishedAtUtc) {
            return 'ConflictingEvidenceTime', 'The collection and run timestamps are inconsistent.'
        }
        $primaryTime = $null
        foreach ($container in @($source,$summary)) {
            if (-not (HasField $container 'CollectedAtUtc')) { continue }
            $stamp = UtcTime (Field $container 'CollectedAtUtc')
            if ($null -eq $stamp) { return 'InvalidEvidenceTime', 'The supplied collection or run timestamp is invalid.' }
            if (($bounds.ContainsKey('StartedAtUtc') -and $stamp -lt $bounds.StartedAtUtc) -or
                ($bounds.ContainsKey('FinishedAtUtc') -and $stamp -gt $bounds.FinishedAtUtc) -or
                ($null -ne $primaryTime -and $stamp -ne $primaryTime)) {
                return 'ConflictingEvidenceTime', 'The collection and run timestamps are inconsistent.'
            }
            $primaryTime = $stamp
        }
        if ($null -ne $primaryTime) { $context.EvidenceTime = $primaryTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
        $context.Organization = $organization
        $context.SourceStatus = 'Collected'
    }

    $problem = @(ReadOrganization)
    $anchors = @{'MDO-ORG-COLLAB'=83; 'MDO-ORG-SAFEDOCS'=84}
    foreach ($def in Get-FlapjacksMailBaselineProtectionDefinitions) {
        if (-not $anchors.ContainsKey($def.Id)) { continue }
        $status = 'Not assessed'
        if ($problem.Count) {
            $reasonCode, $observed = $problem
        } else {
            $value = Field $context.Organization $def.Field
            if ($value -is [bool]) {
                $status = if ($value) { 'Meets selected setting' } else { 'Needs action' }
                $reasonCode = if ($value) { 'SettingEnabled' } else { 'SettingDisabled' }
                $observed = $def.Field + ' = ' + $value.ToString().ToLowerInvariant() + '.'
            } else {
                $reasonCode = 'MissingOrInvalidBoolean'
                $observed = 'The saved ' + $def.Field + ' value is missing, null or not a Boolean.'
            }
        }
        [pscustomobject][ordered]@{
            ControlId=$def.Id; PhysicalRow=$anchors[$def.Id]; Control=$def.Name; Status=$status; ReasonCode=$reasonCode
            SourceId=$sourceId; Provider='Exchange'; Target=$commandName; Field=$def.Field; SourceStatus=$context.SourceStatus
            EvidenceIds=@(); EvidenceTime=$context.EvidenceTime; Observed=$observed
            Expected=('Microsoft global recommendation: ' + $def.Field + ' = true.'); Rationale=$def.Rationale
            Limitation=$def.Limitation; Reference=$def.Reference; ProfileVersion='Flapjacks Microsoft global mail policy 0.1'
            NistCsf20EvidenceMapping='PR.PS-01'; NistFramework='NIST CSF 2.0'
            NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
            NistMappingNote='Analyst-selected supporting evidence only; not NIST outcome attainment.'
            AccessPrerequisites=$def.Access; Section=$def.Section; RecommendationAuthority='Microsoft'; StatusDetailsSafe=$observed
        }
    }
}
