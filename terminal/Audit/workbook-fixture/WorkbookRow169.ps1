#requires -Version 7.4
function Get-FlapjacksWorkbookRow169 {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)
    Set-StrictMode -Version Latest

    function Field($Object, [string]$Key) {
        if ($Object -is [Collections.IDictionary]) { return ,$Object[$Key] }
        if ($Object -is [pscustomobject]) {
            $member = $Object.PSObject.Properties[$Key]
            if ($member -is [System.Management.Automation.PSNoteProperty]) { return ,$member.Value }
        }
        return $null
    }
    function HasKey($Object, [string]$Key) {
        if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Key) }
        return $Object -is [pscustomobject] -and $null -ne $Object.PSObject.Properties[$Key]
    }
    function KnownFields($Object, $Allowed) {
        if ($Object -is [Collections.IDictionary]) { $keys = $Object.psbase.Keys }
        elseif ($Object -is [pscustomobject]) {
            foreach ($member in $Object.PSObject.Properties) {
                if ($member -isnot [System.Management.Automation.PSNoteProperty] -or $member.Name -cnotin $Allowed) { return $false }
            }
            return $true
        }
        else { return $false }
        foreach ($key in $keys) { if ($key -cnotin $Allowed) { return $false } }
        return $true
    }
    function Collection($Value) { return $Value -is [Collections.IList] -and ($Value -isnot [array] -or $Value.Rank -eq 1) }
    function Integer($Value) { return $Value -is [int] -or $Value -is [long] }
    function ReadIPv4([string]$Text) {
        if ($Text -cnotmatch '\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z') { return $null }
        [long]$number = 0
        foreach ($octet in $Text.Split('.')) {
            $part = [int]$octet
            if ($part -gt 255) { return $null }
            $number = 256 * $number + $part
        }
        return $number
    }
    function ValidEntry($Value) {
        if ($Value -isnot [string] -or $Value.Length -gt 31) { return $false }
        if ($Value.Contains('-')) {
            $parts = $Value.Split('-')
            if ($parts.Length -ne 2) { return $false }
            $first = ReadIPv4 $parts[0]
            $last = ReadIPv4 $parts[1]
            return $null -ne $first -and $null -ne $last -and $last -ge $first -and ($last - $first) -le 255
        }
        $parts = $Value.Split('/')
        return $null -ne (ReadIPv4 $parts[0]) -and ($parts.Length -eq 1 -or
            ($parts.Length -eq 2 -and $parts[1] -cmatch '\A(?:2[4-9]|3[0-2])\z'))
    }
    $sourceId = 'exchange-connection-filter-policies'
    $out = [pscustomobject][ordered]@{
        ControlId='WB-REF-92B9-ROW-169'; PhysicalRow=169; Control='Default connection-filter IP allow list'
        Status='Not assessed'; SourceId=$sourceId; SourceStatus='Unknown'; Field='IPAllowList'
        EvidenceIds=@(); EvidenceTime=''; Observed='No usable saved evidence.'
        Expected='IPAllowList contains zero entries on the policy named Default.'
        Rationale='Compares the stored configuration of the Default connection-filter policy.'
        Limitation='Source authenticity, freshness, tenant completeness and message behavior are unverified.'
        Reference='https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
    }
    $metadata = Field $Result 'Metadata'
    if (HasKey $metadata 'SelectedGroups') {
        $groups = Field $metadata 'SelectedGroups'
        if (-not (Collection $groups)) { $out.Observed='Invalid selected source groups.'; return $out }
        foreach ($groupName in $groups) {
            if ($groupName -isnot [string]) { $out.Observed='Invalid selected source groups.'; return $out }
        }
        if ('WorkbookExchange' -cnotin $groups) { $out.Observed='WorkbookExchange was not selected.'; return $out }
    }
    foreach ($key in @('Mode','TenantId','RunId')) {
        if ((HasKey $Result $key) -and (HasKey $metadata $key)) {
            $outer = Field $Result $key
            $inner = Field $metadata $key
            if ($outer -isnot [string] -or $inner -isnot [string] -or $outer -cne $inner) {
                $out.Observed='Contradictory report identity.'; return $out
            }
        }
    }
    $rows = Field $Result 'Evidence'
    if ($null -eq $rows -or ((Collection $rows) -and $rows.Count -eq 0)) { $rows = Field $Result 'Coverage' }
    if (-not (Collection $rows)) { return $out }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $source = $null
    foreach ($row in $rows) {
        $id = Field $row 'SourceId'
        if ($id -isnot [string] -or $id -cnotmatch '\A[a-z][a-z0-9-]{0,99}\z' -or -not $seen.Add($id)) {
            $out.Observed='Invalid or duplicate source identity.'; return $out
        }
        if ($id -ceq $sourceId) { $source = $row }
    }
    if ($null -eq $source) { return $out }
    $sourceFields = @('SourceId','Group','Provider','Target','Status','Reason','CollectedAtUtc','PageCount','RequestCount','Count','Items','MissingFields','Notes')
    if (-not (KnownFields $source $sourceFields)) { $out.Observed='Unexpected source metadata.'; return $out }
    $mode = Field $metadata 'Mode'
    $synthetic = $mode -is [string] -and $mode -ceq 'Synthetic'
    $reason = Field $source 'Reason'
    if ((HasKey $source 'Reason') -and ($reason -isnot [string] -or
        ($reason.Length -gt 0 -and -not ($synthetic -and $reason -cin @('Synthetic fixture, not tenant data.','Synthetic fixture','Fixture evidence'))))) {
        $out.Observed='Collected status has an inconsistent or unrecognized reason.'; return $out
    }
    foreach ($binding in @{Provider='Exchange';Target='Get-HostedConnectionFilterPolicy';Status='Collected'}.GetEnumerator()) {
        $v = Field $source $binding.Key
        if ($v -isnot [string] -or $v -cne $binding.Value) { $out.Observed='Source binding or collection status is invalid.'; return $out }
    }
    $group = Field $source 'Group'
    if ((HasKey $source 'Group') -and ($group -isnot [string] -or $group -cne 'WorkbookExchange')) { return $out }
    foreach ($key in @('PageCount','RequestCount')) {
        if (HasKey $source $key) {
            $v = Field $source $key
            $syntheticRequest = $key -ceq 'RequestCount' -and $synthetic -and $v -eq 0
            if (-not (Integer $v) -or ($v -ne 1 -and -not $syntheticRequest)) { return $out }
        }
    }
    $items = Field $source 'Items'
    $count = Field $source 'Count'
    $missing = Field $source 'MissingFields'
    if (-not (Collection $items) -or -not (Integer $count) -or $count -ne $items.Count -or
        $count -lt 1 -or -not (Collection $missing) -or $missing.Count -ne 0) {
        $out.Observed='Incomplete selected source records.'; return $out
    }
    $out.SourceStatus='Collected'
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $default = $null
    foreach ($item in $items) {
        if (-not (KnownFields $item @('Name','Identity','IPAllowList','IPBlockList','EnableSafeList'))) {
            $out.Observed='Unexpected policy metadata.'; return $out
        }
        $name = Field $item 'Name'
        $identity = Field $item 'Identity'
        foreach ($label in @($name,$identity)) {
            if ($label -isnot [string] -or [string]::IsNullOrWhiteSpace($label) -or $label -cne $label.Trim() -or $label -match '\p{Cc}') {
                $out.Observed='Policy identity or name is malformed.'; return $out
            }
        }
        if (-not $names.Add($name) -or -not $ids.Add($identity)) { $out.Observed='Duplicate policy name or identity.'; return $out }
        if ([string]::Equals($name,'Default',[StringComparison]::OrdinalIgnoreCase)) { $default = $item }
    }
    if ($null -eq $default) { $out.Observed='Default policy was absent.'; return $out }
    $entries = Field $default 'IPAllowList'
    if (-not (Collection $entries) -or $entries.Count -gt 1273) { $out.Observed='IPAllowList collection is missing or invalid.'; return $out }
    foreach ($entry in $entries) {
        if (-not (ValidEntry $entry)) { $out.Observed='IPAllowList contains an invalid projected entry.'; return $out }
    }
    $out.Status = if ($entries.Count -eq 0) { 'Meets selected setting' } else { 'Needs action' }
    $out.Observed = [string]$entries.Count + ' entries on the policy named Default.'
    $out.EvidenceIds = @('Default')
    return $out
}
