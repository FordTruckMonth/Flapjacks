#requires -Version 7.4
. (Join-Path $PSScriptRoot 'WorkbookOutboundForwarding.ps1')

# The opt-in reviewer passes passive JSON data from a saved schema 1.1 audit.json.
function Get-FlapjacksSyntheticOutboundForwardingComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    $unknown = [pscustomobject]@{Row=76; Comparison='Unknown'; Reason='IncompleteSyntheticOutboundPolicyEvidence'}
    function HasOnlyFields($Record, [string[]]$Fields) {
        if ($Record -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Record.psbase.Keys) {
            if ([array]::IndexOf($Fields,$key) -lt 0) { return $false }
        }
        return $true
    }
    function ExactText($Value, [string]$Text) {
        return $Value -is [string] -and $Value.Equals($Text,[StringComparison]::Ordinal)
    }
    function IsInteger($Value) { return $Value -is [long] -or $Value -is [int] }
    function IsIdentifier($Value) {
        if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
            $Value.Trim() -cne $Value -or $Value -match '[\p{Cc}\p{Cf}]' -or
            $Value -in @('Unknown','<unknown>','None','Null','N/A','Not applicable','Not provided','Not assessed','Unavailable')) { return $false }
        $guid = [guid]::Empty
        return -not ([guid]::TryParse($Value,[ref]$guid) -and $guid -eq [guid]::Empty)
    }

    if (-not (HasOnlyFields $Result @('Metadata','Coverage','Observations')) -or
        $Result['Coverage'] -isnot [array] -or $Result['Observations'] -isnot [array]) { return $unknown }
    $meta = $Result['Metadata']
    $fields = @('SchemaVersion','Mode','TenantId','StartedAtUtc','FinishedAtUtc','SelectedGroups','MaxPages','MaxRecords',
        'OrganizationWideConfirmed','AccountVerification','ToolVersion','PowerShellVersion','Scope','Privacy','WorkbookAntiPhishBaseline')
    if (-not (HasOnlyFields $meta $fields) -or -not (ExactText $meta['SchemaVersion'] '1.1') -or
        -not (ExactText $meta['Mode'] 'Synthetic') -or -not (ExactText $meta['TenantId'] 'SYNTHETIC-NOT-A-TENANT') -or
        $meta['SelectedGroups'] -isnot [array] -or $meta['OrganizationWideConfirmed'] -isnot [bool] -or
        $meta['OrganizationWideConfirmed'] -or -not (ExactText $meta['AccountVerification'] 'Synthetic: not applicable') -or
        -not (IsInteger $meta['MaxPages']) -or $meta['MaxPages'] -lt 1 -or $meta['MaxPages'] -gt 10000 -or
        -not (IsInteger $meta['MaxRecords']) -or $meta['MaxRecords'] -lt 1 -or $meta['MaxRecords'] -gt 1000000) { return $unknown }
    $catalogGroups = @('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange',
        'Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')
    $groups = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($group in $meta['SelectedGroups']) {
        if ($group -isnot [string] -or [array]::IndexOf($catalogGroups,$group) -lt 0 -or -not $groups.Add($group)) { return $unknown }
    }
    if (-not $groups.Contains('Core') -or -not $groups.Contains('Exchange')) { return $unknown }
    if ($meta.Contains('WorkbookAntiPhishBaseline') -and (-not $groups.Contains('WorkbookExchange') -or
        [array]::IndexOf(@('None','Standard','Strict'),$meta['WorkbookAntiPhishBaseline']) -lt 0)) { return $unknown }
    if ($groups.Contains('WorkbookIdentity')) {
        $scope = 'Current configuration and optional point-in-time identity attributes. Not event logs, effective-policy analysis or compliance certification.'
        $privacy = 'Optional workbook identity sources use selected directory fields, registration flags and last successful sign-in time, not sign-in events or mail content. Saved evidence may include object IDs and precise times. Keep local and access controlled.'
    } else {
        $scope = 'Current-state configuration snapshot only. Not a complete M365 inventory, effective-policy engine, vulnerability scan or certification.'
        $privacy = 'No users, sign-ins, mail content, credentials or OAuth grants queried. Policy targeting may contain names, IDs, addresses and infrastructure data. Keep local and access controlled.'
    }
    if (($meta.Contains('Scope') -and -not (ExactText $meta['Scope'] $scope)) -or
        ($meta.Contains('Privacy') -and -not (ExactText $meta['Privacy'] $privacy)) -or
        ($meta.Contains('ToolVersion') -and -not (ExactText $meta['ToolVersion'] '0.2.0-terminal')) -or
        ($meta.Contains('PowerShellVersion') -and ($meta['PowerShellVersion'] -isnot [string] -or
            $meta['PowerShellVersion'] -cnotmatch '\A\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?\z'))) { return $unknown }

    $id = 'exchange-outbound-spam-policies'
    $target = 'Get-HostedOutboundSpamFilterPolicy'
    $source = $null
    $sourceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Result['Coverage']) {
        if ($entry -isnot [Collections.IDictionary] -or 'SourceId' -cnotin $entry.psbase.Keys -or
            'Target' -cnotin $entry.psbase.Keys -or $entry['SourceId'] -isnot [string] -or
            $entry['SourceId'] -cnotmatch '\A[a-z][a-z0-9-]*\z' -or -not $sourceIds.Add($entry['SourceId']) -or
            $entry['Target'] -isnot [string] -or [string]::IsNullOrWhiteSpace($entry['Target']) -or
            $entry['Items'] -isnot [array] -or $entry['MissingFields'] -isnot [array] -or
            -not (IsInteger $entry['Count']) -or $entry['Count'] -ne $entry['Items'].Length) { return $unknown }
        if ($entry['SourceId'] -ceq $id) { $source = $entry; continue }
        # A second claimed inventory for this command would make policy scope ambiguous.
        if ($entry['Target'] -match '(?<![A-Za-z0-9-])Get-HostedOutboundSpamFilterPolicy(?![A-Za-z0-9-])') { return $unknown }
    }
    $sourceFields = @('SourceId','Group','Provider','Target','Status','Count','Items','MissingFields','Reason',
        'Notes','PageCount','RequestCount','CollectedAtUtc')
    if (-not (HasOnlyFields $source $sourceFields) -or -not (ExactText $source['Target'] $target) -or
        -not (ExactText $source['Reason'] 'Synthetic fixture, not tenant data.') -or -not (ExactText $source['Notes'] '') -or
        -not (IsInteger $source['RequestCount']) -or $source['RequestCount'] -ne 0 -or
        $source['Count'] -gt $meta['MaxRecords']) { return $unknown }
    # The pinned evaluator verifies calendar validity and orders the three native UTC timestamps.
    foreach ($stamp in $meta['StartedAtUtc'],$meta['FinishedAtUtc'],$source['CollectedAtUtc']) {
        if ($stamp -isnot [string] -or $stamp -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\z') { return $unknown }
    }
    $policyFields = @('Identity','Name','IsDefault','AutoForwardingMode','ActionWhenThresholdReached',
        'RecipientLimitExternalPerHour','RecipientLimitInternalPerHour','RecipientLimitPerDay','NotifyOutboundSpam','NotifyOutboundSpamRecipients')
    $aliases = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $source['Items']) {
        if (-not (HasOnlyFields $policy $policyFields) -or -not (IsIdentifier $policy['Identity']) -or
            -not $aliases.Add($policy['Identity'])) { return $unknown }
        if ($policy.Contains('Name') -and (-not (IsIdentifier $policy['Name']) -or
            (-not $policy['Name'].Equals($policy['Identity'],[StringComparison]::OrdinalIgnoreCase) -and
             -not $aliases.Add($policy['Name'])))) { return $unknown }
        foreach ($field in 'IsDefault','NotifyOutboundSpam') {
            if ($policy.Contains($field) -and $policy[$field] -isnot [bool]) { return $unknown }
        }
        foreach ($field in 'RecipientLimitExternalPerHour','RecipientLimitInternalPerHour','RecipientLimitPerDay') {
            if ($policy.Contains($field) -and (-not (IsInteger $policy[$field]) -or $policy[$field] -lt 0)) { return $unknown }
        }
        if ($policy.Contains('ActionWhenThresholdReached') -and ($policy['ActionWhenThresholdReached'] -isnot [string] -or
            [string]::IsNullOrWhiteSpace($policy['ActionWhenThresholdReached']))) { return $unknown }
        if ($policy.Contains('NotifyOutboundSpamRecipients')) {
            if ($policy['NotifyOutboundSpamRecipients'] -isnot [array]) { return $unknown }
            foreach ($recipient in $policy['NotifyOutboundSpamRecipients']) {
                if ($recipient -isnot [string] -or [string]::IsNullOrWhiteSpace($recipient)) { return $unknown }
            }
        }
    }
    $row = Get-FlapjacksWorkbookOutboundForwarding -Result $Result
    if ($row.Comparison -ceq 'Unknown') { return $unknown }
    $comparison = if ($row.Comparison -ceq 'MatchesWorkbookPredicate') { 'Matches' }
        elseif ($row.Comparison -ceq 'DiffersFromWorkbookPredicate') { 'Differs' }
        else { throw 'Unexpected stored outbound mode comparison.' }
    return [pscustomobject]@{Row=76; Comparison=$comparison; Reason='ComparedStoredOutboundForwardingMode'}
}
