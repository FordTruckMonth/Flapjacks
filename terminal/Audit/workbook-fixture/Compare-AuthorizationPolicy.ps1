#requires -Version 7.4
# Input is the passive JSON representation of a saved schema 1.1 synthetic audit.json.
function Get-FlapjacksSyntheticAuthorizationPolicyComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    $unknown = [pscustomobject]@{Row=155; Comparison='Unknown'; Reason='IncompleteSyntheticAuthorizationPolicyEvidence'}
    function HasOnlyFields($Record, [string[]]$Fields) {
        if ($Record -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Record.psbase.Keys) {
            if ($key -isnot [string] -or [array]::IndexOf($Fields,$key) -lt 0) { return $false }
        }
        return $true
    }
    function IsText($Value, [string]$Expected) {
        return $Value -is [string] -and [string]::Equals($Value,$Expected,[StringComparison]::Ordinal)
    }
    function ReadUtc($Value) {
        $time = [datetimeoffset]::MinValue
        if ($Value -is [string] -and $Value -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\z' -and
            [datetimeoffset]::TryParse($Value,[cultureinfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$time)) {
            return $time
        }
    }

    # Saved audit.json carries the complete sources in Coverage. A second Evidence
    # inventory or a loose policy object is outside this input contract.
    if (-not (HasOnlyFields $Result @('Metadata','Coverage','Observations')) -or
        $Result['Coverage'] -isnot [array] -or $Result['Observations'] -isnot [array]) { return $unknown }
    $meta = $Result['Metadata']
    $metadataFields = @('SchemaVersion','Mode','TenantId','StartedAtUtc','FinishedAtUtc','SelectedGroups',
        'ToolVersion','PowerShellVersion','MaxPages','MaxRecords','OrganizationWideConfirmed','AccountVerification',
        'Scope','Privacy','WorkbookAntiPhishBaseline')
    if (-not (HasOnlyFields $meta $metadataFields) -or -not (IsText $meta['SchemaVersion'] '1.1') -or
        -not (IsText $meta['Mode'] 'Synthetic') -or -not (IsText $meta['TenantId'] 'SYNTHETIC-NOT-A-TENANT') -or
        $meta['SelectedGroups'] -isnot [array]) { return $unknown }
    if ($meta.Contains('OrganizationWideConfirmed') -and
        ($meta['OrganizationWideConfirmed'] -isnot [bool] -or $meta['OrganizationWideConfirmed'])) { return $unknown }
    if ($meta.Contains('AccountVerification') -and
        -not (IsText $meta['AccountVerification'] 'Synthetic: not applicable')) { return $unknown }
    $catalogGroups = @('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange',
        'Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')
    $groups = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($group in $meta['SelectedGroups']) {
        if ($group -isnot [string] -or [array]::IndexOf($catalogGroups,$group) -lt 0 -or
            -not $groups.Add($group)) { return $unknown }
    }
    if (-not $groups.Contains('Core')) { return $unknown }
    if ($meta.Contains('WorkbookAntiPhishBaseline') -and (-not $groups.Contains('WorkbookExchange') -or
        [array]::IndexOf(@('None','Standard','Strict'),$meta['WorkbookAntiPhishBaseline']) -lt 0)) { return $unknown }
    # The two native scope and privacy statements vary with WorkbookIdentity selection.
    if ($groups.Contains('WorkbookIdentity')) {
        $scope = 'Current configuration and optional point-in-time identity attributes. Not event logs, effective-policy analysis or compliance certification.'
        $privacy = 'Optional workbook identity sources use selected directory fields, registration flags and last successful sign-in time, not sign-in events or mail content. Saved evidence may include object IDs and precise times. Keep local and access controlled.'
    } else {
        $scope = 'Current-state configuration snapshot only. Not a complete M365 inventory, effective-policy engine, vulnerability scan or certification.'
        $privacy = 'No users, sign-ins, mail content, credentials or OAuth grants queried. Policy targeting may contain names, IDs, addresses and infrastructure data. Keep local and access controlled.'
    }
    if (($meta.Contains('Scope') -and -not (IsText $meta['Scope'] $scope)) -or
        ($meta.Contains('Privacy') -and -not (IsText $meta['Privacy'] $privacy))) { return $unknown }

    $source = $null
    $sourceId = 'authorization-policy'
    $target = '/policies/authorizationPolicy'
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Result['Coverage']) {
        if ($entry -isnot [Collections.IDictionary] -or 'SourceId' -cnotin $entry.psbase.Keys -or
            'Target' -cnotin $entry.psbase.Keys) { return $unknown }
        $id = $entry['SourceId']
        $route = $entry['Target']
        if ($id -isnot [string] -or $id -cnotmatch '\A[a-z][a-z0-9-]*\z' -or -not $seen.Add($id) -or
            $route -isnot [string] -or [string]::IsNullOrWhiteSpace($route)) { return $unknown }
        # Reject an alternate ID for the same resource, including a qualified URL,
        # a query or an escaped path. Only the literal catalog route can be used.
        $path = [uri]::UnescapeDataString($route.Split([char[]]'?#',2)[0]).Trim().TrimEnd('/')
        $policyRoute = $path.EndsWith($target,[StringComparison]::OrdinalIgnoreCase)
        if ($id -cne $sourceId -and -not $policyRoute) { continue }
        if ($null -ne $source -or -not (IsText $id $sourceId) -or -not (IsText $route $target)) { return $unknown }
        $source = $entry
    }
    $sourceFields = @('SourceId','Group','Provider','Target','Status','Reason','CollectedAtUtc','PageCount',
        'RequestCount','Count','Items','MissingFields','Notes')
    if (-not (HasOnlyFields $source $sourceFields) -or -not (IsText $source['Group'] 'Core') -or
        -not (IsText $source['Provider'] 'Graph') -or -not (IsText $source['Status'] 'Collected') -or
        $source['Items'] -isnot [array] -or $source['Items'].Length -ne 1 -or
        $source['MissingFields'] -isnot [array] -or $source['MissingFields'].Length -ne 0 -or
        -not (IsText $source['Notes'] '')) { return $unknown }
    foreach ($key in 'PageCount','Count','RequestCount') {
        if ($source[$key] -isnot [long] -and $source[$key] -isnot [int]) { return $unknown }
    }
    if ($source['PageCount'] -ne 1 -or $source['Count'] -ne 1) { return $unknown }
    $requestCount = $source['RequestCount']
    if ($requestCount -notin @(0,1) -or
        ($requestCount -eq 0 -and -not (IsText $source['Reason'] 'Synthetic fixture, not tenant data.')) -or
        ($requestCount -eq 1 -and -not (IsText $source['Reason'] ''))) { return $unknown }
    $start = ReadUtc $meta['StartedAtUtc']
    $finish = ReadUtc $meta['FinishedAtUtc']
    $captured = ReadUtc $source['CollectedAtUtc']
    if ($null -eq $start -or $null -eq $finish -or $null -eq $captured -or
        $captured -lt $start -or $captured -gt $finish) { return $unknown }

    $policy = $source['Items'][0]
    $policyFields = @('id','@odata.type','@odata.context','@odata.etag','@microsoft.graph.tips',
        'allowEmailVerifiedUsersToJoinOrganization','allowInvitesFrom','allowUserConsentForRiskyApps',
        'allowedToSignUpEmailBasedSubscriptions','allowedToUseSSPR','blockMsolPowerShell',
        'defaultUserRolePermissions','description','displayName','guestUserRoleId')
    if (-not (HasOnlyFields $policy $policyFields) -or -not (IsText $policy['id'] 'authorizationPolicy')) { return $unknown }
    if ($policy.Contains('@odata.type') -and -not (IsText $policy['@odata.type'] '#microsoft.graph.authorizationPolicy')) { return $unknown }
    $context = 'https://graph.microsoft.com/v1.0/$metadata#policies/authorizationPolicy/$entity'
    if ($policy.Contains('@odata.context') -and -not (IsText $policy['@odata.context'] $context)) { return $unknown }
    $role = $policy['defaultUserRolePermissions']
    $roleFields = @('allowedToCreateSecurityGroups','@odata.type','allowedToCreateApps','allowedToCreateTenants',
        'allowedToReadBitlockerKeysForOwnedDevice','allowedToReadOtherUsers','permissionGrantPoliciesAssigned')
    if (-not (HasOnlyFields $role $roleFields) -or $role['allowedToCreateSecurityGroups'] -isnot [bool]) { return $unknown }
    if ($role.Contains('@odata.type') -and -not (IsText $role['@odata.type'] '#microsoft.graph.defaultUserRolePermissions')) { return $unknown }
    $comparison = if ($role['allowedToCreateSecurityGroups']) { 'Differs' } else { 'Matches' }
    return [pscustomobject]@{Row=155; Comparison=$comparison; Reason='ComparedStoredDefaultRoleSwitch'}
}
