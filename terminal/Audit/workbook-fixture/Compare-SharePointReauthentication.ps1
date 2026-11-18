#requires -Version 7.4
function Get-FlapjacksSyntheticSharePointReauthenticationComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$ProjectedJson)

    $unknown = [pscustomobject]@{Row=141; Comparison='Unknown'; Reason='IncompleteProjectedEvidence'}
    $sourceId = 'workbook-spo-tenant'
    $target = 'Get-SPOTenant'
    $module = 'Microsoft.Online.SharePoint.PowerShell'

    function Test-ClaimLabels([Text.Json.JsonElement]$Node, [switch]$InProvenance) {
        if ($Node.ValueKind -ne 'Object') { return $false }
        foreach ($member in $Node.EnumerateObject()) {
            if ($member.Name -ieq 'Provenance' -and -not $InProvenance) {
                if (Test-ClaimLabels $member.Value -InProvenance) { return $true }
            } elseif ($member.Value.ValueKind -eq 'String') {
                $text = $member.Value.GetString().Trim()
                if ($member.Name -ieq 'SourceId' -and $text.Equals($sourceId,[StringComparison]::OrdinalIgnoreCase)) { return $true }
                if ($member.Name -iin @('Target','Command','RequiredNativeCommand') -and
                    $text -imatch '\A(?:[a-z0-9_.-]+\\)?Get-SPOTenant(?:\s|\z)') { return $true }
            }
        }
        return $false
    }
    function Test-Fields($Map, [string[]]$Fields) {
        if ($Map -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Map.psbase.Keys) {
            if ([array]::IndexOf($Fields,$key) -lt 0) { return $false }
        }
        return $true
    }
    function Test-Labels($Map, $Labels, [switch]$OptionalText) {
        foreach ($key in $Labels.Keys) {
            $value = $Map[$key]
            if ($OptionalText -and (-not $Map.Contains($key) -or ($value -is [string] -and $value.Length -eq 0))) { continue }
            if ($value -isnot [string] -or -not $value.Equals($Labels[$key],[StringComparison]::Ordinal)) { return $false }
        }
        return $true
    }

    # Inspect labels before deserializing: a malformed or duplicate-key record
    # may still claim this singleton. An unrelated damaged record has no claim.
    if ($ProjectedJson -isnot [Text.Json.JsonElement] -or $ProjectedJson.ValueKind -ne 'Array') { return $unknown }
    $sourceJson = $null
    foreach ($node in $ProjectedJson.EnumerateArray()) {
        if (Test-ClaimLabels $node) {
            if ($null -ne $sourceJson) { return $unknown }
            $sourceJson = $node
        }
    }
    if ($null -eq $sourceJson) { return $unknown }
    try { $source = ConvertFrom-FjcJson $sourceJson.GetRawText() }
    catch {
        if ($_.Exception.Message -cne 'Invalid JSON: use bounded passive JSON with unique property names and supported numbers.') { throw }
        return $unknown
    }

    $aliases = @{Command=$target; RequiredNativeCommand=$target; NativeModule=$module; OriginalProvider=$module}
    $sourceFields = @('SourceId','Group','Provider','Target','Status','Reason','Notes','SnapshotComplete',
        'MissingFields','Items','Count','PageCount','RequestCount','CollectedAtUtc','Provenance') + @($aliases.Keys)
    if (-not (Test-Fields $source $sourceFields) -or -not (Test-Labels $source @{
        SourceId=$sourceId; Group='WorkbookCollaboration'; Provider='OfflineSnapshot'; Target=$target; Status='OfflineSnapshot'
    })) { return $unknown }
    $origin = $source['Provenance']
    if (-not (Test-Fields $origin (@('Kind','ScopeVerification','OriginalStatus','Note') + @($aliases.Keys))) -or
        -not (Test-Labels $origin @{Kind='AlreadyCollected'; ScopeVerification='Unverified'; OriginalStatus='Collected'; RequiredNativeCommand=$target})) {
        return $unknown
    }
    # A complete native projection writes these fixed messages. Additional
    # diagnostic text on Reason describes an incomplete input.
    if (-not (Test-Labels $source @{
        Reason='Unverified offline scope; never a successful tenant collection. '
        Notes='Offline snapshot only. Exact current tenant and account cannot be verified by this adapter. No live collector, authentication, installation, permission grant, or coverage pass.'
    } -OptionalText) -or -not (Test-Labels $origin @{
        Note='OriginalStatus and timestamp are supplier claims. RequiredNativeCommand is a requirement, not proof of execution. Tenant, account and freshness have not been verified.'
    } -OptionalText)) { return $unknown }
    foreach ($record in $source,$origin) {
        foreach ($key in $aliases.Keys) {
            if ($record.Contains($key) -and -not (Test-Labels $record @{$key=$aliases[$key]})) { return $unknown }
        }
    }
    foreach ($key in 'Count','PageCount','RequestCount') {
        if ($source[$key] -isnot [long]) { return $unknown }
    }
    if ($source['Count'] -ne 1 -or $source['PageCount'] -ne 0 -or $source['RequestCount'] -ne 0 -or
        $source['SnapshotComplete'] -isnot [bool] -or -not $source['SnapshotComplete'] -or
        $source['Items'] -isnot [array] -or $source['Items'].Length -ne 1 -or
        $source['MissingFields'] -isnot [array]) { return $unknown }
    $stamp = $source['CollectedAtUtc']
    $time = [datetimeoffset]::MinValue
    if ($stamp -isnot [string] -or $stamp -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)\z' -or
        -not [datetimeoffset]::TryParse($stamp,[cultureinfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$time)) { return $unknown }

    $switchField = 'EmailAttestationRequired'
    $daysField = 'EmailAttestationReAuthDays'
    $item = $source['Items'][0]
    # These are the SPO tenant fields in the native projection and its reviewed
    # fixture extensions. A site, user, or policy object is a different input.
    $fields = @('SharingCapability','CoreSharingCapability','OneDriveSharingCapability','DefaultSharingLinkType',
        'DefaultLinkPermission','CoreDefaultShareLinkScope','OneDriveDefaultShareLinkScope','CoreDefaultShareLinkRole',
        'OneDriveDefaultShareLinkRole','CoreDefaultLinkToExistingAccess','OneDriveDefaultLinkToExistingAccess',
        'DisallowInfectedFileDownload','ExternalUserExpirationRequired','ExternalUserExpireInDays',$switchField,$daysField)
    if (-not (Test-Fields $item $fields) -or $item[$switchField] -isnot [bool]) { return $unknown }
    $enabled = $item[$switchField]
    foreach ($field in $source['MissingFields']) {
        if ($field -isnot [string] -or [string]::IsNullOrWhiteSpace($field) -or $field.Trim() -ieq $switchField -or
            ($enabled -and $field.Trim() -ieq $daysField)) { return $unknown }
    }
    $comparison = 'Differs'
    if ($enabled) {
        $days = $item[$daysField]
        if ($days -isnot [long] -or $days -lt 1 -or $days -gt 365) { return $unknown }
        if ($days -le 15) { $comparison = 'Matches' }
    }
    return [pscustomobject]@{Row=141; Comparison=$comparison; Reason='ComparedProjectedSetting'}
}
