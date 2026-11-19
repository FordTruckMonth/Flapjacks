#requires -Version 7.4
# v2 fixture-pack input is the ProjectedCollaboration array decoded by PassiveJson.ps1.
function Get-FlapjacksAdditionalCollaborationComparison {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Evidence)

    function Get-StoredComparison([int]$Row, [string]$SourceId, [string]$Target) {
        $records = @($Evidence | Where-Object {
            $_ -is [Collections.IDictionary] -and $_['SourceId'] -is [string] -and $_['SourceId'] -ieq $SourceId
        })
        if ($records.Count -ne 1) { return 'Unknown' }
        $record = $records[0]
        $required = @{
            SourceId=$SourceId; Target=$Target; Group='WorkbookCollaboration'
            Provider='OfflineSnapshot'; Status='OfflineSnapshot'
        }
        foreach ($key in 'Command','RequiredNativeCommand') {
            if ($record.Contains($key)) { $required[$key] = $Target }
        }
        foreach ($key in $required.Keys) {
            if ($record[$key] -isnot [string] -or $record[$key] -cne $required[$key]) { return 'Unknown' }
        }

        $provenance = $record['Provenance']
        if ($provenance -isnot [Collections.IDictionary]) { return 'Unknown' }
        $required = @{
            Kind='AlreadyCollected'; ScopeVerification='Unverified'
            OriginalStatus='Collected'; RequiredNativeCommand=$Target
        }
        if ($provenance.Contains('Command')) { $required['Command'] = $Target }
        foreach ($key in $required.Keys) {
            if ($provenance[$key] -isnot [string] -or $provenance[$key] -cne $required[$key]) { return 'Unknown' }
        }
        foreach ($key in 'PageCount','RequestCount') {
            if ($Row -eq 140 -and -not $record.Contains($key)) { continue }
            $value = $record[$key]
            if (($value -isnot [int] -and $value -isnot [long]) -or $value -ne 0) { return 'Unknown' }
        }
        $stamp = $record['CollectedAtUtc']
        $parsed = [DateTimeOffset]::MinValue
        if ($stamp -isnot [string] -or
            $stamp -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|\+00:00)\z' -or
            -not [DateTimeOffset]::TryParse($stamp, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            return 'Unknown'
        }
        $count = $record['Count']
        $items = $record['Items']
        if ($record['SnapshotComplete'] -isnot [bool] -or -not $record['SnapshotComplete'] -or
            ($count -isnot [int] -and $count -isnot [long]) -or $count -ne 1 -or
            $items -isnot [Collections.IList] -or $items.Count -ne 1 -or $items[0] -isnot [Collections.IDictionary]) {
            return 'Unknown'
        }
        $item = $items[0]
        $missing = $record['MissingFields']
        if ($missing -isnot [Collections.IList]) { return 'Unknown' }
        if ($Row -eq 176) {
            $name = $item['Name']
            $enabled = $item['ZapEnabled']
            if ($missing.Count -ne 0 -or $name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or
                $enabled -isnot [bool]) { return 'Unknown' }
            if ($enabled) { return 'Matches' }
            return 'Differs'
        }

        $enabled = $item['ExternalUserExpirationRequired']
        if ($enabled -isnot [bool]) { return 'Unknown' }
        foreach ($field in $missing) {
            if ($field -isnot [string] -or [string]::IsNullOrWhiteSpace($field) -or
                $field.Trim() -ieq 'ExternalUserExpirationRequired' -or
                ($enabled -and $field.Trim() -ieq 'ExternalUserExpireInDays')) { return 'Unknown' }
        }
        if (-not $enabled) { return 'Differs' }
        $days = $item['ExternalUserExpireInDays']
        if (($days -is [int] -or $days -is [long]) -and $days -ge 30 -and $days -le 730) { return 'Matches' }
        return 'Unknown'
    }

    [pscustomobject]@{ Row=140; Comparison=(Get-StoredComparison 140 'workbook-spo-tenant' 'Get-SPOTenant') }
    [pscustomobject]@{ Row=176; Comparison=(Get-StoredComparison 176 'workbook-teams-protection' 'Get-TeamsProtectionPolicy') }
}
