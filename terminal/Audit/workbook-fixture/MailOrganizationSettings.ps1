#requires -Version 7.4
. (Join-Path $PSScriptRoot '../src/MailBaselineProtection.ps1')
. (Join-Path $PSScriptRoot 'WorkbookGlobalSettings.ps1')

function Get-FlapjacksSyntheticMailOrganizationComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Result)

    # Accept passive saved-report dictionaries only. Keep both evidence inventories
    # intact when calling the reviewed evaluator, which checks their typed values.
    function Has-OnlyFields($Map, [string[]]$Allowed) {
        if ($Map -isnot [Collections.IDictionary]) { return $false }
        foreach ($key in $Map.psbase.Keys) {
            if ($key -isnot [string] -or $key -cnotin $Allowed) { return $false }
        }
        return $true
    }
    function Test-WorkbookPin($Map) {
        if (-not $Map.Contains('ReferenceWorkbookSha256')) { return $true }
        $pin=$Map['ReferenceWorkbookSha256']
        return $pin -is [string] -and $pin -ceq '92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
    }
    function Get-SourceInventory($Records) {
        if ($Records -isnot [Collections.IList]) { return $null }
        $index=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($record in $Records) {
            if ($record -isnot [Collections.IDictionary] -or 'SourceId' -cnotin $record.psbase.Keys) { return $null }
            $id=$record['SourceId']
            if ($id -isnot [string] -or $id -cnotmatch '\A[a-z][a-z0-9-]{0,99}\z' -or -not $index.TryAdd($id,$record)) { return $null }
        }
        return ,$index
    }
    function Test-OrganizationFixture {
        $reportFields=@('Metadata','Evidence','Coverage','Observations','Mode','TenantId','RunId','ReferenceWorkbookSha256',
            'OutputPath','SelectedCount','CollectedCount','IncompleteCount','FindingCount')
        $metadataFields=@('SchemaVersion','ToolVersion','Mode','TenantId','RunId','ReferenceWorkbookSha256','StartedAtUtc',
            'FinishedAtUtc','PowerShellVersion','SelectedGroups','MaxPages','MaxRecords','OrganizationWideConfirmed',
            'AccountVerification','Scope','Privacy','WorkbookAntiPhishBaseline')
        if (-not (Has-OnlyFields $Result $reportFields) -or -not (Test-WorkbookPin $Result)) { return $false }
        $metadata=$Result['Metadata']
        if (-not (Has-OnlyFields $metadata $metadataFields) -or -not (Test-WorkbookPin $metadata)) { return $false }
        if ($metadata.Contains('SchemaVersion') -and ($metadata['SchemaVersion'] -isnot [string] -or
            $metadata['SchemaVersion'] -cne '1.1')) { return $false }
        if ($metadata['Mode'] -isnot [string] -or $metadata['Mode'] -cne 'Synthetic' -or
            $metadata['TenantId'] -isnot [string] -or $metadata['TenantId'] -cne 'SYNTHETIC-NOT-A-TENANT' -or
            $metadata['StartedAtUtc'] -isnot [string] -or $metadata['FinishedAtUtc'] -isnot [string] -or
            $metadata['SelectedGroups'] -isnot [Collections.IList]) { return $false }
        $catalogGroups=@('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange',
            'Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')
        $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($group in $metadata['SelectedGroups']) {
            if ($group -isnot [string] -or $group -cnotin $catalogGroups -or -not $selected.Add($group)) { return $false }
        }
        if (-not $selected.Contains('Exchange') -or -not $selected.Contains('WorkbookExchange')) { return $false }
        if ($metadata.Contains('OrganizationWideConfirmed') -and
            ($metadata['OrganizationWideConfirmed'] -isnot [bool] -or $metadata['OrganizationWideConfirmed'])) { return $false }
        if ($metadata.Contains('AccountVerification') -and ($metadata['AccountVerification'] -isnot [string] -or
            $metadata['AccountVerification'] -cne 'Synthetic: not applicable')) { return $false }

        $evidence=$null
        $coverage=$null
        if ($Result.Contains('Evidence')) {
            $evidence=Get-SourceInventory $Result['Evidence']
            if ($null -eq $evidence -or $evidence.psbase.Count -eq 0) { return $false }
        }
        if ($Result.Contains('Coverage')) {
            $coverage=Get-SourceInventory $Result['Coverage']
            if ($null -eq $coverage) { return $false }
        }
        $id='exchange-atp-organization'
        $full=$coverage
        $summary=$null
        if ($null -ne $evidence) {
            $full=$evidence
            if ($null -ne $coverage) {
                if ($coverage.psbase.Count -ne $evidence.psbase.Count) { return $false }
                foreach ($key in $evidence.psbase.Keys) {
                    if (-not $coverage.ContainsKey($key)) { return $false }
                }
                if (-not $coverage.ContainsKey($id)) { return $false }
                $summary=$coverage[$id]
            }
        }
        if ($null -eq $full -or -not $full.ContainsKey($id)) { return $false }
        $source=$full[$id]
        $sourceFields=@('SourceId','Group','Provider','Target','Status','Count','Items','MissingFields','Reason',
            'Notes','PageCount','RequestCount','CollectedAtUtc','Truncated','Warnings','TenantId','RunId','Mode')
        if (-not (Has-OnlyFields $source $sourceFields) -or $source['CollectedAtUtc'] -isnot [string] -or
            ($source['PageCount'] -isnot [int] -and $source['PageCount'] -isnot [long]) -or $source['PageCount'] -ne 1 -or
            ($source['RequestCount'] -isnot [int] -and $source['RequestCount'] -isnot [long]) -or $source['RequestCount'] -ne 0) { return $false }
        foreach ($record in $Result,$source) {
            if ($record.Contains('RunId') -and -not $metadata.Contains('RunId')) { return $false }
        }
        if ($source.Contains('Notes') -and ($source['Notes'] -isnot [string] -or $source['Notes'] -cnotin @('',
            'Selected Defender settings only; Safe Documents requires its own eligible licensing.'))) { return $false }
        if ($source['Items'] -isnot [Collections.IList] -or $source['Items'].Count -ne 1) { return $false }
        $org=$source['Items'][0]
        if (-not (Has-OnlyFields $org @('Identity','EnableATPForSPOTeamsODB','EnableSafeDocs','AllowSafeDocsOpen'))) { return $false }
        $identity=$org['Identity']
        if ($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or $identity.Trim() -cne $identity -or
            $identity -match '[\p{Cc}\p{Cf}]' -or
            $identity -in @('Unknown','<unknown>','None','Null','N/A','Not applicable','Not provided','Not assessed','Unavailable')) { return $false }
        $guid=[guid]::Empty
        if ([guid]::TryParse($identity,[ref]$guid) -and $guid -eq [guid]::Empty) { return $false }
        if ($null -ne $summary) {
            # The released in-memory summary always projects these eight fields.
            # Permit additional native source metadata only when the full record
            # corroborates it. A second full record is ambiguous.
            $required=@('SourceId','Group','Provider','Status','Count','Reason','MissingFields','Notes')
            if (-not (Has-OnlyFields $summary $sourceFields) -or $summary.Contains('Items')) { return $false }
            foreach ($field in $required) {
                if (-not $summary.Contains($field)) { return $false }
            }
            foreach ($field in $summary.psbase.Keys) {
                if (-not $source.Contains($field)) { return $false }
                $value=ConvertTo-Json -InputObject $source[$field] -Depth 40 -Compress -WarningAction Stop
                $parallel=ConvertTo-Json -InputObject $summary[$field] -Depth 40 -Compress -WarningAction Stop
                if ($value -cne $parallel) { return $false }
            }
        }
        return $true
    }
    if (-not (Test-OrganizationFixture)) {
        foreach ($row in 83,84) {
            [pscustomobject]@{Row=$row;Comparison='Unknown';Reason='MailOrganizationFixtureRefused'}
        }
        return
    }
    foreach ($row in Get-FlapjacksWorkbookGlobalSettings -Result $Result) {
        $comparison=switch -CaseSensitive ($row.Status) {
            'Meets selected setting' { 'Matches' }
            'Needs action' { 'Differs' }
            'Not assessed' { 'Unknown' }
            default { throw 'Unexpected organization fixture comparison.' }
        }
        [pscustomobject]@{Row=$row.PhysicalRow;Comparison=$comparison;Reason=$row.ReasonCode}
    }
}
