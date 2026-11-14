function Get-M365AuditPlan {
    [CmdletBinding()]
    param([ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview')][string[]]$Include=@())
    $selected=@(Get-AuditSourceCatalog | Where-Object { $_.Group -eq 'Core' -or $_.Group -in $Include })
    # Each source's first scope is the documented least-privileged option. Existing Policy.Read.All
    # covers Authentication as well, so do not request an unnecessary extra scope in the combined plan.
    $scopes=@($selected | Where-Object Provider -eq 'Graph' | ForEach-Object { $_.Scopes[0] } | Sort-Object -Unique)
    if ('Policy.Read.All' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'Policy.Read.AuthenticationMethod' }) }
    if ('RoleManagement.Read.Directory' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'RoleEligibilitySchedule.Read.Directory' }) }
    [pscustomobject]@{ SchemaVersion='1.1'; ToolVersion='0.2.0-terminal'; ReadOnly=$true; Cloud='Global';
        SelectedGroups=@('Core')+@($Include | Sort-Object -Unique); GraphReadPermissions=$scopes;
        ConnectionPolicy='Use separately authorized existing sessions only. No auth, grants, module installs or role activation performed.';
        Sources=$selected }
}
function Invoke-M365SecurityAudit {
    [CmdletBinding()]
    param(
        [ValidateSet('Synthetic','Live')][string]$Mode='Synthetic',
        [ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview')][string[]]$Include=@(),
        [string]$OutputPath='',[guid]$TenantId=[guid]::Empty,
        [string]$ExpectedAccount='', [guid]$ConfirmTenantId=[guid]::Empty, [switch]$ConfirmOrganizationScope,
        [ValidateRange(1,10000)][int]$MaxPages=100,[ValidateRange(1,1000000)][int]$MaxRecords=50000
    )
    if ($Mode -eq 'Live') {
        # Reject before touching sessions, making requests or reserving a report directory.
        if ($TenantId -eq [guid]::Empty) { throw 'Live audit requires an explicit non-empty tenant ID. Nothing was collected.' }
        if (-not $ConfirmOrganizationScope) { throw 'Organization-wide configuration audit was not confirmed. Nothing was collected.' }
        if ($ConfirmTenantId -eq [guid]::Empty -or $ConfirmTenantId -ne $TenantId) { throw 'Confirmed tenant ID does not match the requested tenant. Nothing was collected.' }
        if ([string]::IsNullOrWhiteSpace($ExpectedAccount) -or $ExpectedAccount -notmatch '^[^\s@]+@[^\s@]+$') { throw 'ExpectedAccount must identify the signed-in administrator account. Nothing was collected.' }
    }
    $fullPath=''
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $fullPath=[IO.Path]::GetFullPath($OutputPath)
        if (Test-Path -LiteralPath $fullPath) { throw 'OutputPath already exists. Choose a new directory to avoid overwriting an audit.' }
        # Explicit export only. Terminal-only operation never creates a temporary report.
        [void][IO.Directory]::CreateDirectory($fullPath)
    }
    $started=[DateTime]::UtcNow.ToString('o'); $plan=Get-M365AuditPlan -Include $Include
    $catalog=@(Get-AuditSourceCatalog); $results=[System.Collections.Generic.List[object]]::new()
    if ($Mode -eq 'Synthetic') {
        $fixture=Get-Content -LiteralPath (Join-Path $script:AuditRoot 'fixtures/synthetic.json') -Raw | ConvertFrom-Json -Depth 100
    }
    foreach ($source in $catalog) {
        if ($source.Group -ne 'Core' -and $source.Group -notin $Include) { $results.Add((New-AuditResult $source 'NotSelected' 'Optional source group was not requested.')); continue }
        if ($Mode -eq 'Synthetic') {
            $item=Get-AuditProperty $fixture $source.Id
            if ($null -eq $item) { $r=New-AuditResult $source 'NotProvided' 'No synthetic fixture for this selected source; this is not tenant data.' }
            else {
                $r=New-AuditResult $source ([string]$item.Status) ([string]$item.Reason)
                $r.Items=@($item.Items); $r.Count=$r.Items.Count; $r.PageCount=if ($r.Status -eq 'Collected') { 1 } else { 0 }
            }
            $results.Add($r); continue
        }
        # Recheck each source, not merely once at startup: no source may reuse a stale identity check.
        $context=if ($source.Provider -eq 'Graph') { Get-AuditGraphContext $TenantId $ExpectedAccount } else { Get-AuditCommandSession $TenantId $source.Provider $ExpectedAccount }
        if ($context.Status -ne 'Ready') { $results.Add((New-AuditResult $source $context.Status $context.Reason)); continue }
        if ($source.Provider -eq 'Graph') {
            $currentScopes=@((Get-AuditProperty $context.Context 'Scopes' @()))
            $authType=[string](Get-AuditProperty $context.Context 'AuthType')
            if ($authType -eq 'Delegated' -and @($source.Scopes | Where-Object { $_ -in $currentScopes }).Count -eq 0) {
                $results.Add((New-AuditResult $source 'InsufficientPermissions' ('No supported read scope visible in existing session. One of: '+($source.Scopes -join ', ')))); continue
            }
            $request={param($Uri) Microsoft.Graph.Authentication\Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop}
            $results.Add((Read-AuditGraphSource -Source $source -Request $request -MaxPages $MaxPages -MaxRecords $MaxRecords))
        } else {
            $results.Add((Read-AuditCommandSource -Source $source -Session $context -MaxRecords $MaxRecords))
        }
    }
    $resultArray=$results.ToArray(); $observations=@(Get-AuditObservations $resultArray)
    $metadata=[pscustomobject]@{ SchemaVersion='1.1'; ToolVersion='0.2.0-terminal'; Mode=$Mode; TenantId=if ($Mode -eq 'Live') { $TenantId.ToString() } else { 'SYNTHETIC-NOT-A-TENANT' };
        StartedAtUtc=$started; FinishedAtUtc=[DateTime]::UtcNow.ToString('o'); PowerShellVersion=$PSVersionTable.PSVersion.ToString();
        SelectedGroups=$plan.SelectedGroups; MaxPages=$MaxPages; MaxRecords=$MaxRecords;
        OrganizationWideConfirmed=($Mode -eq 'Live' -and [bool]$ConfirmOrganizationScope); AccountVerification=if ($Mode -eq 'Live') { 'Exact delegated account and tenant checked per source; gaps recorded.' } else { 'Synthetic: not applicable' };
        Scope='Current-state configuration snapshot only. Not a complete M365 inventory, effective-policy engine, vulnerability scan or certification.';
        Privacy='No users, sign-ins, mail content, credentials or OAuth grants queried. Policy targeting may contain names, IDs, addresses and infrastructure data. Keep local and access controlled.' }
    if ($fullPath) { Export-AuditReport -Path $fullPath -Metadata $metadata -Results $resultArray -Observations $observations -Catalog $catalog -Plan $plan }
    [pscustomobject]@{ OutputPath=$fullPath; SelectedCount=@($resultArray | Where-Object Status -ne 'NotSelected').Count;
        CollectedCount=@($resultArray | Where-Object Status -eq 'Collected').Count;
        IncompleteCount=@($resultArray | Where-Object { $_.Status -notin @('Collected','NotSelected') }).Count; FindingCount=$observations.Count;
        Mode=$Mode; TenantId=$metadata.TenantId; Metadata=$metadata; Evidence=$resultArray; Coverage=@($resultArray | Select-Object SourceId,Group,Provider,Status,Count,Reason,MissingFields,Notes); Observations=$observations }
}
