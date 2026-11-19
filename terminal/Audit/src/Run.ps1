function Get-M365AuditPlan {
    [CmdletBinding()]
    param([ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')][string[]]$Include=@())
    $catalog=@(Get-AuditSourceCatalog)
    if (@($Include | Where-Object { $_ -like 'Workbook*' }).Count) { $catalog+=@(Get-FlapjacksWorkbookSources) }
    $selected=@($catalog | Where-Object { $_.Group -eq 'Core' -or $_.Group -in $Include })
    # Each source's first scope is the documented least-privileged option. Existing Policy.Read.All
    # covers Authentication as well, so do not request an unnecessary extra scope in the combined plan.
    $scopes=@($selected | Where-Object Provider -eq 'Graph' | ForEach-Object { $_.Scopes[0]; (Get-AuditProperty $_ 'RequiredScopes' @()) | Where-Object { $_ } } | Sort-Object -Unique)
    if ('Policy.Read.All' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'Policy.Read.AuthenticationMethod' }) }
    if ('RoleManagement.Read.Directory' -in $scopes) { $scopes=@($scopes | Where-Object { $_ -ne 'RoleEligibilitySchedule.Read.Directory' }) }
    [pscustomobject]@{ SchemaVersion='1.1'; ToolVersion='0.2.0-terminal'; ReadOnly=$true; Cloud='Global';
        SelectedGroups=@('Core')+@($Include | Sort-Object -Unique); GraphReadPermissions=$scopes;
        ConnectionPolicy='Use separately authorized existing sessions only. No auth, grants, module installs or role activation performed.';
        Sources=$selected }
}
function Invoke-FlapjacksAuditCore {
    [CmdletBinding()]
    param(
        [ValidateSet('Live')][string]$Mode,
        [ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')][string[]]$Include=@(),
        [string]$OutputPath='',[guid]$TenantId=[guid]::Empty,
        [string]$ExpectedAccount='', [guid]$ConfirmTenantId=[guid]::Empty, [switch]$ConfirmOrganizationScope,
        [ValidateRange(1,10000)][int]$MaxPages=100,[ValidateRange(1,1000000)][int]$MaxRecords=50000,
        [object]$WorkbookCollaborationSnapshot=$null,
        [Alias('WorkbookMailBaseline')][ValidateSet('None','Standard','Strict')][string]$WorkbookAntiPhishBaseline='None'
    )
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live audit requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    # Reject before touching sessions, making requests or reserving a report directory.
    if ($TenantId -eq [guid]::Empty) { throw 'Live audit requires an explicit non-empty tenant ID. Nothing was collected.' }
    if (-not $ConfirmOrganizationScope) { throw 'Organization-wide configuration audit was not confirmed. Nothing was collected.' }
    if ($ConfirmTenantId -eq [guid]::Empty -or $ConfirmTenantId -ne $TenantId) { throw 'Confirmed tenant ID does not match the requested tenant. Nothing was collected.' }
    if ([string]::IsNullOrWhiteSpace($ExpectedAccount) -or $ExpectedAccount -notmatch '^[^\s@]+@[^\s@]+$') { throw 'ExpectedAccount must identify the signed-in administrator account. Nothing was collected.' }
    if ($WorkbookAntiPhishBaseline -ne 'None' -and 'WorkbookExchange' -notin $Include) { throw 'Explicit workbook Exchange selection is required for an anti-phishing baseline.' }
    $snapshots=@{}
    if ($null -ne $WorkbookCollaborationSnapshot) {
        if ('WorkbookCollaboration' -notin $Include) { throw 'Explicit workbook collaboration selection is required to supply a snapshot.' }
        foreach ($row in (ConvertTo-FlapjacksWorkbookCollaborationSnapshot -Snapshot $WorkbookCollaborationSnapshot)) { $snapshots[$row.SourceId]=$row }
    }
    $fullPath=''
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $fullPath=[IO.Path]::GetFullPath($OutputPath)
        if (Test-Path -LiteralPath $fullPath) { throw 'OutputPath already exists. Choose a new directory to avoid overwriting an audit.' }
        # Explicit export only. Terminal-only operation never creates a temporary report.
        [void][IO.Directory]::CreateDirectory($fullPath)
    }
    $started=[DateTime]::UtcNow.ToString('o'); $plan=Get-M365AuditPlan -Include $Include
    $catalog=@(Get-AuditSourceCatalog)
    $catalog+=@($plan.Sources | Where-Object { $_.Group -like 'Workbook*' })
    $results=[System.Collections.Generic.List[object]]::new()
    foreach ($source in $catalog) {
        if ($source.Group -ne 'Core' -and $source.Group -notin $Include) { $results.Add((New-AuditResult $source 'NotSelected' 'Optional source group was not requested.')); continue }
        if ($source.Provider -eq 'OfflineSnapshot') {
            if ($snapshots.ContainsKey($source.Id)) { $results.Add($snapshots[$source.Id]) }
            else { $results.Add((New-AuditResult $source 'NotConnected' 'No verified live connector for this workload; a separately saved snapshot is not proof of live coverage.')) }
            continue
        }
        # Recheck each source, not merely once at startup: no source may reuse a stale identity check.
        $context=if ($source.Provider -eq 'Graph') { Get-AuditGraphContext $TenantId $ExpectedAccount } else { Get-AuditCommandSession $TenantId $source.Provider $ExpectedAccount }
        if ($context.Status -ne 'Ready') { $results.Add((New-AuditResult $source $context.Status $context.Reason)); continue }
        if ($source.Provider -eq 'Graph') {
            if (-not (Test-FlapjacksGraphScope $source $context)) {
                $required=@((Get-AuditProperty $source 'RequiredScopes' @()))
                $detail='Existing session must contain one of: '+($source.Scopes -join ', ')
                if($required.Count){$detail+='; plus all of: '+($required -join ', ')}
                $results.Add((New-AuditResult $source 'InsufficientPermissions' $detail)); continue
            }
            $request={
                param($Uri)
                if ($source.Group -in @('WorkbookIdentity','WorkbookCollaboration')) {
                    $pageContext=Get-AuditGraphContext $TenantId $ExpectedAccount
                    if ($pageContext.Status -ne 'Ready' -or -not (Test-FlapjacksGraphScope $source $pageContext)) {
                        $denied=[InvalidOperationException]::new('Existing verified identity or scopes changed.')
                        $denied.Data['HttpStatus']=401
                        throw $denied
                    }
                }
                Microsoft.Graph.Authentication\Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
            }
            $results.Add((Read-AuditGraphSource -Source $source -Request $request -MaxPages $MaxPages -MaxRecords $MaxRecords))
        } else {
            $workbookMailFields='WorkbookExchange' -in $Include -and $source.Provider -ceq 'Exchange'
            $results.Add((Read-AuditCommandSource -Source $source -Session $context -MaxRecords $MaxRecords -IncludeWorkbookMailFields:$workbookMailFields))
        }
    }
    $resultArray=$results.ToArray(); $observations=@(Get-AuditObservations $resultArray)
    $metadata=[pscustomobject]@{ SchemaVersion='1.1'; ToolVersion='0.2.0-terminal'; Mode=$Mode; TenantId=$TenantId.ToString();
        StartedAtUtc=$started; FinishedAtUtc=[DateTime]::UtcNow.ToString('o'); PowerShellVersion=$PSVersionTable.PSVersion.ToString();
        SelectedGroups=$plan.SelectedGroups; MaxPages=$MaxPages; MaxRecords=$MaxRecords;
        OrganizationWideConfirmed=[bool]$ConfirmOrganizationScope; AccountVerification='Exact delegated account and tenant checked per source; gaps recorded.';
        Scope='Current-state configuration snapshot only. Not a complete M365 inventory, effective-policy engine, vulnerability scan or certification.';
        Privacy='No users, sign-ins, mail content, credentials or OAuth grants queried. Policy targeting may contain names, IDs, addresses and infrastructure data. Keep local and access controlled.' }
    if ('WorkbookExchange' -in $Include) { $metadata | Add-Member -NotePropertyName WorkbookAntiPhishBaseline -NotePropertyValue $WorkbookAntiPhishBaseline }
    if ('WorkbookIdentity' -in $Include) { $metadata.Scope='Current configuration and optional point-in-time identity attributes. Not event logs, effective-policy analysis or compliance certification.'; $metadata.Privacy='Optional workbook identity sources use selected directory fields, registration flags and last successful sign-in time, not sign-in events or mail content. Saved evidence may include object IDs and precise times. Keep local and access controlled.' }
    if ($fullPath) { Export-AuditReport -Path $fullPath -Metadata $metadata -Results $resultArray -Observations $observations -Catalog $catalog -Plan $plan }
    [pscustomobject]@{ OutputPath=$fullPath; SelectedCount=@($resultArray | Where-Object Status -ne 'NotSelected').Count;
        CollectedCount=@($resultArray | Where-Object Status -eq 'Collected').Count;
        IncompleteCount=@($resultArray | Where-Object { $_.Status -notin @('Collected','NotSelected') }).Count; FindingCount=$observations.Count;
        Mode=$Mode; TenantId=$metadata.TenantId; Metadata=$metadata; Evidence=$resultArray; Coverage=@($resultArray | Select-Object SourceId,Group,Provider,Status,Count,Reason,MissingFields,Notes); Observations=$observations }
}

function Invoke-M365SecurityAudit {
    [CmdletBinding()]
    param(
        [ValidateSet('Live')][string]$Mode,
        [ValidateSet('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')][string[]]$Include=@(),
        [string]$OutputPath='',[guid]$TenantId=[guid]::Empty,
        [string]$ExpectedAccount='', [guid]$ConfirmTenantId=[guid]::Empty, [switch]$ConfirmOrganizationScope,
        [ValidateRange(1,10000)][int]$MaxPages=100,[ValidateRange(1,1000000)][int]$MaxRecords=50000,
        [object]$WorkbookCollaborationSnapshot=$null,
        [Alias('WorkbookMailBaseline')][ValidateSet('None','Standard','Strict')][string]$WorkbookAntiPhishBaseline='None'
    )
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live audit requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    Invoke-FlapjacksAuditCore @PSBoundParameters
}
