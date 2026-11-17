function Get-M365OrganizationAuditPlan {
    [CmdletBinding()]
    param()
    $plan=Get-M365AuditPlan -Include Authentication,Consent,Administration,TenantInventory,Intune,Exchange,Purview
    $plan | Add-Member -NotePropertyName OrganizationScope -NotePropertyValue 'Organization-wide current configuration across all 46 supported sources; not every Microsoft 365 setting or effective policy evaluation.'
    $plan | Add-Member -NotePropertyName SensitiveReportNotice -NotePropertyValue 'Reports may include tenant policy targeting identities, addresses and infrastructure. Keep on approved local storage.'
    $plan | Add-Member -NotePropertyName ConfirmationRequired -NotePropertyValue 'Verify signed-in delegated account and tenant binding, and explicitly authorize organization-wide configuration collection. Interactive Flapjacks uses one AUDIT confirmation; direct API callers must supply matching confirmed tenant ID. No tenant writes or log collection.'
    return $plan
}
function Invoke-M365OrganizationAudit {
    [CmdletBinding()]
    param(
        [ValidateSet('Synthetic','Live')][string]$Mode='Synthetic',
        [string]$OutputPath='',
        [guid]$TenantId=[guid]::Empty,
        [string]$ExpectedAccount='',
        [guid]$ConfirmedTenantId=[guid]::Empty,
        [switch]$ConfirmOrganizationWide,
        [ValidateRange(1,10000)][int]$MaxPages=100,
        [ValidateRange(1,1000000)][int]$MaxRecords=50000
    )
    Invoke-M365SecurityAudit -Mode $Mode -OutputPath $OutputPath -TenantId $TenantId -ExpectedAccount $ExpectedAccount `
        -ConfirmTenantId $ConfirmedTenantId -ConfirmOrganizationScope:$ConfirmOrganizationWide `
        -Include Authentication,Consent,Administration,TenantInventory,Intune,Exchange,Purview `
        -MaxPages $MaxPages -MaxRecords $MaxRecords
}
function ConvertTo-AuditTerminalText($Value) {
    $s=[string]$Value
    # Strip ANSI/OSC sequences and ALL C0/C1 controls, including embedded newlines, so
    # provider strings cannot change the terminal title, fake lines or alter color/state.
    $s=[regex]::Replace($s,'\x1B\][^\x07\x1B]*(?:\x07|\x1B\\|$)','')
    $s=[regex]::Replace($s,'\x1B\[[0-?]*[ -/]*[@-~]','')
    $s=[regex]::Replace($s,'[\x00-\x1F\x7F-\x9F\u202A-\u202E\u2066-\u2069]',' ')
    return $s
}
function Write-M365AuditSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)
    Write-Host ''
    Write-Host ('M365 CONFIGURATION AUDIT | '+(ConvertTo-AuditTerminalText $Result.Mode))
    Write-Host ('Tenant: '+(ConvertTo-AuditTerminalText $Result.TenantId))
    Write-Host ('Selected {0}; collected {1}; incomplete/unavailable {2}; review observations {3}.' -f $Result.SelectedCount,$Result.CollectedCount,$Result.IncompleteCount,$Result.FindingCount)
    if ($Result.Mode -eq 'Synthetic') { Write-Host 'SYNTHETIC DATA ONLY. No tenant was contacted.' }
    Write-Host 'Collected is not a security grade. Unselected, denied and partial sources are unknown, not clean.'
    Write-Host ''
    foreach ($item in $Result.Coverage) {
        Write-Host ('{0,-46} {1,-24} records={2}' -f (ConvertTo-AuditTerminalText $item.SourceId),(ConvertTo-AuditTerminalText $item.Status),$item.Count)
        if ($item.Status -notin @('Collected','NotSelected')) {
            Write-Host ('  Gap: '+(ConvertTo-AuditTerminalText $item.Reason))
            if (@($item.MissingFields).Count -gt 0) { Write-Host ('  Missing fields: '+(ConvertTo-AuditTerminalText ($item.MissingFields -join ', '))) }
        }
    }
    Write-Host ''
    foreach ($observation in $Result.Observations) {
        Write-Host ('REVIEW [{0}] {1}' -f (ConvertTo-AuditTerminalText $observation.Rule),(ConvertTo-AuditTerminalText $observation.Title))
        Write-Host ('  '+(ConvertTo-AuditTerminalText $observation.Detail))
    }
    if ($Result.OutputPath) {
        Write-Host ('Local JSON/CSV evidence: '+(ConvertTo-AuditTerminalText $Result.OutputPath))
        Write-Host 'Files: audit.json, coverage.csv, inventory.csv, observations.csv, collection-plan.json, evidence/, manifest.json.'
    } else { Write-Host 'No files saved. Collected evidence remains in the returned in-memory result.' }
    Write-Host 'No HTML, browser, local server, upload, sign-in or permission grant was performed by the audit module.'
}
function Write-M365AuditSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$SourceId,
        [ValidateRange(0,1000000)][int]$Offset=0,
        [ValidateRange(1,1000)][int]$Limit=20
    )
    $matches=@($Result.Evidence | Where-Object { $_.SourceId -ceq $SourceId })
    if ($matches.Count -ne 1) { throw 'Select an exact source ID from the audit coverage list.' }
    $source=$matches[0]
    Write-Host ('SOURCE {0} | {1} | {2} collected records' -f (ConvertTo-AuditTerminalText $source.SourceId),(ConvertTo-AuditTerminalText $source.Status),$source.Count)
    if ($source.Reason) { Write-Host (ConvertTo-AuditTerminalText $source.Reason) }
    $items=@($source.Items | Select-Object -Skip $Offset -First $Limit)
    Write-Host ('Displaying {0} records from offset {1}; total collected {2}. This view does not change collection coverage.' -f $items.Count,$Offset,$source.Count)
    $json=ConvertTo-Json -InputObject $items -Depth 100 -WarningAction Stop
    foreach ($line in ($json -split '\r?\n')) { Write-Host (ConvertTo-AuditTerminalText $line) }
}
