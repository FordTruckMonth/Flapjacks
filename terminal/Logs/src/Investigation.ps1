function Get-BecSourceNames {
    @('Exchange.Mailbox','Exchange.Statistics','Exchange.ArchiveStatistics','Exchange.Rules','Exchange.FullAccess','Exchange.SendAs','Exchange.Protocols','Exchange.Mobile','Exchange.AcceptedDomains','Exchange.FolderPermissions','Trace.Sent','Trace.Received','Trace.Details','Purview.Audit','Entra.SignIns','Entra.NonInteractiveSignIns','Entra.Audit','Entra.OAuthUser','Entra.OAuthTenant','Entra.Risks','Defender.UrlClicks','Defender.Email','Defender.PostDelivery','Defender.Alerts')
}

function Get-BecTenantContextSources {
    @('Exchange.AcceptedDomains','Purview.Audit','Entra.Audit','Entra.OAuthTenant')
}

function New-BecScopeGap {
    param([string]$Name)
    $kind=if($Name -in @('Exchange.AcceptedDomains','Entra.OAuthTenant')){'CurrentSnapshot'}else{'Historical'}
    $c=New-BecCollection $Name $kind 'NotRequested'
    $c.Reason='Not collected: tenant-wide collection is prohibited in this mailbox-only logs adapter.'
    $c.Notes=@('Skipped before any provider request. This gap can hide delegate/admin activity or tenant-wide grants affecting the target; it is not a clean finding.')
    $c.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');$c
}

function Invoke-InvestigationCore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetUpn,[Parameter(Mandatory)][DateTimeOffset]$Start,[Parameter(Mandatory)][DateTimeOffset]$End,
          [ValidateSet('Live')][string]$Mode,[ValidateSet('MailboxOnly')][string]$CollectionScope='MailboxOnly',[string]$OutputRoot,[string]$ProjectRoot,
          [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[hashtable]$Context)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live investigation requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    if(-not $PSBoundParameters.ContainsKey('ProjectRoot')){$ProjectRoot=Split-Path $PSScriptRoot -Parent}
    if(-not (Test-BecUpn $TargetUpn)){throw 'Invalid target UPN'}
    if($End -le $Start -or ($End-$Start).TotalDays -gt 90){throw 'Require a positive interval of at most 90 days'}
    $collections=@();$began=[DateTimeOffset]::UtcNow.ToString('o')
    if($End -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Live interval cannot end in the future'}
    if(-not $Context){$Context=New-BecContext}
    $collections+=@(Invoke-BecExchange $TargetUpn $Context)
    $collections+=@(New-BecScopeGap 'Exchange.AcceptedDomains');$collections+=@(New-BecScopeGap 'Purview.Audit')
    $mailbox=$collections | Where-Object Source -eq 'Exchange.Mailbox'
    if($mailbox.Status -eq 'Collected'){
        $identity=Get-BecMailboxIdentity $TargetUpn $collections
        $trace=@(Invoke-BecTrace $TargetUpn $Start $End $Context -Addresses $identity.Addresses);$collections+=$trace
        $collections+=@(Invoke-BecTraceDetails @($trace | ForEach-Object {$_.Items}) $Start $End $Context)
    }else{
        foreach($name in @('Trace.Sent','Trace.Received','Trace.Details')){$gap=New-BecCollection $name 'Historical' 'Exchange';$gap.Reason='Exact mailbox resolution unavailable; trace collection refused';$collections+=$gap}
    }
    $collections+=@(Invoke-BecEntra $TargetUpn $Start $End $Context -IncludeNonInteractivePreview:$IncludeNonInteractivePreview)
    $collections+=@(Invoke-BecDefender $TargetUpn $Start $End $Context -Enabled ([bool]$IncludeDefender))
    $allEvents=@(ConvertTo-BecTimeline $collections $TargetUpn)
    # Provider endpoints have differing inclusive boundary rules; keep all returned raw records,
    # but apply the requested half-open interval to the historical timeline. Unknown times remain flagged.
    $timeline=@($allEvents | Where-Object {$_.Kind -eq 'CurrentSnapshot' -or -not $_.TimeUtc -or ([DateTimeOffset]$_.TimeUtc -ge $Start -and [DateTimeOffset]$_.TimeUtc -lt $End)})
    $links=Get-BecCorrelations $timeline
    $versions=@(Get-Module | Where-Object {$_.Name -match 'ExchangeOnlineManagement|Microsoft.Graph|M365Bec'} | Select-Object Name,@{n='Version';e={$_.Version.ToString()}})
    $codeRoot=Split-Path $PSScriptRoot -Parent
    $implementation=@(Get-ChildItem -LiteralPath (Join-Path $codeRoot 'src') -File)
    foreach($name in @('M365Bec.psm1','Get-UtcQueryWindow.ps1','Test-CaseManifest.ps1')){$implementation+=@(Get-Item -LiteralPath (Join-Path $codeRoot $name))}
    $code=@($implementation | Sort-Object FullName | ForEach-Object {[pscustomobject]@{Path=[IO.Path]::GetRelativePath($codeRoot,$_.FullName).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    $meta=[ordered]@{Tool='M365 BEC Investigator';Version='0.2.0-review';CollectionScope=$CollectionScope;Execution='Terminal-only PowerShell; optional JSON/CSV evidence files';Mode='LIVE READ-ONLY COLLECTION — adapter not live-validated by this release';TargetUpn=$TargetUpn;StartUtc=$Start.ToUniversalTime().ToString('o');EndUtc=$End.ToUniversalTime().ToString('o');CollectionStartedUtc=$began;CollectionFinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');PowerShell=$PSVersionTable.PSVersion.ToString();ModuleVersions=$versions;CodeHashes=$code;FixtureSha256=$null;Authentication='External operator session; no credentials collected or stored';Limits=@{MaxPages=$Context.MaxPages;MaxDetails=$Context.MaxDetails;MaxFolders=$Context.MaxFolders}}
    $coverage=@($collections | Select-Object Source,Kind,Provider,Status,Reason,Matched,Scanned,Retention,QueryCompleteness,StartedUtc,FinishedUtc,Notes)
    $summary=[pscustomobject]@{Metadata=$meta;Warning='Missing evidence is not a clean verdict. Tenant-wide audit, accepted domains and tenant grants are intentionally unavailable.';TimelineRows=$timeline.Count;Coverage=$coverage;Links=$links.Items.Count;LinksPartial=$links.Partial}
    $case=$null;$integrity=$null
    if($OutputRoot){
        $case=Write-BecCase $OutputRoot $ProjectRoot $meta $collections $timeline $links
        $integrity=Test-BecManifest $case
        if(-not $integrity.Passed){throw ('Case manifest verification failed: '+($integrity.Failures -join ', '))}
    }
    [pscustomobject]@{Metadata=$meta;Collections=$collections;Timeline=$timeline;Correlations=$links;Summary=$summary;CasePath=$case;CollectionScope=$CollectionScope;Mode=$Mode;TimelineRows=$timeline.Count;Coverage=$coverage;Manifest=$integrity}
}

function Invoke-BecInvestigation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetUpn,[Parameter(Mandatory)][DateTimeOffset]$Start,[Parameter(Mandatory)][DateTimeOffset]$End,
          [ValidateSet('Live')][string]$Mode,[ValidateSet('MailboxOnly')][string]$CollectionScope='MailboxOnly',[string]$OutputRoot,[string]$ProjectRoot,
          [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[hashtable]$Context)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live investigation requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    Invoke-InvestigationCore @PSBoundParameters
}
