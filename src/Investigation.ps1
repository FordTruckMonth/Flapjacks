function Get-BecSourceNames {
    @('Exchange.Mailbox','Exchange.Statistics','Exchange.ArchiveStatistics','Exchange.Rules','Exchange.FullAccess','Exchange.SendAs','Exchange.Protocols','Exchange.Mobile','Exchange.AcceptedDomains','Exchange.FolderPermissions','Trace.Sent','Trace.Received','Trace.Details','Purview.Audit','Entra.SignIns','Entra.NonInteractiveSignIns','Entra.Audit','Entra.OAuthUser','Entra.OAuthTenant','Entra.Risks','Defender.UrlClicks','Defender.Email','Defender.PostDelivery','Defender.Alerts')
}

function Invoke-InvestigationCore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetUpn,[Parameter(Mandatory)][DateTimeOffset]$Start,[Parameter(Mandatory)][DateTimeOffset]$End,
          [ValidateSet('Live')][string]$Mode,[string]$OutputRoot,[string]$ProjectRoot,
          [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[hashtable]$Context)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live investigation requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    if(-not (Test-BecUpn $TargetUpn)){throw 'Invalid target UPN'}
    if($End -le $Start -or ($End-$Start).TotalDays -gt 90){throw 'Require a positive interval of at most 90 days'}
    $collections=@();$began=[DateTimeOffset]::UtcNow.ToString('o')
    if($End -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Live interval cannot end in the future'}
    if(-not $Context){$Context=New-BecContext}
    $collections+=@(Invoke-BecExchange $TargetUpn $Context)
    $identity=Get-BecMailboxIdentity $TargetUpn $collections;$Context.AuditIdentities=$identity.Identifiers
    $trace=@(Invoke-BecTrace $TargetUpn $Start $End $Context -Addresses $identity.Addresses);$collections+=$trace
    $collections+=@(Invoke-BecTraceDetails @($trace | ForEach-Object {$_.Items}) $Start $End $Context)
    $collections+=@(Invoke-BecAudit $TargetUpn $Start $End $Context)
    $collections+=@(Invoke-BecEntra $TargetUpn $Start $End $Context -IncludeNonInteractivePreview:$IncludeNonInteractivePreview)
    $collections+=@(Invoke-BecDefender $TargetUpn $Start $End $Context -Enabled ([bool]$IncludeDefender))
    $allEvents=@(ConvertTo-BecTimeline $collections $TargetUpn)
    # Provider endpoints have differing inclusive boundary rules; keep all returned raw records,
    # but apply the requested half-open interval to the historical timeline. Unknown times remain flagged.
    $timeline=@($allEvents | Where-Object {$_.Kind -eq 'CurrentSnapshot' -or -not $_.TimeUtc -or ([DateTimeOffset]$_.TimeUtc -ge $Start -and [DateTimeOffset]$_.TimeUtc -lt $End)})
    $links=Get-BecCorrelations $timeline
    $versions=@(Get-Module | Where-Object {$_.Name -match 'ExchangeOnlineManagement|Microsoft.Graph|M365Bec'} | Select-Object Name,@{n='Version';e={$_.Version.ToString()}})
    $implementation=@(Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'src') -File)
    foreach($name in @('M365Bec.psm1','Get-UtcQueryWindow.ps1','Start-BecInvestigation.ps1')){$implementation+=@(Get-Item -LiteralPath (Join-Path $ProjectRoot $name))}
    $code=@($implementation | Sort-Object FullName | ForEach-Object {[pscustomobject]@{Path=[IO.Path]::GetRelativePath($ProjectRoot,$_.FullName).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    $meta=[ordered]@{Tool='M365 BEC Investigator';Version='0.1.0-review';Mode='LIVE READ-ONLY COLLECTION — adapter not live-validated by this release';TargetUpn=$TargetUpn;StartUtc=$Start.ToUniversalTime().ToString('o');EndUtc=$End.ToUniversalTime().ToString('o');CollectionStartedUtc=$began;CollectionFinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');PowerShell=$PSVersionTable.PSVersion.ToString();ModuleVersions=$versions;CodeHashes=$code;FixtureSha256=$null;Authentication='External operator session; no credentials collected or stored';Limits=@{MaxPages=$Context.MaxPages;MaxDetails=$Context.MaxDetails;MaxFolders=$Context.MaxFolders}}
    $case=Write-BecCase $OutputRoot $ProjectRoot $meta $collections $timeline $links
    $integrity=Test-BecManifest $case
    if(-not $integrity.Passed){throw ('Case manifest verification failed: '+($integrity.Failures -join ', '))}
    [pscustomobject]@{CasePath=$case;Report=(Join-Path $case 'report.html');Mode=$Mode;TimelineRows=$timeline.Count;Coverage=@($collections | Select-Object Source,Status,Reason);Manifest=$integrity}
}

function Invoke-BecInvestigation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetUpn,[Parameter(Mandatory)][DateTimeOffset]$Start,[Parameter(Mandatory)][DateTimeOffset]$End,
          [ValidateSet('Live')][string]$Mode,[string]$OutputRoot,[string]$ProjectRoot,
          [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[hashtable]$Context)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live investigation requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    Invoke-InvestigationCore @PSBoundParameters
}
