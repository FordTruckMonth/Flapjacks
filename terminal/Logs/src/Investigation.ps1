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

function Get-BecFixtureCollections {
    param($Fixture,[DateTimeOffset]$Start,[DateTimeOffset]$End,[ValidateSet('MailboxOnly')][string]$CollectionScope='MailboxOnly',[switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview)
    foreach($name in Get-BecSourceNames){
        if($CollectionScope -eq 'MailboxOnly' -and $name -in (Get-BecTenantContextSources)){New-BecScopeGap $name;continue}
        if(($name.StartsWith('Defender.') -and -not $IncludeDefender) -or ($name -eq 'Entra.NonInteractiveSignIns' -and -not $IncludeNonInteractivePreview)){
            $gap=New-BecCollection $name 'Historical' 'SyntheticFixture'
            $gap.Reason=if($name.StartsWith('Defender.')){'Optional Defender collection not requested'}else{'Optional beta non-interactive user sign-in collection not requested'}
            $gap.StartedUtc=$Fixture.ReferenceUtc;$gap.FinishedUtc=$Fixture.ReferenceUtc;$gap;continue
        }
        $spec=Get-BecValue $Fixture.Sources $name
        $kind=if($name.StartsWith('Exchange.') -or $name.StartsWith('Entra.OAuth')){'CurrentSnapshot'}else{'Historical'}
        $c=New-BecCollection $name $kind 'SyntheticFixture';$c.StartedUtc=$Fixture.ReferenceUtc
        if(-not $spec){$c.Reason='Synthetic fixture does not provide this source';$c.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');$c;continue}
        $rows=Get-BecValue $spec 'Items' @();$state=@{Page=0}
        $query={param($token)
            $page=$state.Page++;$chunk=@($rows | Select-Object -Skip ($page*2) -First 2)
            @{Items=$chunk;NextToken=$(if(($page+1)*2 -lt $rows.Count){[string]($page+1)}else{$null});IsComplete=(($page+1)*2 -ge $rows.Count);Provenance=@{FixturePage=$page;Synthetic=$true}}
        }.GetNewClosure()
        $r=Invoke-BecPagedQuery $query
        $c.Items=$r.Items;$c.Pages=$r.Pages;$c.Status=Get-BecValue $spec 'Status' 'Collected';$c.Reason=Get-BecValue $spec 'Reason' 'Synthetic example only';$c.Notes=@(Get-BecList $spec 'Notes' @())
        $c.Windows=@([pscustomobject]@{StartUtc=$Start;EndUtc=$End});$c.Retention='Synthetic fixture, no real tenant retention';$c.QueryCompleteness='Fixture only';$c.Matched=$c.Items.Count;$c.Scanned=$c.Items.Count;$c.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');$c
    }
}

function Invoke-BecInvestigation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TargetUpn,[Parameter(Mandatory)][DateTimeOffset]$Start,[Parameter(Mandatory)][DateTimeOffset]$End,
          [ValidateSet('Fixture','Live')][string]$Mode='Fixture',[ValidateSet('MailboxOnly')][string]$CollectionScope='MailboxOnly',[string]$FixturePath,[string]$OutputRoot,[string]$ProjectRoot=(Split-Path $PSScriptRoot -Parent),
          [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[hashtable]$Context)
    if(-not $FixturePath){$FixturePath=Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/bec-synthetic.json'}
    if(-not (Test-BecUpn $TargetUpn)){throw 'Invalid target UPN'}
    if($End -le $Start -or ($End-$Start).TotalDays -gt 90){throw 'Require a positive interval of at most 90 days'}
    $collections=@();$began=[DateTimeOffset]::UtcNow.ToString('o');$fixtureHash=$null
    if($Mode -eq 'Fixture'){
        $fixture=Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json -Depth 100
        if($fixture.Synthetic -ne $true -or $fixture.TargetUpn -ine $TargetUpn){throw 'Fixture must be explicitly synthetic and match the target UPN'}
        $fixtureHash=(Get-FileHash -LiteralPath $FixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $collections=@(Get-BecFixtureCollections $fixture $Start $End -CollectionScope $CollectionScope -IncludeDefender:$IncludeDefender -IncludeNonInteractivePreview:$IncludeNonInteractivePreview)
    }else{
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
    }
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
    $meta=[ordered]@{Tool='M365 BEC Investigator';Version='0.2.0-review';CollectionScope=$CollectionScope;Execution='Terminal-only PowerShell; optional JSON/CSV evidence files';Mode=$(if($Mode -eq 'Fixture'){'SYNTHETIC FIXTURE — NOT TENANT EVIDENCE'}else{'LIVE READ-ONLY COLLECTION — adapter not live-validated by this release'});TargetUpn=$TargetUpn;StartUtc=$Start.ToUniversalTime().ToString('o');EndUtc=$End.ToUniversalTime().ToString('o');CollectionStartedUtc=$began;CollectionFinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');PowerShell=$PSVersionTable.PSVersion.ToString();ModuleVersions=$versions;CodeHashes=$code;FixtureSha256=$fixtureHash;Authentication='External operator session; no credentials collected or stored';Limits=$(if($Context){@{MaxPages=$Context.MaxPages;MaxDetails=$Context.MaxDetails;MaxFolders=$Context.MaxFolders}}else{@{Fixture=$true}})}
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
