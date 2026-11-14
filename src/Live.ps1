# The transport is injectable for offline tests. The production transport only calls this allowlist.
function New-BecContext {
    param([scriptblock]$Transport, [scriptblock]$Sleep={param($s) Start-Sleep -Seconds $s}, [int]$MaxPages=20, [int]$MaxDetails=200, [int]$MaxFolders=100)
    if(-not $Transport){$Transport={param($command,$parameters)
        $allow=@('Get-Mailbox','Get-MailboxStatistics','Get-InboxRule','Get-MailboxPermission','Get-RecipientPermission','Get-CASMailbox','Get-MobileDeviceStatistics','Get-MailboxFolderStatistics','Get-MailboxFolderPermission','Get-AcceptedDomain','Get-MessageTraceV2','Get-MessageTraceDetailV2','Search-UnifiedAuditLog','Get-MgContext','Invoke-MgGraphRequest')
        if($command -notin $allow){throw "Read command not allowed: $command"}
        if(-not (Get-Command $command -ErrorAction SilentlyContinue)){throw "Module unavailable: $command"}
        & $command @parameters -ErrorAction Stop
    }}
    @{Transport=$Transport;Sleep=$Sleep;MaxPages=$MaxPages;MaxDetails=$MaxDetails;MaxFolders=$MaxFolders;AuditIdentities=@();Requests=[Collections.Generic.List[object]]::new();TraceThrottle=(New-BecThrottle -Sleep $Sleep)}
}

function Invoke-BecRead {
    param([hashtable]$Context,[string]$Command,[hashtable]$Parameters)
    $action={
        if($Command -in @('Get-MessageTraceV2','Get-MessageTraceDetailV2')){Wait-BecThrottle $Context.TraceThrottle}
        & $Context.Transport $Command $Parameters
    }.GetNewClosure()
    $r=Invoke-BecRequest -Action $action -Sleep $Context.Sleep
    $Context.Requests.Add([pscustomobject]@{Command=$Command;Parameters=$Parameters;Attempts=$r.Attempts;Failure=$r.Failure})
    if(-not $r.Success){$e=[Exception]::new($r.Failure.Message);$e.Data['StatusCode']=$r.Failure.Code;throw $e}
    if($null -ne $r.Value){return $r.Value}
}

function Complete-BecCollection {
    param($Collection,[hashtable]$Context,[int]$RequestStart)
    $Collection.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    if($Context.Requests.Count -gt $RequestStart){$Collection.Pages+=@($Context.Requests.ToArray() | Select-Object -Skip $RequestStart)}
    $Collection.Matched=@($Collection.Items).Count
    return $Collection
}

function Invoke-BecSnapshot {
    param([string]$Name,[string]$Command,[hashtable]$Parameters,[hashtable]$Context)
    $c=New-BecCollection $Name 'CurrentSnapshot' 'Exchange';$n=$Context.Requests.Count
    try{$c.Items=@(Invoke-BecRead $Context $Command $Parameters | ForEach-Object {$_});$c.Status='Collected';$c.Reason='Current snapshot only; not historical state';$c.QueryCompleteness='Command returned';$c.Retention='Collection time'}
    catch{$c.Status=(Get-BecFailureClass $_).Status;$c.Reason=$_.Exception.Message}
    Complete-BecCollection $c $Context $n
}

function Invoke-BecExchange {
    param([string]$Target,[hashtable]$Context)
    $specs=@(
        @('Exchange.Mailbox','Get-Mailbox',@{Identity=$Target}),
        @('Exchange.Statistics','Get-MailboxStatistics',@{Identity=$Target}),
        @('Exchange.ArchiveStatistics','Get-MailboxStatistics',@{Identity=$Target;Archive=$true}),
        @('Exchange.Rules','Get-InboxRule',@{Mailbox=$Target;IncludeHidden=$true;ResultSize='Unlimited'}),
        @('Exchange.FullAccess','Get-MailboxPermission',@{Identity=$Target}),
        @('Exchange.SendAs','Get-RecipientPermission',@{Identity=$Target}),
        @('Exchange.Protocols','Get-CASMailbox',@{Identity=$Target}),
        @('Exchange.Mobile','Get-MobileDeviceStatistics',@{Mailbox=$Target}),
        @('Exchange.AcceptedDomains','Get-AcceptedDomain',@{})
    )
    foreach($s in $specs){Invoke-BecSnapshot $s[0] $s[1] $s[2] $Context}
    $c=New-BecCollection 'Exchange.FolderPermissions' 'CurrentSnapshot' 'Exchange';$n=$Context.Requests.Count
    $items=[Collections.Generic.List[object]]::new();$errors=[Collections.Generic.List[string]]::new()
    try{
        $folders=@(Invoke-BecRead $Context 'Get-MailboxFolderStatistics' @{Identity=$Target;ResultSize='Unlimited'} | ForEach-Object {$_})
        $c.Scanned=$folders.Count
        foreach($f in @($folders | Select-Object -First $Context.MaxFolders)){
            $path=[string](Get-BecValue $f 'FolderPath')
            if(-not $path.StartsWith('/')){$errors.Add('Missing/invalid folder path');continue}
            $identity=$Target+':'+$path.Replace('/','\')
            try{foreach($x in @(Invoke-BecRead $Context 'Get-MailboxFolderPermission' @{Identity=$identity} | ForEach-Object {$_})){$items.Add([pscustomobject]@{FolderPath=$path;Payload=$x})}}
            catch{$errors.Add($path+': '+$_.Exception.Message)}
        }
        if($folders.Count -gt $Context.MaxFolders){$errors.Add('Folder cap reached')}
        $c.Status=if($errors.Count){'Partial'}else{'Collected'};$c.Reason=if($errors.Count){$errors -join '; '}else{'Current folder permission snapshot'}
        $c.QueryCompleteness=if($errors.Count){'Partial'}else{'Enumerated folders'}
    }catch{$c.Status=(Get-BecFailureClass $_).Status;$c.Reason=$_.Exception.Message}
    $c.Items=$items.ToArray();$c.Retention='Collection time';Complete-BecCollection $c $Context $n
}

function Invoke-BecTrace {
    param([string]$Target,[DateTimeOffset]$Start,[DateTimeOffset]$End,[hashtable]$Context,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow,[string[]]$Addresses=@())
    if(-not $Addresses.Count){$Addresses=@($Target)}
    foreach($direction in @('Sent','Received')){
        $c=New-BecCollection "Trace.$direction" 'Historical' 'Exchange';$n=$Context.Requests.Count
        $items=[Collections.Generic.List[object]]::new();$pages=[Collections.Generic.List[object]]::new();$issues=[Collections.Generic.List[string]]::new()
        $floor=$Now.AddDays(-90);$effective=$Start
        if($End -le $floor){$c.Status='OutsideRetention';$c.Reason='Requested interval is older than trace 90-day retention';$c.Retention='90 days';Complete-BecCollection $c $Context $n;continue}
        if($Start -lt $floor){$effective=$floor;$issues.Add('Requested beginning outside 90-day retention')}
        foreach($w in @(Get-UtcQueryWindow -Start $effective -End $End -MaxWindowDays 10)){
            $c.Windows+=@($w);$state=@{End=$w.EndUtc;Recipient=$null}
            $query={param($token)
                if($token){$cursor=ConvertFrom-Json $token;$state.End=[DateTimeOffset]$cursor.End;$state.Recipient=$cursor.Recipient}
                $p=@{StartDate=$w.StartUtc.UtcDateTime;EndDate=$state.End.UtcDateTime;ResultSize=5000}
                if($direction -eq 'Sent'){$p.SenderAddress=$Addresses}else{$p.RecipientAddress=$Addresses}
                if($state.Recipient){$p.StartingRecipientAddress=$state.Recipient}
                $rows=@(Invoke-BecRead $Context 'Get-MessageTraceV2' $p | ForEach-Object {$_});$next=$null
                if($rows.Count -ge 5000){
                    $last=$rows[-1];$time=ConvertTo-BecUtc (Get-BecValue $last 'Received');$recipient=Get-BecValue $last 'RecipientAddress'
                    if($null -ne $time -and $time -ge $w.StartUtc -and $time -le $state.End -and $recipient){$next=ConvertTo-BecJson @{End=$time.ToString('o');Recipient=[string]$recipient}}
                }
                @{Items=$rows;NextToken=$next;IsComplete=($rows.Count -lt 5000);Provenance=$p}
            }.GetNewClosure()
            $r=Invoke-BecPagedQuery $query -MaxPages $Context.MaxPages
            $c.OverflowItems+=@($r.OverflowItems)
            foreach($x in $r.Items){$items.Add($x)};foreach($p in $r.Pages){$pages.Add($p)}
            if($r.Status -ne 'Complete'){$issues.Add($r.Reason);break}
        }
        $c.Items=$items.ToArray();$c.Pages=$pages.ToArray();$c.Status=if($issues.Count){'Partial'}else{'Collected'}
        $c.Reason=if($issues.Count){$issues -join '; '}else{'All bounded trace windows exhausted; service latency still applies'}
        if($items.Count -eq 0 -and $pages.Count -and $pages[-1].Failure){$c.Status=$pages[-1].Failure.Status;$c.Reason=$pages[-1].Error}
        $c.QueryCompleteness=if($issues.Count){'Partial'}else{'Exhausted'};$c.Retention='90 days; at most 10 days per query'
        $c.Notes=@('Queried current SMTP addresses: '+($Addresses -join ', '),'Current aliases cannot establish historical aliases. Use MessageTraceId for messages with more than 1000 recipients; broad trace results may not expose every recipient.')
        Complete-BecCollection $c $Context $n
    }
}

function Invoke-BecTraceDetails {
    param([object[]]$Traces,[DateTimeOffset]$Start,[DateTimeOffset]$End,[hashtable]$Context)
    $c=New-BecCollection 'Trace.Details' 'Historical' 'Exchange';$n=$Context.Requests.Count
    $items=[Collections.Generic.List[object]]::new();$errors=[Collections.Generic.List[string]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($t in $Traces){
        $id=Get-BecValue $t 'MessageTraceId';$recipient=Get-BecValue $t 'RecipientAddress';$received=ConvertTo-BecUtc (Get-BecValue $t 'Received')
        if(-not $id -or -not $recipient -or -not $received){$errors.Add('Trace lacks detail identity/date');continue}
        if(-not $seen.Add("$id|$recipient")){continue}
        if($seen.Count -gt $Context.MaxDetails){$errors.Add('Detail query cap reached');break}
        $lo=$received.AddDays(-1);$hi=$received.AddDays(1);if($lo -lt $Start){$lo=$Start};if($hi -gt $End){$hi=$End}
        try{foreach($r in @(Invoke-BecRead $Context 'Get-MessageTraceDetailV2' @{MessageTraceId=$id;RecipientAddress=$recipient;StartDate=$lo.UtcDateTime;EndDate=$hi.UtcDateTime} | ForEach-Object {$_})){$items.Add([pscustomobject]@{MessageTraceId=$id;RecipientAddress=$recipient;Payload=$r})}}
        catch{$errors.Add($_.Exception.Message)}
    }
    $c.Items=$items.ToArray();$c.Status=if($errors.Count){'Partial'}else{'Collected'};$c.Reason=if($errors.Count){$errors -join '; '}else{'Details for available unique trace/recipient pairs only'}
    $c.Notes=@('Parent trace coverage applies; no traces does not establish absence of mail.');$c.QueryCompleteness=if($errors.Count){'Partial'}else{'Available trace pairs'}
    Complete-BecCollection $c $Context $n
}

function Invoke-BecAudit {
    param([string]$Target,[DateTimeOffset]$Start,[DateTimeOffset]$End,[hashtable]$Context)
    $c=New-BecCollection 'Purview.Audit' 'Historical' 'Purview';$n=$Context.Requests.Count;$items=[Collections.Generic.List[object]]::new();$issues=[Collections.Generic.List[string]]::new()
    foreach($w in @(Get-UtcQueryWindow -Start $Start -End $End -MaxWindowDays 1)){
        $c.Windows+=@($w);$session=[guid]::NewGuid().ToString();$state=@{Count=0;Page=0}
        $query={param($token)
            # Do not filter UserIds: delegates/admins may change or access the target mailbox.
            $p=@{StartDate=$w.StartUtc.UtcDateTime;EndDate=$w.EndUtc.UtcDateTime;SessionId=$session;SessionCommand='ReturnLargeSet';ResultSize=5000}
            $rows=@(Invoke-BecRead $Context 'Search-UnifiedAuditLog' $p | ForEach-Object {$_});$state.Count+=$rows.Count;$state.Page++
            @{Items=$rows;NextToken=$(if($rows.Count -and $state.Count -lt 50000){[string]$state.Page}else{$null});IsComplete=($rows.Count -eq 0);Provenance=$p}
        }.GetNewClosure()
        $r=Invoke-BecPagedQuery $query -MaxPages ([Math]::Min(11,$Context.MaxPages)) -MaxItems 50000
        # Only target-related overflow is exported; tenant-wide audit payloads stay in memory.
        $c.OverflowItems+=@($r.OverflowItems | Where-Object {Test-BecTargetAudit $_ $Target $Context.AuditIdentities})
        foreach($x in $r.Items){$c.Scanned++;if(Test-BecTargetAudit $x $Target $Context.AuditIdentities){$items.Add($x)}else{$auditPayload=Get-BecValue $x 'AuditData';if($auditPayload -is [string]){try{$null=ConvertFrom-Json $auditPayload -ErrorAction Stop}catch{$issues.Add('Unparseable AuditData could not be target-matched')}}}}
        $c.Pages+=@($r.Pages)
        if($r.Status -ne 'Complete'){$issues.Add('Audit window incomplete: '+$r.Reason);break}
    }
    $c.Items=$items.ToArray();$c.Status=if($issues.Count){'Partial'}else{'Collected'};$c.Reason=if($issues.Count){$issues -join '; '}else{'Paged available audit records; exact named actor/target matching applied locally'}
    if($items.Count -eq 0 -and $c.Pages.Count -and $c.Pages[-1].Failure){$c.Status=$c.Pages[-1].Failure.Status;$c.Reason=$c.Pages[-1].Error}
    $c.QueryCompleteness=if($issues.Count){'Partial'}else{'Exhausted available results'}
    $c.Notes=@('Tenant-wide pages are queried in memory to include other actors. Only target-related raw records are exported. Legacy/non-UPN identities can evade matching.','Audit availability and retention are not established by an empty result. Bind is aggregated; Sync is folder-level. Neither proves human reading.')
    Complete-BecCollection $c $Context $n
}

function Assert-BecGraphUri {
    param([string]$Uri,[switch]$AllowPreviewSignIns)
    $u=[uri]$Uri
    $allowedPath=$u.AbsolutePath.StartsWith('/v1.0/') -or ($AllowPreviewSignIns -and $u.AbsolutePath -ieq '/beta/auditLogs/signIns')
    if(-not $u.IsAbsoluteUri -or $u.Scheme -cne 'https' -or $u.Host -ine 'graph.microsoft.com' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Fragment -or -not $allowedPath){throw 'Unsafe or unsupported Graph continuation URI'}
}

function Invoke-BecGraphCollection {
    param([string]$Name,[string]$Uri,[hashtable]$Context,[string]$Kind='Historical',[string]$Target,[string]$TargetId)
    $c=New-BecCollection $Name $Kind 'MicrosoftGraph';$n=$Context.Requests.Count
    $preview=$Name -eq 'Entra.NonInteractiveSignIns' -and ([uri]$Uri).AbsolutePath -ieq '/beta/auditLogs/signIns'
    if($preview){$c.Provider='MicrosoftGraphBetaPreview';$c.Notes=@('Opt-in preview API; schema may change and Microsoft does not support beta APIs for production applications. No live validation is claimed.')}
    $query={param($token)
        $nextUri=if($token){$token}else{$Uri};Assert-BecGraphUri $nextUri -AllowPreviewSignIns:$preview
        if(-not ([uri]$nextUri).AbsolutePath.Equals(([uri]$Uri).AbsolutePath,[StringComparison]::OrdinalIgnoreCase)){throw 'Graph continuation changed collection path'}
        $response=Invoke-BecRead $Context 'Invoke-MgGraphRequest' @{Method='GET';Uri=$nextUri;OutputType='PSObject'}
        $rows=Get-BecValue $response 'value';$next=Get-BecValue $response '@odata.nextLink'
        # Validate continuation before the next request, so the already fetched page is retained
        # even if the server supplies a disallowed nextLink. No untrusted URL is followed.
        @{Items=$rows;NextToken=$next;IsComplete=($null -eq $next);Provenance=@{Uri=$nextUri;Method='GET'}}
    }.GetNewClosure()
    $r=Invoke-BecPagedQuery $query -MaxPages $Context.MaxPages
    $c.OverflowItems=$r.OverflowItems
    $c.Scanned=$r.Items.Count;$c.Items=$r.Items
    if($Name -eq 'Entra.Audit'){$c.Items=@($r.Items | Where-Object {Test-BecTargetAudit $_ $Target $TargetId});$c.OverflowItems=@($r.OverflowItems | Where-Object {Test-BecTargetAudit $_ $Target $TargetId})}
    $c.Pages=$r.Pages;$c.Status=if($r.Status -eq 'Complete'){'Collected'}else{'Partial'};$c.Reason=if($r.Reason){$r.Reason}else{'Available result pages exhausted; retention/permissions may constrain returned fields'}
    if($r.Items.Count -eq 0 -and $r.Pages.Count -and $r.Pages[-1].Failure){$c.Status=$r.Pages[-1].Failure.Status;$c.Reason=$r.Pages[-1].Error}
    $c.QueryCompleteness=$r.Status
    if($Kind -eq 'CurrentSnapshot'){$c.Retention='Collection time'}else{$c.Retention='Tenant/license dependent; Entra sign-in/audit 7 days Free or 30 days P1/P2; not independently confirmed'}
    Complete-BecCollection $c $Context $n
}

function Invoke-BecEntra {
    param([string]$Target,[DateTimeOffset]$Start,[DateTimeOffset]$End,[hashtable]$Context,[switch]$IncludeNonInteractivePreview)
    if(-not $IncludeNonInteractivePreview){
        $unsupported=New-BecCollection 'Entra.NonInteractiveSignIns' 'Historical' 'MicrosoftGraphBetaPreview'
        $unsupported.Reason='Optional preview collection not requested. Use -IncludeNonInteractivePreview to query the documented beta user sign-in filter; v1.0 results do not imply full sign-in coverage.'
        $unsupported.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');$unsupported
    }
    $names=@('Entra.SignIns','Entra.Audit','Entra.OAuthUser','Entra.OAuthTenant','Entra.Risks');$id=$null
    if($IncludeNonInteractivePreview){$names+=@('Entra.NonInteractiveSignIns')}
    try{
        $mg=Invoke-BecRead $Context 'Get-MgContext' @{}
        if(-not $mg){throw 'Not connected to Microsoft Graph'}
        if((Get-BecValue $mg 'Environment' 'Global') -ne 'Global'){throw 'Not implemented for non-Global Graph cloud'}
        $u=Invoke-BecRead $Context 'Invoke-MgGraphRequest' @{Method='GET';Uri=('https://graph.microsoft.com/v1.0/users/'+[uri]::EscapeDataString($Target)+'?$select=id,userPrincipalName');OutputType='PSObject'}
        $id=Get-BecValue $u 'id';if(-not $id){throw 'Target user lookup returned no id'}
    }catch{foreach($name in $names){$c=New-BecCollection $name 'Historical' 'MicrosoftGraph';$c.Status=(Get-BecFailureClass $_).Status;$c.Reason=$_.Exception.Message;$c.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');$c};return}
    $s=$Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ');$e=$End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ');$escaped=$Target.Replace("'","''")
    $specs=@(
        @('Entra.SignIns','auditLogs/signIns',"userPrincipalName eq '$escaped' and createdDateTime ge $s and createdDateTime le $e",'Historical'),
        @('Entra.Audit','auditLogs/directoryAudits',"activityDateTime ge $s and activityDateTime le $e",'Historical'),
        @('Entra.OAuthUser',"users/$id/oauth2PermissionGrants",$null,'CurrentSnapshot'),
        @('Entra.OAuthTenant','oauth2PermissionGrants',"consentType eq 'AllPrincipals'",'CurrentSnapshot'),
        @('Entra.Risks','identityProtection/riskDetections',"userId eq '$id' and detectedDateTime ge $s and detectedDateTime le $e",'Historical')
    )
    foreach($spec in $specs){$uri='https://graph.microsoft.com/v1.0/'+$spec[1];if($spec[2]){$uri+='?$filter='+[uri]::EscapeDataString($spec[2])};$c=Invoke-BecGraphCollection $spec[0] $uri $Context $spec[3] $Target $id
        if($spec[0] -eq 'Entra.OAuthTenant'){$c.Notes+=@('Tenant-wide AllPrincipals delegated grants may apply to the target; not evidence of actual use. Application app-role assignments are not enumerated.')}
        if($spec[0] -eq 'Entra.SignIns'){$c.Notes+=@('Conditional Access details require additional read rights. This endpoint is not an exhaustive export of every workload/noninteractive sign-in type.')}
        $c
    }
    if($IncludeNonInteractivePreview){
        $filter="userPrincipalName eq '$escaped' and createdDateTime ge $s and createdDateTime le $e and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
        $uri='https://graph.microsoft.com/beta/auditLogs/signIns?$filter='+[uri]::EscapeDataString($filter)
        Invoke-BecGraphCollection 'Entra.NonInteractiveSignIns' $uri $Context 'Historical' $Target $id
    }
}

function Get-BecHuntingQuery {
    param([ValidateSet('UrlClicks','Email','PostDelivery','Alerts')][string]$Type,[string]$Target,[DateTimeOffset]$Start,[DateTimeOffset]$End,[int]$Limit=10000)
    $upn=ConvertTo-Json -InputObject $Target -Compress;$s=$Start.ToUniversalTime().ToString('o');$e=$End.ToUniversalTime().ToString('o')
    $base=switch($Type){
        UrlClicks {"UrlClickEvents | where Timestamp >= datetime($s) and Timestamp < datetime($e) | where AccountUpn =~ $upn | project Timestamp,AccountUpn,Url,ActionType,Workload,NetworkMessageId,ThreatTypes,DetectionMethods,IPAddress,IsClickedThrough,UrlChain,ReportId"}
        Email {"EmailEvents | where Timestamp >= datetime($s) and Timestamp < datetime($e) | where RecipientEmailAddress =~ $upn or SenderFromAddress =~ $upn or SenderMailFromAddress =~ $upn | project Timestamp,NetworkMessageId,InternetMessageId,SenderFromAddress,SenderMailFromAddress,RecipientEmailAddress,Subject,DeliveryAction,DeliveryLocation,ThreatTypes,DetectionMethods,EmailDirection"}
        PostDelivery {"EmailPostDeliveryEvents | where Timestamp >= datetime($s) and Timestamp < datetime($e) | where RecipientEmailAddress =~ $upn | project Timestamp,NetworkMessageId,InternetMessageId,Action,ActionType,ActionResult,RecipientEmailAddress,DeliveryLocation,ThreatTypes,ReportId"}
        Alerts {"AlertEvidence | where Timestamp >= datetime($s) and Timestamp < datetime($e) | where AccountUpn =~ $upn | project Timestamp,AlertId,Title,Categories,Severity,AccountUpn,NetworkMessageId,RemoteIP,RemoteUrl,ServiceSource,EntityType,EvidenceRole"}
    }
    "$base | take $Limit"
}

function Invoke-BecDefender {
    param([string]$Target,[DateTimeOffset]$Start,[DateTimeOffset]$End,[hashtable]$Context,[bool]$Enabled,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
    foreach($type in @('UrlClicks','Email','PostDelivery','Alerts')){
        $c=New-BecCollection "Defender.$type" 'Historical' 'MicrosoftGraphHunting';$n=$Context.Requests.Count
        if(-not $Enabled){$c.Reason='Optional Defender collection not requested';Complete-BecCollection $c $Context $n;continue}
        $floor=$Now.AddDays(-30);$effective=$Start;$issues=[Collections.Generic.List[string]]::new();$items=[Collections.Generic.List[object]]::new()
        if($End -le $floor){$c.Status='OutsideRetention';$c.Reason='Outside default 30-day hunting range; extended Sentinel data is not queried';Complete-BecCollection $c $Context $n;continue}
        if($effective -lt $floor){$effective=$floor;$issues.Add('Beginning outside default 30-day hunting range')}
        try{
            $mg=Invoke-BecRead $Context 'Get-MgContext' @{};if(-not $mg){throw 'Not connected to Microsoft Graph'}
            if((Get-BecValue $mg 'Environment' 'Global') -ne 'Global'){throw 'Not implemented for non-Global Graph cloud'}
            foreach($w in @(Get-UtcQueryWindow -Start $effective -End $End -MaxWindowDays 1)){
                $c.Windows+=@($w);$query=Get-BecHuntingQuery $type $Target $w.StartUtc $w.EndUtc
                # POST executes a read-only hunting query. It does not change tenant resources.
                $r=Invoke-BecRead $Context 'Invoke-MgGraphRequest' @{Method='POST';Uri='https://graph.microsoft.com/v1.0/security/runHuntingQuery';ContentType='application/json';Body=(ConvertTo-BecJson @{Query=$query;Timespan=($w.StartUtc.ToString('o')+'/'+$w.EndUtc.ToString('o'))});OutputType='PSObject'}
                $rows=Get-BecValue $r 'results';if($rows -isnot [array]){throw 'Invalid hunting response: results must be an array'}
                foreach($x in $rows){$items.Add($x)}
                if($rows.Count -ge 10000){$issues.Add('Hunting result cap reached; refine query interval')}
            }
            $c.Status=if($issues.Count){'Partial'}else{'Collected'};$c.Reason=if($issues.Count){$issues -join '; '}else{'Bounded available hunting results; license/service coverage is not guaranteed'}
        }catch{$c.Status=if($items.Count){'Partial'}else{(Get-BecFailureClass $_).Status};$c.Reason=$_.Exception.Message}
        $c.Items=$items.ToArray();$c.Retention='Normally 30 days; service deployment and licensing required';$c.QueryCompleteness=if($c.Status -eq 'Collected'){'Below cap'}else{'Partial'}
        $c.Notes=@('Safe Links is not complete browsing history. A click does not prove credential submission. Missing/default message IDs remain unlinked. Alerts are account-associated evidence, not every tenant alert.')
        Complete-BecCollection $c $Context $n
    }
}
