function Get-BecFirst {
    param($Object,[string[]]$Names,$Default=$null)
    foreach($name in $Names){$v=Get-BecValue $Object $name;if($null -ne $v -and [string]$v -ne ''){return ,$v}}
    return $Default
}

function Test-BecIdentifier {
    param($Value)
    return $Value -is [string] -and $Value.Trim().Length -gt 0 -and $Value.Trim() -notmatch '^(?i:unknown|null|none|n/a|0+|0{8}-0{4}-0{4}-0{4}-0{12})$'
}

function ConvertTo-BecTimeline {
    param([object[]]$Collections,[string]$Target)
    $events=[Collections.Generic.List[object]]::new();$dedupe=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($c in $Collections){
        for($i=0;$i -lt $c.Items.Count;$i++){
            $raw=$c.Items[$i];$a=$raw;$flags=[Collections.Generic.List[string]]::new();$facts=[Collections.Generic.List[string]]::new();$ids=[Collections.Generic.List[string]]::new()
            if($null -eq $raw){$flags.Add('NullRecord')}
            $payload=Get-BecValue $raw 'AuditData'
            if($payload -is [string]){try{$a=ConvertFrom-Json $payload -Depth 100 -ErrorAction Stop}catch{$flags.Add('UnparseableAuditPayload')}} elseif($payload -is [Collections.IDictionary] -or $payload -is [pscustomobject]){$a=$payload}
            if($c.Source -eq 'Trace.Details'){$a=Get-BecValue $raw 'Payload'}
            $time=if($c.Kind -eq 'CurrentSnapshot'){ConvertTo-BecUtc $c.StartedUtc}else{ConvertTo-BecUtc (Get-BecFirst $a @('CreationTime','Received','createdDateTime','activityDateTime','Timestamp','detectedDateTime','Date','Time'))}
            $op=[string](Get-BecFirst $a @('Operation','activityDisplayName','ActionType','Event','riskEventType') $c.Source)
            $actor=[string](Get-BecFirst $a @('UserId','userPrincipalName','AccountUpn','SenderAddress','SenderFromAddress','SenderMailFromAddress') '')
            if(-not $actor){$actor=[string](Get-BecFirst (Get-BecValue (Get-BecValue $a 'initiatedBy') 'user') @('userPrincipalName','id') '')}
            $targetValue=[string](Get-BecFirst $a @('MailboxOwnerUPN','RecipientAddress','RecipientEmailAddress') $Target)
            $result=Get-BecFirst $a @('ResultStatus','Result','ActionResult','DeliveryAction','Status','result','riskLevel') ''
            if($result -isnot [string] -and $null -ne $result){$result=ConvertTo-BecJson $result}
            $ip=[string](Get-BecFirst $a @('ClientIP','ClientIPAddress','IPAddress','ipAddress','RemoteIP') '')
            $session=[string](Get-BecFirst $a @('SessionId','sessionId') '')
            $internet=Get-BecFirst $a @('InternetMessageId','MessageId')
            if(Test-BecIdentifier $internet){$ids.Add([string]$internet)}
            $network=[string](Get-BecValue $a 'NetworkMessageId' '')
            if(-not (Test-BecIdentifier $network)){$network=''}
            if($c.Source -eq 'Defender.UrlClicks'){
                $flags.Add('UrlClickObserved');$facts.Add('Safe Links event only; not full browsing history or proof of credential submission.')
                # Missing/default IDs, and explicitly Drafts/Sent events, cannot establish an email link.
                $folder=[string](Get-BecFirst $a @('Folder','FolderName') '')
                if($folder -match '(?i)^(drafts|sent|sent items)$'){$network='';$flags.Add('ClickMessageUnlinked')}
                if(-not $network){$flags.Add('ClickMessageUnlinked')}
                $facts.Add('ActionType='+[string](Get-BecValue $a 'ActionType')+'; IsClickedThrough='+[string](Get-BecValue $a 'IsClickedThrough'))
            }
            if($op -eq 'MailItemsAccessed'){
                $access=Get-BecValue $a 'MailAccessType'
                foreach($p in @(Get-BecList $a 'OperationProperties' @())){if((Get-BecValue $p 'Name') -eq 'MailAccessType'){$access=Get-BecValue $p 'Value'}}
                $flags.Add('MailAccessAggregate');$facts.Add("MailItemsAccessed $access; service aggregate, not proof of human reading. Offline reads are absent.")
                if($access -eq 'Bind'){
                    foreach($folder in @(Get-BecList $a 'Folders' @())){foreach($item in @(Get-BecList $folder 'FolderItems' @())){$m=Get-BecValue $item 'InternetMessageId';if(Test-BecIdentifier $m){$ids.Add([string]$m)}}}
                    $facts.Add('Bind item IDs remain within this aggregated event; no fabricated item timestamps.')
                }elseif($access -eq 'Sync'){$ids.Clear();$facts.Add('Sync is folder-level; no item-level access is inferred.')}
            }
            if($op -match '(?i)inboxrule|forward|permission|consent|authentication|password|security info'){$flags.Add('ConfigurationChangeReview')}
            if($c.Source -eq 'Exchange.Mailbox' -and ((Get-BecValue $a 'ForwardingAddress') -or (Get-BecValue $a 'ForwardingSmtpAddress'))){$flags.Add('ForwardingConfiguredNow')}
            if($c.Source -in @('Entra.SignIns','Entra.NonInteractiveSignIns')){
                $status=Get-BecValue $a 'status';$code=Get-BecValue $status 'errorCode'
                if($null -ne $code -and $code -ne 0){$flags.Add('FailedSignIn')}
                $facts.Add('MFA/CA evidence: '+(ConvertTo-BecJson @{authenticationRequirement=(Get-BecValue $a 'authenticationRequirement');authenticationDetails=(Get-BecValue $a 'authenticationDetails');conditionalAccessStatus=(Get-BecValue $a 'conditionalAccessStatus');deviceDetail=(Get-BecValue $a 'deviceDetail');location=(Get-BecValue $a 'location')}))
            }
            if($c.Source -eq 'Entra.Risks'){$flags.Add('ProviderRiskSignal')}
            if($null -eq $time){$flags.Add('MissingOrInvalidTimestamp')}
            if($c.Kind -eq 'CurrentSnapshot'){$facts.Add('Observed at collection time; not the configuration during the requested historical period.')}
            $sourceId=[string](Get-BecFirst $a @('Id','id','Identity') '')
            $family=if($c.Source -in @('Trace.Sent','Trace.Received')){'Trace'}else{$c.Source}
            $traceIdentity=Get-BecValue $a 'MessageTraceId';$traceRecipient=Get-BecValue $a 'RecipientAddress';$traceTime=ConvertTo-BecUtc (Get-BecValue $a 'Received')
            $identity=if($family -eq 'Trace' -and $traceIdentity -and $traceRecipient -and $traceTime){[string]$traceIdentity+'|'+[string]$traceRecipient+'|'+$traceTime.ToString('o')}elseif($family -ne 'Trace' -and (Test-BecIdentifier $sourceId)){$sourceId}else{Get-BecHash (ConvertTo-BecJson $raw)}
            $key=$family+'|'+$identity
            $ref='raw/'+$c.Source+'.json#/Items/'+$i
            if($dedupe.ContainsKey($key)){
                $dedupe[$key].RawRefs+=@($ref)
                if($c.Source -cnotin $dedupe[$key].Sources){$dedupe[$key].Sources+=@($c.Source)}
                continue
            }
            $event=[pscustomobject]@{
                EventId=(Get-BecHash $key).Substring(0,24);TimeUtc=$(if($time){$time.ToString('o')}else{$null});TimeQuality=$(if($time){if($c.Kind -eq 'CurrentSnapshot'){'CollectionTime'}else{'ProviderTime'}}else{'Unknown'})
                Source=$c.Source;Sources=@($c.Source);Kind=$c.Kind;Actor=$actor;Target=$targetValue;Operation=$op;Result=[string]$result;IP=$ip
                Client=[string](Get-BecFirst $a @('ClientInfoString','clientAppUsed','UserAgent') '');App=[string](Get-BecFirst $a @('appDisplayName','Application','AppId') '')
                SessionId=$session;InternetMessageIds=@($ids.ToArray() | Select-Object -Unique);NetworkMessageId=$network;TraceId=[string](Get-BecFirst $raw @('MessageTraceId') '')
                ReportId=[string](Get-BecValue $a 'ReportId' '');Subject=[string](Get-BecFirst $a @('Subject','EmailSubject','Title') '');Url=[string](Get-BecFirst $a @('Url','RemoteUrl') '')
                RawRefs=@($ref);ReviewFlags=@($flags.ToArray() | Select-Object -Unique);ObservedFacts=$facts.ToArray()
            }
            $dedupe.Add($key,$event);$events.Add($event)
        }
    }
    return @($events.ToArray() | Sort-Object @{Expression={if($_.TimeUtc){0}else{1}}},TimeUtc,EventId)
}

function Get-BecCorrelations {
    param([object[]]$Timeline,[int]$MaxLinks=10000)
    $links=[Collections.Generic.List[object]]::new();$buckets=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal);$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$capped=$false
    foreach($e in $Timeline){
        $keys=[Collections.Generic.List[string]]::new()
        foreach($id in $e.InternetMessageIds){if(Test-BecIdentifier $id){$keys.Add('InternetMessageId|'+$id)}}
        if(Test-BecIdentifier $e.NetworkMessageId){$keys.Add('NetworkMessageId|'+$e.NetworkMessageId)}
        # Session identifiers are only treated as exact within the same provider family.
        if(Test-BecIdentifier $e.SessionId){$keys.Add('Session|'+$e.Source.Split('.')[0]+'|'+$e.SessionId)}
        if($e.Source -eq 'Defender.UrlClicks' -and (Test-BecIdentifier $e.ReportId)){$keys.Add('ClickReportId|'+$e.ReportId)}
        if($e.IP -and $e.TimeUtc){$keys.Add('IP|'+$e.IP)}
        foreach($k in $keys){
            if(-not $buckets.ContainsKey($k)){$buckets[$k]=[Collections.Generic.List[object]]::new()}
            foreach($prior in $buckets[$k]){
                $inferred=$k.StartsWith('IP|')
                if($inferred -and [Math]::Abs(([DateTimeOffset]$e.TimeUtc-[DateTimeOffset]$prior.TimeUtc).TotalMinutes) -gt 30){continue}
                if($k.StartsWith('NetworkMessageId|') -and ($e.Source -eq 'Defender.UrlClicks' -or $prior.Source -eq 'Defender.UrlClicks') -and $e.Source -ne 'Defender.Email' -and $prior.Source -ne 'Defender.Email'){continue}
                $pair=$prior.EventId+'|'+$e.EventId+'|'+$k
                if(-not $seen.Add($pair)){continue}
                if($links.Count -ge $MaxLinks){$capped=$true;break}
                $links.Add([pscustomobject]@{From=$prior.EventId;To=$e.EventId;Basis=$k.Split('|')[0];Classification=$(if($inferred){'Inferred'}else{'Observed shared identifier'});Explanation=$(if($inferred){'Same IP within 30 minutes. Shared NAT/proxy/VPN is possible; not proof of same actor.'}else{'Exact identifier match only; not proof of causation, human reading, or credential submission.'})})
            }
            $buckets[$k].Add($e)
            if($capped){break}
        }
        if($capped){break}
    }
    [pscustomobject]@{Items=$links.ToArray();Partial=$capped;Limit=$MaxLinks}
}
