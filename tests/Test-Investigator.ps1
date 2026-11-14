# Native, dependency-free evaluator. Every provider call below is injected; no tenant is contacted.
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/M365Bec.psm1" -Force -DisableNameChecking
$script:checks=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Condition){$script:checks.Add([pscustomobject]@{Name=$Name;Passed=$Condition});if(-not $Condition){Write-Host "FAIL $Name"}}
function Block([string]$Name,[scriptblock]$Body){try{& $Body}catch{$script:checks.Add([pscustomobject]@{Name=$Name;Passed=$false;Error=$_.Exception.Message;Line=$_.InvocationInfo.ScriptLineNumber});Write-Host "ERROR ${Name}: $_"}}
function Rejects([scriptblock]$Action){$threw=$false;try{& $Action | Out-Null}catch{$threw=$true};return $threw}
$target='alex@contoso.example';$start=[DateTimeOffset]'2026-11-01T00:00:00Z';$end=[DateTimeOffset]'2026-11-02T00:00:00Z'

Block 'primitives' {
    Check 'valid UPN' (Test-BecUpn $target)
    Check 'invalid UPN' (-not (Test-BecUpn 'x@@example.com'))
    Check 'command-like UPN rejected' (-not (Test-BecUpn 'x;pwd@example.com'))
    Check 'null timestamp' ($null -eq (ConvertTo-BecUtc $null))
    Check 'locale timestamp rejected' ($null -eq (ConvertTo-BecUtc '11/10/2026'))
    Check 'impossible timestamp rejected' ($null -eq (ConvertTo-BecUtc '2026-02-30T00:00:00Z'))
    Check 'offset instant normalized' ((ConvertTo-BecUtc '2026-11-10T10:00:00+01:00').ToString('HH:mmzzz') -eq '09:00+00:00')
    Check 'null ID rejected' (-not (Test-BecIdentifier $null))
    Check 'zero GUID rejected' (-not (Test-BecIdentifier '00000000-0000-0000-0000-000000000000'))
    Check 'padded zero GUID rejected' (-not (Test-BecIdentifier ' 00000000-0000-0000-0000-000000000000 '))
    Check 'padded unknown sentinel rejected' (-not (Test-BecIdentifier ' unknown '))
}
Block 'pager bounds and immutability' {
    $rows=@([pscustomobject]@{Id='a'},[pscustomobject]@{Id='b'});$before=ConvertTo-BecJson $rows
    $r=Invoke-BecPagedQuery {param($t) @{Items=$rows;NextToken=$null;IsComplete=$true}} -MaxItems 1
    Check 'item cap is partial' ($r.Status -eq 'Partial' -and $r.Reason -eq 'max-items')
    Check 'fetched overflow retained' ($r.OverflowItems.Count -eq 2 -and $r.Items.Count -eq 0)
    Check 'overflow provenance count' ($r.Pages.Count -eq 1 -and $r.Pages[0].Count -eq 2)
    Check 'input unchanged' ((ConvertTo-BecJson $rows) -ceq $before)
    $state=@{N=0};$r=Invoke-BecPagedQuery {param($t) $state.N++;@{Items=@(@{Id='same'});NextToken=[string]$state.N;IsComplete=$false}}
    Check 'same data new cursors detected' ($r.Reason -eq 'repeated-page' -and $r.Pages.Count -eq 2)
}
Block 'retry and throttle' {
    $state=@{N=0;Waits=[Collections.Generic.List[double]]::new()}
    $r=Invoke-BecRequest -Action {$state.N++;if($state.N -eq 1){$e=[Exception]::new('throttled');$e.Data['StatusCode']=429;$e.Data['RetryAfterSeconds']=3;throw $e};'ok'} -Sleep {param($s)$state.Waits.Add($s)}
    Check 'transient request recovers' ($r.Success -and $r.Value -eq 'ok' -and $r.Attempts.Count -eq 2)
    Check 'retry after honored' ($state.Waits.Count -eq 1 -and $state.Waits[0] -eq 3)
    $r=Invoke-BecRequest -Action {$e=[Exception]::new('throttled');$e.Data['StatusCode']=429;$e.Data['RetryAfterSeconds']=120;throw $e} -Sleep {throw 'Must not sleep'}
    Check 'long RetryAfter stops explicitly' (-not $r.Success -and $r.Attempts.Count -eq 1)
    Check 'refused RetryAfter retained in provenance' ($r.Attempts[0].ServerRetryAfterSeconds -eq 120 -and -not $r.Attempts[0].WillRetry)
    $r=Invoke-BecRequest -Action {$e=[Exception]::new('forbidden');$e.Data['StatusCode']=403;throw $e} -Sleep {throw 'Must not retry'}
    Check '403 not retried' ($r.Failure.Status -eq 'Denied' -and $r.Attempts.Count -eq 1)
    $clock=@{Now=[DateTimeOffset]'2026-11-01T00:00:00Z';Wait=0.0}
    $throttle=New-BecThrottle -Limit 2 -PeriodSeconds 5 -Now {$clock.Now} -Sleep {param($s)$clock.Wait+=$s;$clock.Now=$clock.Now.AddSeconds($s)}
    Wait-BecThrottle $throttle;Wait-BecThrottle $throttle;Wait-BecThrottle $throttle
    Check 'sliding quota enforced' ($clock.Wait -ge 5 -and $throttle.Times.Count -le 2)
}
Block 'target matching' {
    $data=@{UserId='admin@contoso.example';MailboxOwnerUPN=$target;Operation='Set-Mailbox'}
    Check 'other actor target JSON matched' (Test-BecTargetAudit @{AuditData=(ConvertTo-BecJson $data)} $target '')
    Check 'parsed audit object matched' (Test-BecTargetAudit @{AuditData=[pscustomobject]$data} $target '')
    Check 'parsed audit hashtable matched' (Test-BecTargetAudit @{AuditData=$data} $target '')
    Check 'actor itself matched' (Test-BecTargetAudit @{UserId=$target} $target '')
    Check 'unrelated subject not matched' (-not (Test-BecTargetAudit @{Subject=$target;UserId='other@contoso.example'} $target ''))
    Check 'target parameter matched' (Test-BecTargetAudit @{Parameters=@(@{Name='Mailbox';Value=$target})} $target '')
    Check 'directory target matched' (Test-BecTargetAudit @{targetResources=@(@{id='user-id'})} $target 'user-id')
    Check 'malformed audit rejected' (-not (Test-BecTargetAudit @{AuditData='{bad'} $target ''))
    Check 'mailbox-qualified rule identity matched' (Test-BecTargetAudit @{ObjectId=($target+'\rule-123');UserId='admin@contoso.example'} $target '')
    Check 'identity prefix collision rejected' (-not (Test-BecTargetAudit @{ObjectId=($target+'.evil\rule')} $target ''))
    $c=New-BecCollection 'Exchange.Mailbox';$c.Items=@(@{PrimarySmtpAddress='primary@contoso.example';EmailAddresses=@('SMTP:primary@contoso.example','smtp:alias@contoso.example','X500:/o=legacy');ExchangeGuid='mailbox-guid'})
    $identity=Get-BecMailboxIdentity $target @($c)
    Check 'SMTP aliases and primary collected' ($identity.Addresses.Count -eq 3 -and 'alias@contoso.example' -in $identity.Addresses)
    Check 'verified mailbox GUID matches other actor audit' (Test-BecTargetAudit @{ObjectId='mailbox-guid';UserId='admin@contoso.example'} $target $identity.Identifiers)
}
Block 'trace continuation windows and detail cap' {
    $state=@{Calls=[Collections.Generic.List[object]]::new()}
    $ctx=New-BecContext -Transport {param($cmd,$p)
        $state.Calls.Add(@{Command=$cmd;Params=$p.Clone()})
        if($cmd -eq 'Get-MessageTraceV2'){
            if($p.ContainsKey('StartingRecipientAddress')){return @()}
            if($p.ContainsKey('SenderAddress')){return @()}
            for($i=0;$i -lt 5000;$i++){[pscustomobject]@{MessageTraceId="trace-$i";Received=$p.EndDate.AddHours(-1).ToString('o');RecipientAddress=$target;SenderAddress='sender@outside.example';MessageId="<m$i@example>"}}
        }elseif($cmd -eq 'Get-MessageTraceDetailV2'){@{Event='Deliver';Date='2026-11-01T12:00:00Z'}}else{throw 'Unexpected command'}
    } -Sleep {throw 'Unexpected wait'} -MaxDetails 1
    $r=@(Invoke-BecTrace $target $start $start.AddDays(21) $ctx -Now $start.AddDays(22))
    Check 'trace both directions' ($r.Count -eq 2 -and $r[0].Source -eq 'Trace.Sent' -and $r[1].Source -eq 'Trace.Received')
    Check 'trace windows exhausted' (@($r | Where-Object Status -ne 'Collected').Count -eq 0)
    Check 'three windows per direction' ($r[0].Windows.Count -eq 3 -and $r[1].Windows.Count -eq 3)
    Check 'max ten day windows' (@($state.Calls | Where-Object {($_.Params.EndDate-$_.Params.StartDate).TotalDays -gt 10}).Count -eq 0)
    Check 'full pages followed with real cursor' (@($state.Calls | Where-Object {$_.Params.ContainsKey('StartingRecipientAddress')}).Count -eq 3)
    Check 'no synthetic cursor sent to trace API' (@($state.Calls | Where-Object {$_.Params.ContainsKey('NextToken')}).Count -eq 0)
    Check 'trace raw retained' ($r[1].Items.Count -eq 15000)
    $detail=Invoke-BecTraceDetails @($r[1].Items | Select-Object -First 2) $start $start.AddDays(21) $ctx
    Check 'detail cap explicit' ($detail.Status -eq 'Partial' -and $detail.Items.Count -eq 1 -and $detail.Reason -match 'cap')
    $old=@(Invoke-BecTrace $target $start $end $ctx -Now $start.AddDays(100))
    Check 'trace outside retention explicit' (@($old | Where-Object Status -eq 'OutsideRetention').Count -eq 2)
}
Block 'UAL paging and other actor' {
    $state=@{Calls=[Collections.Generic.List[object]]::new();N=0}
    $ctx=New-BecContext -Transport {param($cmd,$p)
        $state.Calls.Add($p.Clone());$state.N++
        if($state.N -eq 1){@{AuditData=(ConvertTo-BecJson @{Id='target-event';UserId='admin@contoso.example';MailboxOwnerUPN=$target})};@{AuditData=(ConvertTo-BecJson @{Id='unrelated';UserId='elsewhere@contoso.example'})}}
    } -Sleep {throw 'Unexpected wait'}
    $r=Invoke-BecAudit $target $start $end $ctx
    Check 'short UAL page followed until empty' ($state.N -eq 2 -and $r.Status -eq 'Collected')
    Check 'same UAL session and large-set mode' ($state.Calls[0].SessionId -eq $state.Calls[1].SessionId -and $state.Calls[0].SessionCommand -eq 'ReturnLargeSet')
    Check 'no actor-only query filter' (-not $state.Calls[0].ContainsKey('UserIds'))
    Check 'other actor retained unrelated omitted' ($r.Scanned -eq 2 -and $r.Items.Count -eq 1)
    $ctx=New-BecContext -Transport {param($cmd,$p)$e=[Exception]::new('forbidden');$e.Data['StatusCode']=403;throw $e}
    $r=Invoke-BecAudit $target $start $end $ctx
    Check 'audit denial explicit' ($r.Status -eq 'Denied' -and $r.Items.Count -eq 0 -and $r.Pages.Count -ge 1)
}
Block 'Graph pagination and URI safety' {
    $state=@{N=0}
    $uri='https://graph.microsoft.com/v1.0/auditLogs/signIns'
    $ctx=New-BecContext -Transport {param($cmd,$p)$state.N++;if($state.N -eq 1){@{value=@(@{id='a'});'@odata.nextLink'=$uri+'?$skiptoken=x'}}else{@{value=@(@{id='b'})}}}
    $r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx
    Check 'Graph pages complete' ($r.Items.Count -eq 2 -and $r.Status -eq 'Collected' -and $state.N -eq 2)
    foreach($bad in @('http://graph.microsoft.com/v1.0/users','https://evil.example/v1.0/users','https://graph.microsoft.com:444/v1.0/users','https://a@graph.microsoft.com/v1.0/users','https://graph.microsoft.com/beta/users')){Check ('unsafe URI '+$bad) (Rejects {Assert-BecGraphUri $bad})}
    $state.N=0;$ctx=New-BecContext -Transport {param($cmd,$p)$state.N++;@{value=@(@{id='a'});'@odata.nextLink'='https://graph.microsoft.com/v1.0/users/alex/messages'}}
    $r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx
    Check 'changed collection continuation blocked and fetched page retained' ($state.N -eq 1 -and $r.Status -eq 'Partial' -and $r.Items.Count -eq 1)
    $state.N=0;$ctx=New-BecContext -Transport {param($cmd,$p)$state.N++;@{value=@(@{id='kept'});'@odata.nextLink'='https://evil.example/steal'}}
    $r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx
    Check 'remote continuation not followed, evidence retained' ($state.N -eq 1 -and $r.Status -eq 'Partial' -and $r.Items[0].id -eq 'kept')
    $ctx=New-BecContext -Transport {param($cmd,$p)$e=[Exception]::new('forbidden');$e.Data['StatusCode']=403;throw $e}
    $r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx
    Check 'Graph denied preserved' ($r.Status -eq 'Denied')
}
Block 'snapshots and mixed failures' {
    $state=@{Commands=[Collections.Generic.List[string]]::new()}
    $ctx=New-BecContext -Transport {param($cmd,$p)$state.Commands.Add($cmd)
        if($cmd -eq 'Get-MobileDeviceStatistics'){$e=[Exception]::new('forbidden');$e.Data['StatusCode']=403;throw $e}
        if($cmd -eq 'Get-MailboxFolderStatistics'){@{FolderPath='/Inbox'};@{FolderPath='/Calendar'}}
        elseif($cmd -eq 'Get-MailboxFolderPermission'){@{User='Default';AccessRights=@('None')}}
        else{@{Identity=$target}}
    } -MaxFolders 1
    $r=@(Invoke-BecExchange $target $ctx)
    Check 'all Exchange snapshot sources returned' ($r.Count -eq 10)
    Check 'mobile denial independent' (($r | Where-Object Source -eq 'Exchange.Mobile').Status -eq 'Denied')
    Check 'other snapshot survives denial' (($r | Where-Object Source -eq 'Exchange.Mailbox').Status -eq 'Collected')
    Check 'folder cap partial' (($r | Where-Object Source -eq 'Exchange.FolderPermissions').Status -eq 'Partial')
    Check 'snapshots not historical' (@($r | Where-Object Kind -ne 'CurrentSnapshot').Count -eq 0)
    $ctx=New-BecContext -Transport {param($cmd,$p)throw "Module unavailable: $cmd"}
    $r=@(Invoke-BecEntra $target $start $end $ctx)
    Check 'absent Graph modules handled independently' ($r.Count -eq 6 -and @($r | Where-Object Status -ne 'Unavailable').Count -eq 0)
    $r=@(Invoke-BecDefender $target $start $end $ctx -Enabled $false)
    Check 'optional Defender unrequested explicit' ($r.Count -eq 4 -and @($r | Where-Object Status -ne 'Unavailable').Count -eq 0)
}
Block 'hunting contract' {
    $state=@{Calls=[Collections.Generic.List[object]]::new()}
    $ctx=New-BecContext -Transport {param($cmd,$p)
        if($cmd -eq 'Get-MgContext'){@{Environment='Global'}}
        else{$state.Calls.Add($p);@{results=@(@{Timestamp='2026-11-01T12:00:00Z';AccountUpn=$target;ActionType='ClickBlocked';NetworkMessageId='';ReportId='one'})}}
    }
    $r=@(Invoke-BecDefender $target $start $end $ctx -Enabled $true -Now $end)
    Check 'four hunting collectors' ($r.Count -eq 4 -and @($r | Where-Object Status -ne 'Collected').Count -eq 0)
    Check 'modern Graph hunting endpoint only' (@($state.Calls | Where-Object {$_.Uri -ne 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -or $_.Method -ne 'POST'}).Count -eq 0)
    Check 'query target and cap' (@($state.Calls | Where-Object {($_.Body | ConvertFrom-Json).Query -notmatch 'take 10000'}).Count -eq 0)
    Check 'KQL input escaped' ((Get-BecHuntingQuery UrlClicks 'a"| take 1// @x.example' $start $end) -match '\\"')
    $ctx=New-BecContext -Transport {param($cmd,$p)if($cmd -eq 'Get-MgContext'){@{Environment='Global'}}else{@{results=@(1..10000 | ForEach-Object {@{Timestamp='2026-11-01T12:00:00Z';ReportId=[string]$_}})}}}
    $r=@(Invoke-BecDefender $target $start $end $ctx -Enabled $true -Now $end)
    Check 'hunting saturated pages explicit partial' (@($r | Where-Object {$_.Status -eq 'Partial' -and $_.Items.Count -eq 10000}).Count -eq 4)
}
Block 'Entra source mapping' {
    $state=@{Uris=[Collections.Generic.List[string]]::new()}
    $ctx=New-BecContext -Transport {param($cmd,$p)
        if($cmd -eq 'Get-MgContext'){return @{Environment='Global'}}
        $state.Uris.Add($p.Uri)
        if($p.Uri -match '/users/[^/]+\?\$select=') {return @{id='synthetic-id';userPrincipalName=$target}}
        if($p.Uri -match '/directoryAudits') {return @{value=@(@{id='audit';activityDateTime='2026-11-01T12:00:00Z';initiatedBy=@{user=@{userPrincipalName='admin@contoso.example'}};targetResources=@(@{id='synthetic-id'})})}}
        return @{value=@()}
    }
    $r=@(Invoke-BecEntra $target $start $end $ctx)
    Check 'Entra six coverage entries' ($r.Count -eq 6)
    Check 'preview opt-out explicit' (($r | Where-Object Source -eq 'Entra.NonInteractiveSignIns').Status -eq 'Unavailable')
    Check 'Entra other-actor target retained' (($r | Where-Object Source -eq 'Entra.Audit').Items.Count -eq 1)
    Check 'user and tenant OAuth collected separately' (@($state.Uris | Where-Object {$_ -match 'oauth2PermissionGrants'}).Count -eq 2)
    Check 'user lookup URL escapes UPN' ($state.Uris[0] -match 'alex%40contoso.example')
    Check 'risk query target scoped' (@($state.Uris | Where-Object {$_ -match 'riskDetections' -and [uri]::UnescapeDataString($_) -match "userId eq 'synthetic-id'"}).Count -eq 1)
}
Block 'optional noninteractive preview' {
    $state=@{Uris=[Collections.Generic.List[string]]::new();BetaPages=0}
    $ctx=New-BecContext -Transport {param($cmd,$p)
        if($cmd -eq 'Get-MgContext'){return @{Environment='Global'}}
        $state.Uris.Add($p.Uri)
        if($p.Uri -match '/users/[^/]+\?\$select='){return @{id='user-id'}}
        if($p.Uri -match '/beta/auditLogs/signIns'){
            $state.BetaPages++
            if($state.BetaPages -eq 1){return @{value=@(@{id='ni-1';createdDateTime='2026-11-01T12:00:00Z';userPrincipalName=$target;signInEventTypes=@('nonInteractiveUser');isInteractive=$false;sessionId='ni-session';status=@{errorCode=0}});'@odata.nextLink'='https://graph.microsoft.com/beta/auditLogs/signins?$skiptoken=opaque'}}
            return @{value=@(@{id='ni-2';createdDateTime='2026-11-01T12:01:00Z';userPrincipalName=$target;signInEventTypes=@('nonInteractiveUser');status=@{errorCode=50126}})}
        }
        return @{value=@()}
    }
    $r=@(Invoke-BecEntra $target $start $end $ctx -IncludeNonInteractivePreview)
    $ni=$r | Where-Object Source -eq 'Entra.NonInteractiveSignIns'
    Check 'preview collector separate and complete pages' ($r.Count -eq 6 -and $ni.Status -eq 'Collected' -and $ni.Items.Count -eq 2 -and $state.BetaPages -eq 2)
    Check 'preview clearly labeled' ($ni.Provider -eq 'MicrosoftGraphBetaPreview' -and @($ni.Notes -match 'preview API').Count -eq 1)
    $query=[uri]::UnescapeDataString(@($state.Uris | Where-Object {$_ -match '/beta/'})[0])
    Check 'explicit user noninteractive filter and UTC bounds' ($query -match "signInEventTypes/any\(t: t eq 'nonInteractiveUser'\)" -and $query -match "userPrincipalName eq 'alex@contoso.example'" -and $query -match 'createdDateTime ge 2026-11-01T00:00:00Z')
    Check 'preview endpoint allowed only with explicit switch' (-not (Rejects {Assert-BecGraphUri 'https://graph.microsoft.com/beta/auditLogs/signIns' -AllowPreviewSignIns}))
    Check 'other beta endpoints refused' (Rejects {Assert-BecGraphUri 'https://graph.microsoft.com/beta/users' -AllowPreviewSignIns})
    Check 'preview other cloud refused' (Rejects {Assert-BecGraphUri 'https://graph.microsoft.us/beta/auditLogs/signIns' -AllowPreviewSignIns})
    $t=@(ConvertTo-BecTimeline @($ni) $target)
    Check 'preview success/failure normalization' ($t.Count -eq 2 -and @($t | Where-Object {$_.ReviewFlags -contains 'FailedSignIn'}).Count -eq 1)
    $state=@{N=0};$ctx=New-BecContext -Transport {param($cmd,$p)$state.N++;$e=[Exception]::new('forbidden');$e.Data['StatusCode']=403;throw $e}
    $denied=Invoke-BecGraphCollection 'Entra.NonInteractiveSignIns' 'https://graph.microsoft.com/beta/auditLogs/signIns' $ctx
    Check 'preview permission failure explicit' ($denied.Status -eq 'Denied' -and $state.N -eq 1)
}
Block 'normalization and correlations' {
    $f=Get-Content "$root/fixtures/bec-synthetic.json" -Raw | ConvertFrom-Json -Depth 100
    $collections=@(Get-BecFixtureCollections $f $start $end);$before=ConvertTo-BecJson $collections
    $t=@(ConvertTo-BecTimeline $collections $target);$links=Get-BecCorrelations $t
    Check 'raw collections unchanged by normalization' ((ConvertTo-BecJson $collections) -ceq $before)
    Check 'unknown dates sort last' ($t[-1].TimeQuality -eq 'Unknown')
    Check 'offset sign-in instant correct' (($t | Where-Object {$_.Source -eq 'Entra.SignIns' -and $_.Operation -eq 'Entra.SignIns' -and $_.Result -match 'errorCode.:0'}).TimeUtc -match 'T09:10:00')
    $bind=@($t | Where-Object {$_.ObservedFacts -match 'Bind item IDs'})
    $sync=@($t | Where-Object {$_.ObservedFacts -match 'Sync is folder-level'})
    Check 'one Bind aggregate with IDs' ($bind.Count -eq 1 -and $bind[0].InternetMessageIds.Count -eq 1)
    Check 'Sync stays folder level' ($sync.Count -eq 1 -and $sync[0].InternetMessageIds.Count -eq 0)
    Check 'non-human-reading caveat' (@($bind[0].ObservedFacts -match 'not proof of human reading').Count -gt 0)
    Check 'exact email linkage exists' (@($links.Items | Where-Object Basis -eq 'NetworkMessageId').Count -gt 0)
    Check 'IP links explicitly inferred' (@($links.Items | Where-Object {$_.Basis -eq 'IP' -and $_.Classification -ne 'Inferred'}).Count -eq 0 -and @($links.Items | Where-Object Basis -eq 'IP').Count -gt 0)
    $unlinked=$t | Where-Object {$_.Source -eq 'Defender.UrlClicks' -and $_.NetworkMessageId -eq ''}
    Check 'default message ID never joined' (@($links.Items | Where-Object {$_.Basis -eq 'NetworkMessageId' -and ($_.From -eq $unlinked.EventId -or $_.To -eq $unlinked.EventId)}).Count -eq 0)
    $limited=Get-BecCorrelations $t -MaxLinks 1
    Check 'link cap disclosed' ($limited.Partial -and $limited.Items.Count -eq 1)
    $c=New-BecCollection 'Trace.Received';$c.Items=@(@{MessageTraceId='id';RecipientAddress=$target;Received='2026-11-01T00:00:00Z'},@{MessageTraceId='id';RecipientAddress=$target;Received='2026-11-01T00:00:00Z'})
    $d=@(ConvertTo-BecTimeline @($c) $target)
    Check 'dedupe merges evidence references' ($d.Count -eq 1 -and $d[0].RawRefs.Count -eq 2)
    $c.Items=@($null,@{Subject='missing identity'})
    $d=@(ConvertTo-BecTimeline @($c) $target)
    Check 'null and missing trace fields remain distinct' ($d.Count -eq 2)
    $a=New-BecCollection 'Trace.Sent';$b=New-BecCollection 'Trace.Received'
    $a.Items=@(@{MessageTraceId='self';RecipientAddress=$target;SenderAddress=$target;Received='2026-11-01T00:00:00Z'});$b.Items=$a.Items
    $self=@(ConvertTo-BecTimeline @($a,$b) $target)
    Check 'self mail retains both directions' ($self.Count -eq 1 -and $self[0].Sources.Count -eq 2)
    $a.Items=@(@{MessageTraceId='one';RecipientAddress=$target;Received='2026-11-01T00:00:00Z';MessageId='<A@x>'},@{MessageTraceId='two';RecipientAddress=$target;Received='2026-11-01T00:00:00Z';MessageId='<a@x>'})
    $caseEvents=@(ConvertTo-BecTimeline @($a) $target);$caseLinks=Get-BecCorrelations $caseEvents
    Check 'opaque message IDs are case-sensitive' ($caseLinks.Items.Count -eq 0)
    $caseEvents[0].SessionId='Case';$caseEvents[1].SessionId='case';$caseLinks=Get-BecCorrelations $caseEvents
    Check 'opaque session IDs are case-sensitive' ($caseLinks.Items.Count -eq 0)
    foreach($event in $caseEvents){$event.InternetMessageIds=@(' unknown ');$event.SessionId=' 00000000-0000-0000-0000-000000000000 ';$event.NetworkMessageId=' unknown '}
    $caseLinks=Get-BecCorrelations $caseEvents
    Check 'padded sentinels never create links' ($caseLinks.Items.Count -eq 0)
}
Block 'safe output and evidence integrity' {
    foreach($text in @('=1+1',' +SUM(1,2)',"`t@SUM(1)",(([string][char]0x200B)+'-1'))){Check ('CSV formula protected '+$text) ((ConvertTo-BecCsvValue $text).StartsWith("'"))}
    Check 'ordinary CSV unchanged' ((ConvertTo-BecCsvValue 'ordinary') -ceq 'ordinary')
    Check 'HTML escapes injection' ((ConvertTo-BecHtml '<script>alert(1)</script>') -eq '&lt;script&gt;alert(1)&lt;/script&gt;')
    Check 'URL defanged' ((ConvertTo-BecDisplay 'https://evil.example/a') -eq 'hxxps://evil[.]example/a')
    Check 'mixed scheme numeric host defanged' ((ConvertTo-BecDisplay 'hTtP://2130706433/path') -eq 'hxxp://2130706433/path')
    $r=Invoke-BecInvestigation -TargetUpn $target -Start $start -End ([DateTimeOffset]'2026-11-11T00:00:00Z') -Mode Fixture -FixturePath "$root/fixtures/bec-synthetic.json" -OutputRoot "$root/cases/tests" -ProjectRoot $root
    $script:casePath=$r.CasePath
    Check 'full synthetic case has every source' ($r.Coverage.Count -eq 24)
    Check 'case hashes verify' ((Test-BecManifest $r.CasePath).Passed)
    $html=Get-Content -LiteralPath $r.Report -Raw
    Check 'no script tag in report' ($html -notmatch '(?i)<script')
    Check 'no external assets or evidence links' ($html -notmatch '(?i)(src|href)\s*=\s*["'']https?://')
    Check 'hostile subject escaped' ($html -match '&lt;script&gt;alert\(1\)&lt;/script&gt;')
    Check 'synthetic warning and snapshot details present' ($html -match 'SYNTHETIC FIXTURE' -and $html -match 'DeliverToMailboxAndForward')
    $raw=Get-Content -LiteralPath (Join-Path $r.CasePath 'raw/Trace.Received.json') -Raw | ConvertFrom-Json -Depth 100
    Check 'raw hostile field unchanged' ($raw.Items[0].Subject.StartsWith('=HYPERLINK') -and $raw.Items[0].Subject.Contains('<script>'))
    $csv=Import-Csv -LiteralPath (Join-Path $r.CasePath 'timeline.csv')
    Check 'exported CSV formula neutralized' (@($csv | Where-Object {$_.Subject.StartsWith("'=HYPERLINK")}).Count -ge 1)
    $manifest=Get-Content -LiteralPath (Join-Path $r.CasePath 'manifest.json') -Raw | ConvertFrom-Json
    Check 'every raw collection hashed' (@($manifest.Files | Where-Object Path -like 'raw/*').Count -eq 24)
    $path=Join-Path $r.CasePath 'coverage.csv';$original=[IO.File]::ReadAllBytes($path);[IO.File]::AppendAllText($path,'tamper')
    Check 'byte modification detected' (-not (Test-BecManifest $r.CasePath).Passed)
    [IO.File]::WriteAllBytes($path,$original)
    Check 'restored test case verifies' ((Test-BecManifest $r.CasePath).Passed)
    # This fixture stays inside the project. Restore the directory after testing verifier traversal safety.
    $rawDir=Join-Path $r.CasePath 'raw';$backupDir=Join-Path $r.CasePath 'raw-held'
    [IO.Directory]::Move($rawDir,$backupDir)
    try{
        [void][IO.Directory]::CreateSymbolicLink($rawDir,$backupDir)
        Check 'intermediate symlink rejected' (-not (Test-BecManifest $r.CasePath).Passed)
        Check 'nested output symlink rejected' (Rejects {Write-BecCase (Join-Path $rawDir 'newcase') $root @{} @() @() @{Items=@();Partial=$false}})
    }finally{if((Get-Item -LiteralPath $rawDir -Force -ErrorAction SilentlyContinue).LinkType){[IO.Directory]::Delete($rawDir)};[IO.Directory]::Move($backupDir,$rawDir)}
    Check 'case restored after symlink test' ((Test-BecManifest $r.CasePath).Passed)
    Check 'output traversal rejected' (Rejects {Write-BecCase '/tmp/outside-case' $root @{} @() @() @{Items=@();Partial=$false}})
}
$result=[pscustomobject]@{PowerShell=$PSVersionTable.PSVersion.ToString();Total=$script:checks.Count;Passed=@($script:checks | Where-Object Passed).Count;Failed=@($script:checks | Where-Object {-not $_.Passed}).Count;CasePath=$script:casePath;Checks=$script:checks.ToArray();Network='No network calls; injected transports only'}
if($ResultsPath){$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ResultsPath -Encoding utf8}
$result | ConvertTo-Json -Depth 20
if($result.Failed){exit 1}
