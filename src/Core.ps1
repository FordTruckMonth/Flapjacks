Set-StrictMode -Version Latest

function Get-BecValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return ,$Object[$Name] }
    } elseif ($null -ne $Object.PSObject.Properties[$Name]) { return ,$Object.$Name }
    return $Default
}

function Get-BecList {
    param($Object,[string]$Name,$Default=@())
    $v=Get-BecValue $Object $Name $Default
    if($null -ne $v){foreach($item in $v){$item}}
}

function ConvertTo-BecUtc {
    param($Value)
    if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return ([DateTimeOffset]$Value).ToUniversalTime()
    }
    # Provider timestamps without an offset are documented UTC. Do not guess locale dates.
    if ($Value -isnot [string] -or $Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { return $null }
    $parsed = [DateTimeOffset]::MinValue
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-BecHash {
    param([AllowEmptyString()][string]$Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function ConvertTo-BecJson {
    param($Value)
    # Stop on depth loss instead of quietly claiming a complete raw export.
    return ConvertTo-Json -InputObject $Value -Depth 100 -Compress -WarningAction Stop
}

function New-BecCollection {
    param([string]$Source, [string]$Kind = 'Historical', [string]$Provider = 'Injected')
    [pscustomobject]@{
        Source=$Source; Kind=$Kind; Provider=$Provider; Status='Unavailable'; Reason='Not attempted'
        Items=@(); OverflowItems=@(); Pages=@(); Windows=@(); Notes=@(); StartedUtc=[DateTimeOffset]::UtcNow.ToString('o'); FinishedUtc=$null
        Scanned=0; Matched=0; Retention='Not independently verified'; QueryCompleteness='Unknown'
    }
}

function Get-BecFailureClass {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    $code = Get-BecValue $e 'ResponseStatusCode'
    if (-not $code) { $code = $e.Data['StatusCode'] }
    if (-not $code) { $code = Get-BecValue (Get-BecValue $e 'Response') 'StatusCode' }
    $message = [string]$e.Message
    $category = 'Partial'
    if ([string]$code -in @('401','403','Unauthorized','Forbidden') -or $message -match '(?i)access.?denied|unauthorized|insufficient.?privilege') { $category='Denied' }
    elseif ($e -is [System.Management.Automation.CommandNotFoundException] -or $message -match '(?i)not connected|module unavailable|not implemented|license required|table.*not.*found') { $category='Unavailable' }
    $retry = $e.Data['RetryAfterSeconds']
    $headers = Get-BecValue (Get-BecValue $e 'Response') 'Headers'
    if ($null -eq $retry -and $null -ne $headers) {
        $ra = Get-BecValue $headers 'RetryAfter'
        $delta = Get-BecValue $ra 'Delta'
        if ($delta) { $retry = $delta.TotalSeconds }
        elseif (Get-BecValue $ra 'Date') { $retry = [Math]::Max(0, ((Get-BecValue $ra 'Date') - [DateTimeOffset]::UtcNow).TotalSeconds) }
    }
    [pscustomobject]@{Status=$category; Code=[string]$code; Message=$message; RetryAfter=$retry; Transient=([string]$code -in @('429','503','504','TooManyRequests','ServiceUnavailable','GatewayTimeout'))}
}

function Invoke-BecRequest {
    param([scriptblock]$Action, [int]$MaxRetries=2, [double]$MaxRetryWaitSeconds=60,
          [scriptblock]$Sleep={param($seconds) Start-Sleep -Seconds $seconds})
    $attempts=[Collections.Generic.List[object]]::new()
    for($i=0; $i -le $MaxRetries; $i++) {
        $at=[DateTimeOffset]::UtcNow.ToString('o')
        try {
            $value = & $Action
            $attempts.Add([pscustomobject]@{Attempt=$i+1;AtUtc=$at;Outcome='Success';DelaySeconds=0})
            return [pscustomobject]@{Success=$true;Value=$value;Attempts=$attempts.ToArray();Failure=$null}
        } catch {
            $f=Get-BecFailureClass $_
            $delay=if($null -ne $f.RetryAfter){[double]$f.RetryAfter}else{[Math]::Pow(2,$i)}
            $retry=$f.Transient -and $i -lt $MaxRetries -and $delay -ge 0 -and $delay -le $MaxRetryWaitSeconds
            $attempts.Add([pscustomobject]@{Attempt=$i+1;AtUtc=$at;Outcome=$f.Status;Code=$f.Code;Error=$f.Message;ServerRetryAfterSeconds=$f.RetryAfter;WillRetry=$retry;DelaySeconds=$(if($retry){$delay}else{0})})
            if(-not $retry){return [pscustomobject]@{Success=$false;Value=$null;Attempts=$attempts.ToArray();Failure=$f}}
            # Never retry before a server-provided Retry-After. Long waits remain explicit partial failures.
            & $Sleep $delay
        }
    }
}

function New-BecThrottle {
    param([int]$Limit=90, [double]$PeriodSeconds=300,
          [scriptblock]$Now={ [DateTimeOffset]::UtcNow }, [scriptblock]$Sleep={param($s) Start-Sleep -Seconds $s})
    @{Times=[Collections.Generic.Queue[DateTimeOffset]]::new();Limit=$Limit;Period=$PeriodSeconds;Now=$Now;Sleep=$Sleep}
}

function Wait-BecThrottle {
    param([hashtable]$State)
    if($State.Limit -lt 1 -or $State.Period -le 0){throw 'Invalid throttle configuration'}
    for($guard=0;$guard -lt 1000;$guard++) {
        $now=& $State.Now
        while($State.Times.Count -and ($now-$State.Times.Peek()).TotalSeconds -ge $State.Period){[void]$State.Times.Dequeue()}
        if($State.Times.Count -lt $State.Limit){$State.Times.Enqueue($now);return}
        $delay=[Math]::Min(15,[Math]::Max(0.01,$State.Period-($now-$State.Times.Peek()).TotalSeconds+0.01))
        & $State.Sleep $delay
    }
    throw 'Throttle clock made no progress'
}

function Test-BecUpn {
    param([string]$Value)
    return $Value.Length -le 320 -and $Value -match '^[^\s<>";\\@]+@[^\s<>";\\@]+\.[^\s<>";\\@]+$' -and @($Value.ToCharArray() | Where-Object {[char]::IsControl($_)}).Count -eq 0
}

function Test-BecTargetAudit {
    param($Record,[string]$TargetUpn,[string[]]$TargetId)
    # Match named actor/target fields, not arbitrary subject text or a substring search.
    $a=$Record; $payload=Get-BecValue $Record 'AuditData'
    if($payload -is [string]){try{$a=ConvertFrom-Json -InputObject $payload -Depth 100 -ErrorAction Stop}catch{return $false}}
    elseif($payload -is [System.Collections.IDictionary] -or $payload -is [pscustomobject]){$a=$payload}
    $values=[Collections.Generic.List[string]]::new()
    foreach($k in @('UserId','UserPrincipalName','MailboxOwnerUPN','MailboxOwnerId','ObjectId','UserKey','userId','userPrincipalName')) {
        $v=Get-BecValue $a $k; if($v){$values.Add([string]$v)}
    }
    foreach($t in @(Get-BecList $a 'TargetResources' @())){foreach($k in @('id','userPrincipalName')){$v=Get-BecValue $t $k;if($v){$values.Add([string]$v)}}}
    foreach($actor in @('user','app')){$x=Get-BecValue (Get-BecValue $a 'initiatedBy') $actor;foreach($k in @('id','userPrincipalName')){$v=Get-BecValue $x $k;if($v){$values.Add([string]$v)}}}
    foreach($p in @(Get-BecList $a 'Parameters' @())) {
        if((Get-BecValue $p 'Name') -in @('Identity','Mailbox','User','UserPrincipalName','TargetUser','TargetMailbox')) {
            $v=Get-BecValue $p 'Value';if($v){$values.Add([string]$v)}
        }
    }
    foreach($v in $values){foreach($identity in @($TargetUpn)+@($TargetId)){
        if(-not $identity){continue}
        if($v -ieq $identity){return $true}
        # Rule/folder object identities may be mailbox-qualified. Require a whole identity boundary.
        if($v.StartsWith($identity+'\',[StringComparison]::OrdinalIgnoreCase) -or $v.StartsWith($identity+':\',[StringComparison]::OrdinalIgnoreCase)){return $true}
    }}
    return $false
}

function Get-BecMailboxIdentity {
    param([string]$Target,[object[]]$Collections)
    $addresses=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$addresses.Add($Target);[void]$ids.Add($Target)
    foreach($c in $Collections){if($c.Source -ne 'Exchange.Mailbox'){continue};foreach($m in $c.Items){
        foreach($k in @('PrimarySmtpAddress','UserPrincipalName','ExchangeGuid','Guid','DistinguishedName','Alias')){$v=[string](Get-BecValue $m $k '');if($v){[void]$ids.Add($v);if(Test-BecUpn $v){[void]$addresses.Add($v)}}}
        foreach($v in Get-BecList $m 'EmailAddresses') {if([string]$v -match '^(?i)smtp:(.+)$'){$mail=$Matches[1];if(Test-BecUpn $mail){[void]$addresses.Add($mail);[void]$ids.Add($mail)}}}
    }}
    [pscustomobject]@{Addresses=@($addresses | Sort-Object);Identifiers=@($ids | Sort-Object);Basis='Target plus identities/SMTP aliases from current mailbox snapshot; historical aliases may differ'}
}
