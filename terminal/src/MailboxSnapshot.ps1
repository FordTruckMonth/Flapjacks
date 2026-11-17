# Optional, local-only serialization. Does not authenticate or make provider calls.
function ConvertTo-ToolkitMailboxSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)][guid]$TenantId)
    if($TenantId -eq [guid]::Empty){throw 'A verified, nonempty tenant GUID is required.'}
    $metadata=Get-ToolkitValue $Result 'Metadata'
    $target=[string](Get-ToolkitValue $metadata 'TargetUpn' '')
    if(-not (Test-ToolkitAddress $target)){throw 'An exact mailbox UPN is required.'}
    $mode=[string](Get-ToolkitValue $Result 'Mode' '')
    if($mode -notin @('Fixture','Live')){throw 'Explicit Fixture or Live provenance is required.'}
    $finished=Get-ToolkitValue $metadata 'CollectionFinishedUtc' ''
    if($finished -is [DateTimeOffset]){$finished=$finished.ToString('o')}
    elseif($finished -is [DateTime]){if($finished.Kind -eq [DateTimeKind]::Unspecified){throw 'Timestamp timezone is unknown.'};$finished=$finished.ToString('o')}
    $at=[DateTimeOffset]::MinValue
    if($finished -notmatch '^\d{4}-\d{2}-\d{2}T.*(Z|[+-]\d{2}:\d{2})$' -or -not [DateTimeOffset]::TryParse($finished,[ref]$at)){throw 'Collection completion timestamp with timezone is required.'}
    $sources=@{}
    foreach($name in @('Exchange.Rules','Exchange.Mailbox','Exchange.FullAccess','Exchange.SendAs')){
        $found=@((Get-ToolkitValue $Result 'Collections' @()) | Where-Object {(Get-ToolkitValue $_ 'Source') -ceq $name})
        if($found.Count -gt 1){throw "Duplicate source refused: $name"}
        $status='unavailable';$records=@()
        if($found.Count -eq 1){
            $c=$found[0]
            if((Get-ToolkitValue $c 'Kind') -cne 'CurrentSnapshot'){throw "Historical data cannot be exported as current: $name"}
            $raw=([string](Get-ToolkitValue $c 'Status' '')).ToLowerInvariant()
            if($raw -in @('collected','partial','denied','unavailable')){$status=$raw}
            if($status -in @('collected','partial')){$records=@(Get-ToolkitValue $c 'Items' @())}
        }
        $sources[$name]=[ordered]@{status=$status;records=$records}
    }
    $mail=$sources['Exchange.Mailbox']
    foreach($record in $mail.records){
        $canonical=[string](Get-ToolkitValue $record 'UserPrincipalName' '')
        if(-not (Test-ToolkitAddress $canonical) -or $canonical -ine $target){throw 'Canonical mailbox UPN must match the result target; aliases/mismatched mailbox records refused.'}
    }
    # Missing fields are unknown, not evidence that forwarding/delegation is disabled.
    $forward=[ordered]@{status=$mail.status;records=@($mail.records)}
    $behalfStatus=$mail.status
    if($mail.status -in @('collected','partial')){
        if($mail.records.Count -ne 1){$forward.status='partial';$behalfStatus='partial'}
        foreach($record in $mail.records){
            foreach($field in @('ForwardingAddress','ForwardingSmtpAddress','DeliverToMailboxAndForward')){
                if(($record -is [Collections.IDictionary] -and -not $record.Contains($field)) -or ($record -isnot [Collections.IDictionary] -and $null -eq $record.PSObject.Properties[$field])){$forward.status='partial'}
            }
            if(($record -is [Collections.IDictionary] -and -not $record.Contains('GrantSendOnBehalfTo')) -or ($record -isnot [Collections.IDictionary] -and $null -eq $record.PSObject.Properties['GrantSendOnBehalfTo'])){$behalfStatus='partial'}
        }
    }
    $delegates=[Collections.Generic.List[object]]::new()
    foreach($name in @('Exchange.FullAccess','Exchange.SendAs')){
        foreach($record in $sources[$name].records){$delegates.Add([ordered]@{source=$name;record=$record})}
    }
    foreach($record in $mail.records){$delegates.Add([ordered]@{source='Exchange.Mailbox.SendOnBehalf';record=$record})}
    $statuses=@($sources['Exchange.FullAccess'].status,$sources['Exchange.SendAs'].status,$behalfStatus)
    $delegateStatus=if(@($statuses|Where-Object {$_ -ne 'collected'}).Count -eq 0){'collected'}elseif(@($statuses|Where-Object {$_ -in @('collected','partial')}).Count){'partial'}elseif(@($statuses|Where-Object {$_ -ne 'denied'}).Count -eq 0){'denied'}else{'unavailable'}
    [pscustomobject][ordered]@{
        schema='response-menu.mailbox-snapshot.v1';tenant_id=$TenantId.ToString();mailbox_upn=$target.ToLowerInvariant()
        acquired_at=$at.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ');synthetic=($mode -eq 'Fixture')
        evidence_class='reserialized-source-objects'
        sources=[ordered]@{inbox_rules=$sources['Exchange.Rules'];forwarding=$forward;delegates=[ordered]@{status=$delegateStatus;records=$delegates.ToArray()}}
    }
}
function Export-ToolkitMailboxSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][string]$Path)
    $snapshot=ConvertTo-ToolkitMailboxSnapshot $Result $TenantId
    $json=ConvertTo-Json -InputObject $snapshot -Depth 100 -WarningAction Stop
    $full=[IO.Path]::GetFullPath($Path);$parent=[IO.Path]::GetDirectoryName($full)
    if(-not [IO.Directory]::Exists($parent)){throw 'Choose an existing private local directory.'}
    for($p=$parent;$p;$p=[IO.Path]::GetDirectoryName($p)){
        if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Symlink/reparse export directory refused.'}
    }
    # CreateNew refuses an existing file (including symlinks), never silently overwrites evidence.
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
    $full
}
function Invoke-ToolkitCurrentMailboxSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Runtime,[Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][string]$Account,[Parameter(Mandatory)][string]$Target)
    if(-not (Test-ToolkitAddress $Target)){throw 'One exact UPN required; no aliases, groups or wildcards.'}
    Import-Module (Join-Path $script:ToolkitRoot 'Logs/M365Bec.psm1') -DisableNameChecking
    $transport=New-ToolkitMailboxTransport $Runtime $TenantId $Account $Target
    $context=New-BecContext -Transport $transport
    $started=[DateTimeOffset]::UtcNow.ToString('o')
    $mail=Invoke-BecSnapshot 'Exchange.Mailbox' 'Get-Mailbox' @{Identity=$Target} $context
    # Require canonical UPN here, stricter than the legacy alias-tolerant collector.
    if($mail.Status -ne 'Collected' -or $mail.Items.Count -ne 1 -or ([string](Get-ToolkitValue $mail.Items[0] 'UserPrincipalName')) -ine $Target){throw 'Exact UPN mailbox resolution failed; no further mailbox reads.'}
    $collections=[Collections.Generic.List[object]]::new();$collections.Add($mail)
    $rules=Invoke-BecSnapshot 'Exchange.Rules' 'Get-InboxRule' @{Mailbox=$Target;IncludeHidden=$true;ResultSize=1000} $context
    if($rules.Items.Count -ge 1000 -and $rules.Status -eq 'Collected'){$rules.Status='Partial';$rules.Reason='Rule result cap reached; completeness unknown.'}
    $collections.Add($rules)
    $collections.Add((Invoke-BecSnapshot 'Exchange.FullAccess' 'Get-MailboxPermission' @{Identity=$Target} $context))
    $collections.Add((Invoke-BecSnapshot 'Exchange.SendAs' 'Get-RecipientPermission' @{Identity=$Target} $context))
    [pscustomobject]@{Mode='Live';Metadata=[pscustomobject]@{TargetUpn=$Target;CollectionStartedUtc=$started;CollectionFinishedUtc=[DateTimeOffset]::UtcNow.ToString('o')};Collections=$collections.ToArray()}
}
