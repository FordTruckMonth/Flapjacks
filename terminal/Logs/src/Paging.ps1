function Invoke-BecPagedQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Query,[ValidateRange(1,1000)][int]$MaxPages=20,[ValidateRange(1,1000000)][int]$MaxItems=100000)
    $items=[Collections.Generic.List[object]]::new();$pages=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $fingerprints=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $token=$null;$status='Partial';$reason='max-pages';$overflow=@()
    for($page=1;$page -le $MaxPages;$page++){
        $inputToken=$token;$next=$null;$count=0;$outcome='Error';$errorText=$null;$failure=$null;$meta=$null;$start=[DateTimeOffset]::UtcNow.ToString('o')
        try {
            $result=& $Query $inputToken
            $valid=($result -is [hashtable] -or $result -is [pscustomobject])
            foreach($key in @('Items','NextToken','IsComplete')){
                if($result -is [hashtable]){$valid=$valid -and $result.ContainsKey($key)}
                elseif($result -is [pscustomobject]){$valid=$valid -and $null -ne $result.PSObject.Properties[$key]}
            }
            if(-not $valid){$reason='invalid-response';break}
            $raw=Get-BecValue $result 'Items';$next=Get-BecValue $result 'NextToken';$complete=Get-BecValue $result 'IsComplete';$meta=Get-BecValue $result 'Provenance'
            # A string such as "false" is truthy in PowerShell; completion must be a real Boolean.
            if($raw -isnot [array] -or $complete -isnot [bool] -or ($null -ne $next -and ($next -isnot [string] -or $next.Length -eq 0))){$reason='invalid-response';break}
            $count=$raw.Count
            # Preserve the already fetched page separately. A processing cap must not silently discard evidence.
            if($items.Count+$count -gt $MaxItems){$overflow=$raw;$reason='max-items';$outcome='ItemCap';break}
            foreach($item in $raw){$items.Add($item)}
            $outcome='Success'
            if($complete -and $null -ne $next){$reason='invalid-complete-with-token';$outcome='Invalid';break}
            if($complete){$status='Complete';$reason=$null;break}
            if($null -eq $next){$reason='ambiguous-incomplete';break}
            if(-not $seen.Add($next)){$reason='repeated-token';break}
            if($raw.Count){$fp=Get-BecHash (ConvertTo-BecJson $raw);if(-not $fingerprints.Add($fp)){$reason='repeated-page';break}}
            $token=$next
            if($page -eq $MaxPages){$reason='max-pages'}
        } catch {$reason='query-error';$errorText=$_.Exception.Message;$failure=Get-BecFailureClass $_;$outcome='Error'}
        finally {
            # finally also runs for terminal success and break: one record for every attempted callback.
            $pages.Add([pscustomobject]@{Page=$page;InputToken=$inputToken;OutputToken=$next;Count=$count;Outcome=$outcome;Error=$errorText;Failure=$failure;StartedUtc=$start;FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o');Provenance=$meta})
        }
        if($outcome -eq 'Error'){break}
    }
    [pscustomobject]@{Items=$items.ToArray();OverflowItems=$overflow;Pages=$pages.ToArray();Status=$status;Reason=$reason}
}
