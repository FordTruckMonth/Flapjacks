function Get-ToolkitValue($Object,[string]$Name,$Default=$null){
    if($null -eq $Object){return $Default}
    if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
    if($Object.PSObject.Properties[$Name]){return $Object.$Name};return $Default
}
function ConvertTo-ToolkitText {
    param($Value,[int]$Limit=600)
    $text=[string]$Value
    # Never allow evidence values to execute terminal control/OSC sequences or forge lines.
    $text=[regex]::Replace($text,'[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]',{param($m)'\u'+([int][char]$m.Value[0]).ToString('x4')})
    $text=[regex]::Replace($text,'(?i)\bhttps?://', {param($m)if($m.Value.Length -eq 8){'hxxps://'}else{'hxxp://'}})
    if($text.Length -gt $Limit){$text=$text.Substring(0,$Limit)+' [truncated; see optional JSON]'}
    return $text
}
function Write-ToolkitText {param([hashtable]$Runtime,[string]$Text);& $Runtime.Write (ConvertTo-ToolkitText $Text 14000)}
function Read-ToolkitInput {param([hashtable]$Runtime,[string]$Prompt);return [string](& $Runtime.Read $Prompt)}
function Test-ToolkitAddress {
    param([string]$Address)
    return $Address.Length -le 254 -and $Address -cmatch '^[A-Za-z0-9.!#$%&+_={}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$' -and $Address -notmatch '\.\.|[;*?\[\]\\\s]'
}
function ConvertTo-ToolkitTargets {
    param([string]$Text,[string]$UsernameDomain='')
    $tokens=@($Text -split '[,;\r\n]+' | ForEach-Object {$_.Trim()} | Where-Object {$_})
    if($tokens.Count -lt 1 -or $tokens.Count -gt 50){throw 'Provide 1-50 exact usernames or email addresses; no lists, groups or wildcards.'}
    if($UsernameDomain -and -not (Test-ToolkitAddress ('check@'+$UsernameDomain))){throw 'Invalid explicitly supplied username domain.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $result=[Collections.Generic.List[string]]::new()
    foreach($token in $tokens){
        if(-not $token.Contains('@')){
            if(-not $UsernameDomain -or $token -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'){throw 'A bare username requires an explicit UPN suffix; display names and wildcards are not accepted.'}
            $token+='@'+$UsernameDomain
        }
        if(-not (Test-ToolkitAddress $token)){throw 'Invalid exact username/email input. No query was issued.'}
        if($seen.Add($token)){$result.Add($token)}
    }
    return ,$result.ToArray()
}
function ConvertTo-ToolkitWindow {
    param([string]$StartText,[string]$EndText,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
    foreach($text in @($StartText,$EndText)){if($text -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$'){throw 'Use ISO timestamps with explicit timezone, for example 2026-11-01T00:00:00Z.'}}
    $start=[DateTimeOffset]::Parse($StartText,[Globalization.CultureInfo]::InvariantCulture)
    $end=[DateTimeOffset]::Parse($EndText,[Globalization.CultureInfo]::InvariantCulture)
    if($end -le $start -or ($end-$start).TotalDays -gt 90 -or $end -gt $Now){throw 'Require a positive interval of at most 90 days, not ending in the future.'}
    return @{Start=$start.ToUniversalTime();End=$end.ToUniversalTime()}
}
function Write-ToolkitLogsSummary {
    param($Result,[hashtable]$Runtime)
    Write-ToolkitText $Runtime ('MAILBOX: '+(ConvertTo-ToolkitText $Result.Metadata.TargetUpn))
    Write-ToolkitText $Runtime 'Read-only target metadata and triage prompts, not proof of compromise or a clean bill of health.'
    foreach($row in $Result.Coverage){Write-ToolkitText $Runtime ((ConvertTo-ToolkitText $row.Source)+' | '+(ConvertTo-ToolkitText $row.Status)+' | '+(ConvertTo-ToolkitText $row.Reason))}
    $events=@($Result.Timeline)
    Write-ToolkitText $Runtime ('Timeline records: '+$events.Count+'. Showing first 50 UTC records; optional JSON/CSV retains complete collected metadata.')
    foreach($event in @($events | Select-Object -First 50)){
        Write-ToolkitText $Runtime ((ConvertTo-ToolkitText $event.TimeUtc)+' | '+(ConvertTo-ToolkitText $event.Source)+' | '+(ConvertTo-ToolkitText $event.Operation)+' | '+(ConvertTo-ToolkitText $event.Result)+' | '+(ConvertTo-ToolkitText ($event.ReviewFlags -join ', ')))
        if($event.Subject){Write-ToolkitText $Runtime ('  Subject: '+(ConvertTo-ToolkitText $event.Subject 240))}
    }
    Write-ToolkitText $Runtime ('Correlation observations: '+@($Result.Correlations.Items).Count+'. Shared identifiers are observations; IP proximity is inference, not causation.')
    $path=Get-ToolkitValue $Result 'CasePath'
    if($path){Write-ToolkitText $Runtime ('Local JSON/CSV evidence: '+$path)}else{Write-ToolkitText $Runtime 'No evidence files saved.'}
}
function Show-ToolkitResult {
    param($Results,[hashtable]$Runtime)
    $items=@(foreach($result in @($Results)){if($result -is [array]){foreach($r in $result){$r}}else{$result}})
    if(-not $items.Count){Write-ToolkitText $Runtime 'No in-memory result to inspect.';return}
    for($i=0;$i -lt $items.Count;$i++){
        $meta=Get-ToolkitValue $items[$i] 'Metadata'
        $label=Get-ToolkitValue $meta 'TargetUpn' 'Organization audit'
        if(Get-ToolkitValue $items[$i] 'Failed' $false){$label='Failed mailbox '+(Get-ToolkitValue $items[$i] 'Target')}
        Write-ToolkitText $Runtime (($i+1).ToString()+': '+(ConvertTo-ToolkitText $label))
    }
    $indexText=Read-ToolkitInput $Runtime 'Result number to inspect, or ENTER to return'
    if(-not $indexText){return};$index=0
    if(-not [int]::TryParse($indexText,[ref]$index) -or $index -lt 1 -or $index -gt $items.Count){Write-ToolkitText $Runtime 'Invalid result number.';return}
    $selected=$items[$index-1]
    if(Get-ToolkitValue $selected 'Failed' $false){Write-ToolkitText $Runtime (ConvertTo-ToolkitText $selected.Reason);return}
    $sources=@(Get-ToolkitValue $selected 'Collections' @())
    if(-not $sources.Count){$sources=@(Get-ToolkitValue $selected 'Evidence' @())}
    foreach($source in $sources){$id=Get-ToolkitValue $source 'Source' (Get-ToolkitValue $source 'SourceId');Write-ToolkitText $Runtime ((ConvertTo-ToolkitText $id)+' | '+(ConvertTo-ToolkitText $source.Status)+' | '+@($source.Items).Count+' records')}
    Write-ToolkitText $Runtime 'Enter an exact source ID and optional page number. Each page displays 25 records. Also: @coverage, @observations, @timeline, @correlations. ENTER returns. Values are escaped/defanged and long records truncated; optional evidence retains originals.'
    while($true){
        $choice=Read-ToolkitInput $Runtime 'Source [page]'
        if(-not $choice){return}
        $parts=$choice.Trim() -split '\s+';$id=$parts[0];$page=1
        if($parts.Count -gt 2 -or ($parts.Count -eq 2 -and (-not [int]::TryParse($parts[1],[ref]$page) -or $page -lt 1 -or $page -gt 1000000))){Write-ToolkitText $Runtime 'Invalid page.';continue}
        $rows=@()
        switch($id){
            '@coverage' {$rows=@(Get-ToolkitValue $selected 'Coverage' @())}
            '@observations' {$rows=@(Get-ToolkitValue $selected 'Observations' @())}
            '@timeline' {$rows=@(Get-ToolkitValue $selected 'Timeline' @())}
            '@correlations' {$rows=@(Get-ToolkitValue (Get-ToolkitValue $selected 'Correlations') 'Items' @())}
            default {$source=@($sources | Where-Object {(Get-ToolkitValue $_ 'Source' (Get-ToolkitValue $_ 'SourceId')) -ceq $id});if($source.Count -ne 1){Write-ToolkitText $Runtime 'Source ID not found.';continue};$rows=@($source[0].Items)}
        }
        Write-ToolkitText $Runtime ('Page '+$page+' | '+$rows.Count+' records total')
        foreach($row in @($rows | Select-Object -Skip (($page-1)*25) -First 25)){Write-ToolkitText $Runtime (ConvertTo-ToolkitText (ConvertTo-Json -InputObject $row -Depth 100 -Compress) 12000)}
    }
}
