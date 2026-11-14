function ConvertTo-BecDisplay {
    param($Value)
    $text=if($null -eq $Value){''}elseif($Value -is [string]){$Value}else{ConvertTo-BecJson $Value}
    # Display only. Raw metadata remains unchanged in JSON evidence.
    return [regex]::Replace($text,'(?i)\bhttps?://[^\s<>"'']+', {param($m) ([regex]::Replace($m.Value,'(?i)^https?',{param($scheme) if($scheme.Value.Length -eq 5){'hxxps'}else{'hxxp'}})).Replace('.','[.]')})
}

function ConvertTo-BecHtml {
    param($Value)
    return [Net.WebUtility]::HtmlEncode((ConvertTo-BecDisplay $Value))
}

function ConvertTo-BecCsvValue {
    param($Value)
    $s=ConvertTo-BecDisplay $Value
    # Include Unicode spacing/control/format prefixes used to conceal spreadsheet formulas.
    if($s -match '^[\s\p{Cf}\p{Cc}]*[=+@-]' -or $s -match '^[\t\r\n]'){$s="'"+$s}
    return $s
}

function Export-BecCsv {
    param([object[]]$Rows,[string[]]$Columns,[string]$Path)
    $safe=@(foreach($r in $Rows){$o=[ordered]@{};foreach($k in $Columns){$o[$k]=ConvertTo-BecCsvValue (Get-BecValue $r $k)};[pscustomobject]$o})
    if($safe.Count){$safe | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8}
    else{[IO.File]::WriteAllText($Path, (($Columns | ForEach-Object {'"'+$_.Replace('"','""')+'"'}) -join ',')+"`n",[Text.UTF8Encoding]::new($false))}
}

function Get-BecHtmlTable {
    param([object[]]$Rows,[string[]]$Columns,[int]$Limit=5000)
    $b=[Text.StringBuilder]::new();[void]$b.Append('<div class="scroll" tabindex="0"><table><thead><tr>')
    foreach($k in $Columns){[void]$b.Append('<th scope="col">'+(ConvertTo-BecHtml $k)+'</th>')};[void]$b.Append('</tr></thead><tbody>')
    foreach($r in @($Rows | Select-Object -First $Limit)){[void]$b.Append('<tr>');foreach($k in $Columns){[void]$b.Append('<td>'+(ConvertTo-BecHtml (Get-BecValue $r $k))+'</td>')};[void]$b.Append('</tr>')}
    [void]$b.Append('</tbody></table></div><p>Showing '+[Math]::Min($Rows.Count,$Limit)+' of '+$Rows.Count+' records. Complete collected rows are in local CSV/JSON.</p>');$b.ToString()
}

function Write-BecCase {
    param([string]$OutputRoot,[string]$ProjectRoot,$Metadata,[object[]]$Collections,[object[]]$Timeline,$Correlations)
    $root=[IO.Path]::GetFullPath($OutputRoot);$project=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    if(-not ($root+[IO.Path]::DirectorySeparatorChar).StartsWith($project,[StringComparison]::Ordinal)){throw 'OutputRoot must stay inside this project directory'}
    # Refuse existing symlink components instead of following a path outside the local case boundary.
    $probe=$root
    while($probe){
        if((Test-Path -LiteralPath $probe) -and ((Get-Item -LiteralPath $probe -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Symlink/reparse output path is not allowed'}
        $probe=[IO.Path]::GetDirectoryName($probe)
    }
    $case=Join-Path $root ('case-'+[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [void][IO.Directory]::CreateDirectory((Join-Path $case 'raw'))
    foreach($c in $Collections){if($c.Source -notmatch '^[A-Za-z0-9.]+$'){throw 'Unsafe source name'};[IO.File]::WriteAllText((Join-Path $case ('raw/'+$c.Source+'.json')),(ConvertTo-BecJson $c))}
    $coverage=@($Collections | Select-Object Source,Kind,Provider,Status,Reason,Matched,Scanned,Retention,QueryCompleteness,StartedUtc,FinishedUtc,Notes)
    $volumes=@(foreach($direction in @('Trace.Sent','Trace.Received')){[pscustomobject]@{Direction=$direction;RecipientTraceRows=@($Timeline | Where-Object {$direction -cin $_.Sources}).Count}})
    $domains=@($Collections | Where-Object Source -eq 'Exchange.AcceptedDomains' | ForEach-Object {$_.Items} | ForEach-Object {[string](Get-BecValue $_ 'DomainName')} | Where-Object {$_})
    $domainBasis='Exchange accepted-domain snapshot';if(-not $domains.Count){$domains=@($Metadata.TargetUpn.Split('@')[-1]);$domainBasis='Target UPN domain only; heuristic, other tenant domains unknown'}
    $external=@($Timeline | Where-Object {$_.Source -in @('Trace.Sent','Trace.Received')} | ForEach-Object {if($_.Source -eq 'Trace.Sent'){$_.Target}else{$_.Actor}} | Where-Object {$_ -match '@' -and $_.Split('@')[-1] -notin $domains} | Group-Object | ForEach-Object {[pscustomobject]@{Correspondent=$_.Name;RecipientTraceRows=$_.Count}})
    $summary=[ordered]@{Metadata=$Metadata;Warning='Absent evidence is not a clean bill of health. Review coverage and raw records. No tenant remediation is performed.';Serialization='Raw source objects are reserialized as JSON; these are not original HTTP bytes. Wrappers add collection provenance without modifying source payloads.';Coverage=$coverage;TimelineRows=$Timeline.Count;Links=$Correlations.Items.Count;LinksPartial=$Correlations.Partial;Volumes=$volumes;ExternalCorrespondents=$external;ExternalDomainBasis=$domainBasis}
    foreach($pair in @(@('summary.json',$summary),@('timeline.json',$Timeline),@('correlations.json',$Correlations),@('coverage.json',$coverage))){[IO.File]::WriteAllText((Join-Path $case $pair[0]),(ConvertTo-BecJson $pair[1]))}
    $timelineColumns=@('EventId','TimeUtc','TimeQuality','Source','Sources','Kind','Actor','Target','Operation','Result','IP','Client','App','SessionId','InternetMessageIds','NetworkMessageId','TraceId','ReportId','Subject','Url','ReviewFlags','ObservedFacts','RawRefs')
    Export-BecCsv $Timeline $timelineColumns (Join-Path $case 'timeline.csv')
    Export-BecCsv $coverage @('Source','Kind','Status','Reason','Matched','Retention','QueryCompleteness') (Join-Path $case 'coverage.csv')
    Export-BecCsv $Correlations.Items @('From','To','Basis','Classification','Explanation') (Join-Path $case 'correlations.csv')
    Export-BecCsv $external @('Correspondent','RecipientTraceRows') (Join-Path $case 'correspondents.csv')
    $header='<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; base-uri ''none''; form-action ''none''"><title>M365 investigation</title><style>body{font:16px system-ui,sans-serif;color:#17212b;background:#f5f7fa;margin:2rem;line-height:1.5}h1,h2{color:#122d46}.notice{padding:1rem;background:#fff3ce;border:2px solid #806000}.scroll{overflow:auto;background:white;border:1px solid #bbc4ce}.scroll:focus{outline:3px solid #125fb5}table{border-collapse:collapse;min-width:100%}th,td{padding:.5rem;border:1px solid #ccd3da;text-align:left;vertical-align:top;overflow-wrap:anywhere;max-width:40rem}th{background:#dce7f0}a{color:#12548e}code{overflow-wrap:anywhere} @media(max-width:500px){body{margin:1rem}}</style></head><body>'
    $html='<!doctype html>'+$header+'<h1>Read-only M365 investigation</h1><p class="notice"><strong>'+(ConvertTo-BecHtml $Metadata.Mode)+'</strong> — '+(ConvertTo-BecHtml $Metadata.TargetUpn)+'<br>'+(ConvertTo-BecHtml $summary.Warning)+'</p><p>Requested UTC period: '+(ConvertTo-BecHtml $Metadata.StartUtc)+' to '+(ConvertTo-BecHtml $Metadata.EndUtc)+'. No live tenant testing is claimed by this build.</p><p>'+(ConvertTo-BecHtml $summary.Serialization)+'</p>'
    $html+='<h2>Coverage and limitations</h2>'+(Get-BecHtmlTable $coverage @('Source','Kind','Status','Matched','Reason','Retention','Notes'))
    $snapshots=@(foreach($c in $Collections){if($c.Kind -eq 'CurrentSnapshot'){foreach($item in $c.Items){[pscustomobject]@{Source=$c.Source;SnapshotUtc=$c.StartedUtc;Metadata=$item}}}})
    $html+='<h2>Current configuration snapshots</h2><p>Mailbox size, quotas, aliases, forwarding/retain-copy, SendOnBehalf, rules, delegates, protocols, mobile, audit and retention configuration are snapshots. They do not establish past state.</p>'+(Get-BecHtmlTable $snapshots @('Source','SnapshotUtc','Metadata'))
    $html+='<h2>Mail volume</h2><p>Counts describe collected, deduplicated recipient trace rows, not unique messages or exhaustive mail volume.</p>'+(Get-BecHtmlTable $volumes @('Direction','RecipientTraceRows'))+'<p>'+(ConvertTo-BecHtml $domainBasis)+'</p>'+(Get-BecHtmlTable $external @('Correspondent','RecipientTraceRows'))
    $html+='<h2>UTC timeline</h2><p>Current snapshots use collection time. Unknown timestamps sort last. Review flags are prompts for investigation, not verdicts.</p>'+(Get-BecHtmlTable $Timeline @('TimeUtc','TimeQuality','Source','Actor','Target','Operation','Result','Subject','Url','ReviewFlags','ObservedFacts','RawRefs'))
    $html+='<h2>Correlations</h2><p>Shared identifiers are observations. IP proximity is an inference; neither establishes causation. Link cap reached: '+(ConvertTo-BecHtml $Correlations.Partial)+'</p>'+(Get-BecHtmlTable $Correlations.Items @('From','To','Basis','Classification','Explanation'))
    $html+='<h2>Local evidence</h2><ul><li><a href="summary.json">Summary and provenance</a></li><li><a href="timeline.csv">Timeline CSV</a></li><li><a href="timeline.json">Timeline JSON</a></li><li><a href="manifest.json">SHA256 manifest</a></li>'
    foreach($c in $Collections){$html+='<li><a href="raw/'+$c.Source+'.json">'+(ConvertTo-BecHtml $c.Source)+' raw metadata</a></li>'};$html+='</ul><p>Displayed URLs are defanged and noninteractive. Raw JSON contains original returned metadata values; handle it as sensitive evidence.</p></body></html>'
    [IO.File]::WriteAllText((Join-Path $case 'report.html'),$html)
    $files=@(Get-ChildItem -LiteralPath $case -File -Recurse | Sort-Object FullName | ForEach-Object {[pscustomobject]@{Path=[IO.Path]::GetRelativePath($case,$_.FullName).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    $manifest=[ordered]@{Version=1;CreatedUtc=[DateTimeOffset]::UtcNow.ToString('o');Algorithm='SHA256';Meaning='Hashes detect later byte changes; they do not independently authenticate source truth or collection time.';Files=$files}
    [IO.File]::WriteAllText((Join-Path $case 'manifest.json'),(ConvertTo-BecJson $manifest))
    [IO.File]::WriteAllText((Join-Path $case 'manifest.sha256'),(Get-FileHash -LiteralPath (Join-Path $case 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()+"  manifest.json`n")
    return $case
}

function Test-BecManifest {
    param([string]$CasePath)
    $root=[IO.Path]::GetFullPath($CasePath);$m=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json -Depth 100
    $fail=[Collections.Generic.List[string]]::new()
    $expected=(Get-Content -LiteralPath (Join-Path $root 'manifest.sha256') -Raw).Split(' ')[0]
    if((Get-FileHash -LiteralPath (Join-Path $root 'manifest.json') -Algorithm SHA256).Hash -ine $expected){$fail.Add('manifest.json')}
    foreach($f in $m.Files){
        if($f.Path -match '(^/|\\|(^|/)\.\.(/|$)|:)' -or [IO.Path]::IsPathRooted($f.Path)){$fail.Add('Unsafe manifest path');continue}
        $p=Join-Path $root $f.Path
        $component=$p;$unsafe=$false
        while($component -and $component.Length -ge $root.Length){
            if((Test-Path -LiteralPath $component) -and ((Get-Item -LiteralPath $component -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){$unsafe=$true;break}
            $component=[IO.Path]::GetDirectoryName($component)
        }
        if($unsafe){$fail.Add('Symlink component: '+$f.Path);continue}
        if(-not (Test-Path -LiteralPath $p -PathType Leaf)){$fail.Add($f.Path);continue}
        if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){$fail.Add('Symlink: '+$f.Path);continue}
        if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ine $f.Sha256 -or (Get-Item -LiteralPath $p).Length -ne $f.Bytes){$fail.Add($f.Path)}
    }
    [pscustomobject]@{Passed=($fail.Count -eq 0);Files=$m.Files.Count;Failures=$fail.ToArray()}
}
