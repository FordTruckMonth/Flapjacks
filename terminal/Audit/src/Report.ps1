function ConvertTo-AuditCsvValue($Value) {
    $s=if ($null -eq $Value) { '' } elseif ($Value -is [string] -or $Value -is [ValueType]) { [string]$Value } else { ConvertTo-Json -InputObject $Value -Depth 100 -Compress }
    if ($s -match '^[\s\p{Cf}]*[=+@\-]' -or $s -match '^[\t\r\n]') { return "'"+$s }
    return $s
}
function Write-AuditJson([string]$Path,$Value) {
    $json=ConvertTo-Json -InputObject $Value -Depth 100 -WarningAction Stop
    [IO.File]::WriteAllText($Path,$json,[Text.UTF8Encoding]::new($false))
}
function Write-AuditCsv([string]$Path,$Rows,[string[]]$Columns) {
    $safe=@(foreach ($row in $Rows) {
        $copy=[ordered]@{}; foreach ($col in $Columns) { $copy[$col]=ConvertTo-AuditCsvValue (Get-AuditProperty $row $col) }; [pscustomobject]$copy
    })
    if ($safe.Count -eq 0) { [IO.File]::WriteAllText($Path,('"'+($Columns -join '","')+'"'+[Environment]::NewLine),[Text.UTF8Encoding]::new($true)) }
    else { $safe | Export-Csv -LiteralPath $Path -Encoding utf8BOM }
}
function Export-AuditReport {
    param([string]$Path,$Metadata,$Results,$Observations,$Catalog,$Plan)
    $evidence=Join-Path $Path 'evidence'; [void][IO.Directory]::CreateDirectory($evidence)
    Write-AuditJson (Join-Path $Path 'audit.json') ([ordered]@{Metadata=$Metadata;Coverage=$Results;Observations=@($Observations)})
    Write-AuditJson (Join-Path $Path 'collection-plan.json') $Plan
    $coverage=@($Results | Select-Object SourceId,Group,Provider,Target,Status,Reason,CollectedAtUtc,PageCount,RequestCount,Count,MissingFields,Notes)
    Write-AuditCsv (Join-Path $Path 'coverage.csv') $coverage @('SourceId','Group','Provider','Status','Count','Reason','PageCount','RequestCount','MissingFields','CollectedAtUtc','Target','Notes')
    Write-AuditCsv (Join-Path $Path 'observations.csv') $Observations @('SourceId','ObjectId','Rule','Severity','Title','Detail')
    $inventory=[System.Collections.Generic.List[object]]::new()
    foreach ($r in $Results) {
        if ($r.Status -ne 'NotSelected') { Write-AuditJson (Join-Path $evidence ($r.SourceId+'.json')) $r }
        foreach ($item in $r.Items) {
            $id=Get-AuditProperty $item 'id' (Get-AuditProperty $item 'Identity' '')
            $name=Get-AuditProperty $item 'displayName' (Get-AuditProperty $item 'Name' $id)
            $state=Get-AuditProperty $item 'state' (Get-AuditProperty $item 'State' '')
            $inventory.Add([pscustomobject]@{SourceId=$r.SourceId;ObjectId=$id;Name=$name;State=$state;SourceStatus=$r.Status;Configuration=$item})
        }
    }
    Write-AuditCsv (Join-Path $Path 'inventory.csv') $inventory.ToArray() @('SourceId','ObjectId','Name','State','SourceStatus','Configuration')
    $files=@(Get-ChildItem -LiteralPath $Path -File -Recurse | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{Path=[IO.Path]::GetRelativePath($Path,$_.FullName).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    Write-AuditJson (Join-Path $Path 'manifest.json') ([ordered]@{SchemaVersion='1.0';GeneratedAtUtc=[DateTime]::UtcNow.ToString('o');Algorithm='SHA256';Files=$files})
}
function Test-M365AuditManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $root=[IO.Path]::GetFullPath($Path)
    $rootItem=Get-Item -LiteralPath $root
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Report root cannot be a link.' }
    $manifestFile=Get-Item -LiteralPath (Join-Path $root 'manifest.json')
    if ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Manifest cannot be a link.' }
    $manifest=Get-Content -LiteralPath $manifestFile.FullName -Raw | ConvertFrom-Json -Depth 20
    if ($manifest.SchemaVersion -ne '1.0' -or $manifest.Algorithm -ne 'SHA256') { throw 'Unsupported manifest format.' }
    $problems=[System.Collections.Generic.List[string]]::new(); $known=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($file in $manifest.Files) {
        $relative=[string]$file.Path
        if (-not $relative -or $relative -match '(^/|\\|(^|/)\.\.(/|$)|:)' -or $relative -eq 'manifest.json' -or -not $known.Add($relative)) { $problems.Add('Invalid or duplicate manifest path.'); continue }
        $full=[IO.Path]::GetFullPath((Join-Path $root $relative))
        if (-not $full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal)) { $problems.Add('Manifest path escaped report directory.'); continue }
        $linked=$false; $parent=[IO.Path]::GetDirectoryName($full)
        while ($parent -and $parent -cne $root) {
            $parentItem=Get-Item -LiteralPath $parent -ErrorAction SilentlyContinue
            if ($null -ne $parentItem -and ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $linked=$true; break }
            $parent=[IO.Path]::GetDirectoryName($parent)
        }
        if ($linked) { $problems.Add('Manifest path passes through a link.'); continue }
        $target=Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
        if ($null -eq $target -or $target.PSIsContainer -or ($target.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $problems.Add("Missing or non-regular file: $relative"); continue }
        if ($target.Length -ne $file.Bytes -or (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ine $file.Sha256) { $problems.Add("Hash or length mismatch: $relative") }
    }
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse) {
        $relative=[IO.Path]::GetRelativePath($root,$file.FullName).Replace('\','/')
        if ($relative -ne 'manifest.json' -and -not $known.Contains($relative)) { $problems.Add("Unlisted file: $relative") }
    }
    [pscustomobject]@{Valid=($problems.Count -eq 0);CheckedFiles=$known.Count;Problems=$problems.ToArray()}
}
