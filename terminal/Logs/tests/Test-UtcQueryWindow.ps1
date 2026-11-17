#requires -Version 7.4
. (Join-Path $PSScriptRoot '..' 'Get-UtcQueryWindow.ps1')
function Assert-Equal($actual, $expected, $message) { if ($actual -ne $expected) { throw "${message}: expected $expected, got $actual" } }
$start = [DateTimeOffset]::new(2026, 11, 1, 0, 0, 0, [TimeSpan]::Zero)
$end = $start.AddDays(10)
$w = @(Get-UtcQueryWindow -Start $start -End $end -MaxWindowDays 10)
Assert-Equal $w.Count 1 'case1 count'
Assert-Equal $w[0].StartUtc $start.ToUniversalTime() 'case1 start'
Assert-Equal $w[0].EndUtc $end.ToUniversalTime() 'case1 end'
$start2 = [DateTimeOffset]::MaxValue.AddDays(-1)
$end2 = [DateTimeOffset]::MaxValue
$w2 = @(Get-UtcQueryWindow -Start $start2 -End $end2 -MaxWindowDays 10)
Assert-Equal $w2.Count 1 'case2 count'
Assert-Equal $w2[0].StartUtc $start2.ToUniversalTime() 'case2 start'
Assert-Equal $w2[0].EndUtc $end2.ToUniversalTime() 'case2 end'
$start3 = [DateTimeOffset]::new(2026, 11, 1, 0, 0, 0, [TimeSpan]::Zero)
$end3 = $start3.AddDays(23)
$w3 = @(Get-UtcQueryWindow -Start $start3 -End $end3 -MaxWindowDays 10)
Assert-Equal $w3.Count 3 'case3 count'
Assert-Equal $w3[2].EndUtc $end3.ToUniversalTime() 'case3 last end'
Assert-Equal ($w3[2].EndUtc - $w3[2].StartUtc).TotalDays 3 'case3 final duration'
Assert-Equal $w3[1].EndUtc $w3[2].StartUtc 'case3 contiguity 1-2'
Assert-Equal $w3[0].EndUtc $w3[1].StartUtc 'case3 contiguity 0-1'
Write-Output '3 cases passed'
