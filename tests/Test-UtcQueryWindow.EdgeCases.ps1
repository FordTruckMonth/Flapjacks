#requires -Version 7.4
. (Join-Path $PSScriptRoot '..' 'Get-UtcQueryWindow.ps1')
function Assert-Equal($actual, $expected, $message) { if ($actual -ne $expected) { throw "${message}: expected $expected, got $actual" } }
function Assert-True($actual, $message) { if (-not $actual) { throw $message } }
$start = [DateTimeOffset]::new(2026, 11, 1, 5, 30, 0, [TimeSpan]::FromHours(5).Add([TimeSpan]::FromMinutes(30)))
$end = [DateTimeOffset]::new(2026, 11, 2, 5, 30, 0, [TimeSpan]::FromHours(5).Add([TimeSpan]::FromMinutes(30)))
$w = @(Get-UtcQueryWindow -Start $start -End $end -MaxWindowDays 10)
Assert-Equal $w.Count 1 'tz count'
Assert-Equal $w[0].StartUtc.Offset.TotalSeconds 0 'tz start offset'
Assert-Equal $w[0].EndUtc.Offset.TotalSeconds 0 'tz end offset'
Assert-Equal $w[0].StartUtc.UtcDateTime ([DateTime]::new(2026, 11, 1, 0, 0, 0, [DateTimeKind]::Utc) -as [DateTimeOffset]).UtcDateTime 'tz start utc'
Assert-Equal $w[0].EndUtc.UtcDateTime ([DateTime]::new(2026, 11, 2, 0, 0, 0, [DateTimeKind]::Utc) -as [DateTimeOffset]).UtcDateTime 'tz end utc'
function Assert-Throws($script, $message) {
  $threw = $false
  try { & $script } catch { $threw = $true }
  Assert-True $threw $message
}
$base = [DateTimeOffset]::new(2026, 11, 1, 0, 0, 0, [TimeSpan]::Zero)
Assert-Throws { Get-UtcQueryWindow -Start $base -End $base -MaxWindowDays 10 } 'reject end=start'
Assert-Throws { Get-UtcQueryWindow -Start $base -End $base.AddDays(-1) -MaxWindowDays 10 } 'reject end<start'
Assert-Throws { Get-UtcQueryWindow -Start $base -End $base.AddDays(1) -MaxWindowDays 0 } 'reject max=0'
Assert-Throws { Get-UtcQueryWindow -Start $base -End $base.AddDays(1) -MaxWindowDays 11 } 'reject max=11'
Assert-Throws { Get-UtcQueryWindow -Start $base -End $base.AddDays(1) -MaxWindowDays ([double]::NaN) } 'reject max=NaN'
Write-Output 'edge cases passed'
