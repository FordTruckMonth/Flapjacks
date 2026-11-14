param([string]$PagerPath)
$ErrorActionPreference = 'Stop'
. $PagerPath
function Page($id, $next, $complete, [switch]$Hash, [switch]$Empty) {
  $h = @{ Items = @(); NextToken=$next; IsComplete=$complete }
  if (-not $Empty) { $h.Items = @([pscustomobject]@{ Id=$id; Raw='<synthetic>'; Value=7 }) }
  # An empty collection must remain an array, not PowerShell's empty pipeline/null.
  if ($Empty) { $h.Items = @() }
  if ($Hash) { return $h }; [pscustomobject]$h
}
function Step($value) { @{Kind='page';Value=$value} }
$cases = [System.Collections.Generic.List[object]]::new()
function Add-Case($name,$steps,$status,$reason,$ids,$calls,$pages,$max=3) {
  $state=@{Steps=@($steps);Calls=0;Tokens=[System.Collections.Generic.List[object]]::new()}
  $query={param($token)
    $state.Calls++;$state.Tokens.Add($token)
    if ($state.Calls -gt $state.Steps.Count) { throw 'synthetic unexpected extra query' }
    $step=$state.Steps[$state.Calls-1]
    if ($step.Kind -eq 'error') { throw 'synthetic query error' }
    return $step.Value
  }.GetNewClosure()
  $cases.Add([pscustomobject]@{Name=$name;Query=$query;State=$state;Max=$max;Expected=[pscustomobject]@{Status=$status;Reason=$reason;Ids=@($ids);Calls=$calls;Pages=$pages}})
}
Add-Case 'pscustom-complete' @((Step (Page 'p1' $null $true))) 'Complete' 'none' @('p1') 1 1
Add-Case 'hashtable-complete' @((Step (Page 'h1' $null $true -Hash))) 'Complete' 'none' @('h1') 1 1
Add-Case 'string-false-invalid' @((Step (Page 's1' $null 'false'))) 'Partial' 'invalid' @() 1 1
Add-Case 'string-true-invalid' @((Step (Page 's2' $null 'true'))) 'Partial' 'invalid' @() 1 1
$p=Page 'scalar' $null $true;$p.Items='scalar';Add-Case 'scalar-items-invalid' @((Step $p)) 'Partial' 'invalid' @() 1 1
$p=Page 'null' $null $true;$p.Items=$null;Add-Case 'null-items-invalid' @((Step $p)) 'Partial' 'invalid' @() 1 1
Add-Case 'empty-token-invalid' @((Step (Page 'e1' '' $false))) 'Partial' 'invalid' @() 1 1
Add-Case 'numeric-token-invalid' @((Step (Page 'n1' 12 $false))) 'Partial' 'invalid' @() 1 1
Add-Case 'missing-field-invalid' @((Step ([pscustomobject]@{Items=@();IsComplete=$true}))) 'Partial' 'invalid' @() 1 1
Add-Case 'terminal-empty' @((Step (Page '' $null $true -Empty))) 'Complete' 'none' @() 1 1
Add-Case 'query-error-provenance' @(@{Kind='error'}) 'Partial' 'query-error' @() 1 1
Add-Case 'repeated-exact-token' @((Step (Page 'r1' 'A' $false)),(Step (Page 'r2' 'A' $false))) 'Partial' 'no-progress' @('r1','r2') 2 2
Add-Case 'case-sensitive-token-progress' @((Step (Page 'c1' 'A' $false)),(Step (Page 'c2' 'a' $false)),(Step (Page 'c3' $null $true))) 'Complete' 'none' @('c1','c2','c3') 3 3
Add-Case 'explicit-page-cap' @((Step (Page 'm1' 'A' $false)),(Step (Page 'm2' 'B' $false))) 'Partial' 'cap' @('m1','m2') 2 2 2
Add-Case 'contradictory-complete-token' @((Step (Page 'x1' 'A' $true)),(Step (Page 'x2' $null $true))) 'Partial' 'invalid' @('x1') 1 1
Add-Case 'retain-prior-items-on-error' @((Step (Page 'k1' 'A' $false)),@{Kind='error'}) 'Partial' 'query-error' @('k1') 2 2
Add-Case 'empty-page-token-progress' @((Step (Page '' 'A' $false -Empty)),(Step (Page 'v1' $null $true))) 'Complete' 'none' @('v1') 2 2
Add-Case 'multiple-page-objects-invalid' @((Step @((Page 'a1' $null $true),(Page 'a2' $null $true)))) 'Partial' 'invalid' @() 1 1
function Reason-Matches($actual,$kind) {
  switch ($kind) {
    'none' { return [string]::IsNullOrEmpty([string]$actual) }
    'invalid' { return [string]$actual -match '(?i)invalid|malformed|contradict' }
    'no-progress' { return [string]$actual -match '(?i)repeat|no.?progress|cycle' }
    'cap' { return [string]$actual -match '(?i)cap|max.?pages|page.?limit' }
    default { return $actual -eq $kind }
  }
}
$results = foreach ($case in $cases) {
  $out=$null;$exception=$null;$fail=[System.Collections.Generic.List[string]]::new()
  $rawBefore=ConvertTo-Json -InputObject $case.State.Steps -Depth 12 -Compress
  try { $out=Invoke-SyntheticTracePager -Query $case.Query -MaxPages $case.Max } catch { $exception=[pscustomobject]@{Message=$_.Exception.Message;Type=$_.Exception.GetType().FullName;Position=$_.InvocationInfo.PositionMessage;Stack=$_.ScriptStackTrace} }
  $rawAfter=ConvertTo-Json -InputObject $case.State.Steps -Depth 12 -Compress
  if ($null -ne $exception) { $fail.Add('Unexpected exception') }
  else {
    $ids=@($out.Items | ForEach-Object {$_.Id})
    if ($out.Status -ne $case.Expected.Status) {$fail.Add('Status')}
    if (-not (Reason-Matches $out.Reason $case.Expected.Reason)) {$fail.Add('Reason')}
    if ((ConvertTo-Json -InputObject $ids -Compress) -ne (ConvertTo-Json -InputObject $case.Expected.Ids -Compress)) {$fail.Add('Items')}
    if (@($out.Pages).Count -ne $case.Expected.Pages) {$fail.Add('Pages')}
  }
  if ($case.State.Calls -ne $case.Expected.Calls) {$fail.Add('Calls')}
  if ($rawBefore -cne $rawAfter) {$fail.Add('Raw fixture mutation')}
  [pscustomobject]@{Name=$case.Name;Passed=($fail.Count -eq 0);Failures=@($fail.ToArray());Expected=$case.Expected;Actual=$out;Calls=$case.State.Calls;Tokens=@($case.State.Tokens.ToArray());RawFixtureUnchanged=($rawBefore -ceq $rawAfter);Exception=$exception}
}
[pscustomobject]@{PSVersion=$PSVersionTable.PSVersion.ToString();PagerPath=$PagerPath;Total=@($results).Count;Passed=@($results|Where-Object Passed).Count;Failed=@($results|Where-Object {-not $_.Passed}).Count;Cases=@($results)} | ConvertTo-Json -Depth 15
