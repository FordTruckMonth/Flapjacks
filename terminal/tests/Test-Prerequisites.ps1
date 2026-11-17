#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot/../setup/Prerequisites.psm1" -Force
$checks=[Collections.Generic.List[object]]::new()
function Check($name,$ok){$checks.Add(@{Name=$name;Passed=[bool]$ok});if(-not $ok){throw "FAIL: $name"}}
function Rejects([scriptblock]$action){try{& $action | Out-Null;$false}catch{$true}}
function FakeModule($version,$preview=''){[pscustomobject]@{Version=[version]$version;PrivateData=@{PSData=@{Prerelease=$preview}}}}
function New-SetupTestRuntime {
 $state=@{Host=@{Version=[version]'7.4.6';Family='Windows';Distribution='';Release='';Elevated=$false};Installed=@{'Microsoft.PowerShell.PSResourceGet'=@(FakeModule '1.1.0')};Repo=@([pscustomobject]@{Uri='https://www.powershellgallery.com/api/v2';Trusted=$false});Calls=[Collections.Generic.List[object]]::new();Fail=$false;Swap=$false;RepoChecks=0}
 @{
  State=$state
  HostInfo={$state.Host}.GetNewClosure()
  Modules={param($name)$state.Calls.Add(@{Kind='Modules';Name=$name});if($state.Installed.ContainsKey($name)){$state.Installed[$name]}else{@()}}.GetNewClosure()
  Repository={$state.Calls.Add(@{Kind='Repository'});$state.RepoChecks++;if($state.Swap -and $state.RepoChecks -gt 1){return @([pscustomobject]@{Uri='https://evil.example/api/v2'})};$state.Repo}.GetNewClosure()
  Install={param($p)$state.Calls.Add(@{Kind='Install';Parameters=$p});if($state.Fail){throw 'Synthetic install failure'};$v=switch($p.Name){'Microsoft.Graph.Authentication'{'2.10.0'}'PackageManagement'{'1.4.8.1'}'PowerShellGet'{'2.2.5'}default{if($state.Host.Version -lt [version]'7.6'){'3.9.2'}else{'3.10.0'}}};$state.Installed[$p.Name]=@([pscustomobject]@{Version=[version]$v;PrivateData=@{}})}.GetNewClosure()
 }
}
foreach($mode in @('Plan','Check')){
 $r=New-SetupTestRuntime;$p=Invoke-PrerequisiteSetup -Runtime $r -Mode $mode
 Check "$mode no install or repository access" (@($r.State.Calls | Where-Object {$_.Kind -ne 'Modules'}).Count -eq 0)
 Check "$mode defaults to Graph only" ($p.Modules.Count -eq 1 -and $p.Modules[0].Name -eq 'Microsoft.Graph.Authentication')
}
$r=New-SetupTestRuntime;$p=Invoke-PrerequisiteSetup -Runtime $r -Mode Install -IncludeExchange -WhatIf
Check 'WhatIf never installs' (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq 0)
Check 'WhatIf remains not ready when missing' (-not $p.Ready)
Check 'WhatIf never invokes repository manager' (@($r.State.Calls | Where-Object Kind -eq 'Repository').Count -eq 0)
$r=New-SetupTestRuntime;$p=Invoke-PrerequisiteSetup -Runtime $r -Mode Install
$c=@($r.State.Calls | Where-Object Kind -eq 'Install')
Check 'default install only Graph' ($c.Count -eq 1 -and $c[0].Parameters.Name -eq 'Microsoft.Graph.Authentication' -and $p.Ready)
Check 'CurrentUser exact Gallery bounded stable range' ($c[0].Parameters.Scope -eq 'CurrentUser' -and $c[0].Parameters.Repository -eq 'PSGallery' -and $c[0].Parameters.Version -eq '[2.0.0,3.0.0)')
Check 'no trust license preview dependency bypass or force flags' (@($c[0].Parameters.Keys | Where-Object {$_ -in @('TrustRepository','AcceptLicense','Prerelease','SkipDependencyCheck','Force','Reinstall','Quiet')}).Count -eq 0)
$r=New-SetupTestRuntime;$p=Invoke-PrerequisiteSetup -Runtime $r -Mode Install -IncludeExchange
$c=@($r.State.Calls | Where-Object Kind -eq 'Install')
Check 'explicit Exchange installs four supported components' ($c.Count -eq 4 -and $p.Ready)
Check 'PS7.4 avoids EXO3.10 runtime incompatibility' (($c | Where-Object {$_.Parameters.Name -eq 'ExchangeOnlineManagement'}).Parameters.Version -eq '[3.7.0,3.10.0)')
Check 'dependency order precedes Exchange' ($c[1].Parameters.Name -eq 'PackageManagement' -and $c[2].Parameters.Name -eq 'PowerShellGet' -and $c[3].Parameters.Name -eq 'ExchangeOnlineManagement')
$before=$c.Count;$null=Invoke-PrerequisiteSetup -Runtime $r -Mode Install -IncludeExchange
Check 'repeat install idempotent with matching versions' (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq $before)
$r=New-SetupTestRuntime;$r.State.Host.Version=[version]'7.6.1';$p=Invoke-PrerequisiteSetup -Runtime $r -IncludeExchange
Check 'PS7.6 permits reviewed EXO3 major' (($p.Modules | Where-Object Name -eq 'ExchangeOnlineManagement').Range -eq '[3.7.0,4.0.0)')
foreach($family in @('Windows','macOS','Debian')){
 $r=New-SetupTestRuntime
 if($family -eq 'macOS'){$r.State.Host.Family='macOS';$r.State.Host.Release='14.6'}
 if($family -eq 'Debian'){$r.State.Host.Family='Linux';$r.State.Host.Distribution='debian';$r.State.Host.Release='13'}
 $p=Invoke-PrerequisiteSetup -Runtime $r -Mode Install -IncludeExchange
 $c=@($r.State.Calls | Where-Object Kind -eq 'Install')
 Check "$family selected module behavior" ($c.Count -eq $(if($family -eq 'Debian'){1}else{4}))
 if($family -ne 'Windows'){Check "$family reports Purview unavailable" (($p.Gaps -join ' ') -match 'Purview.*unavailable')}
 if($family -eq 'Debian'){Check 'Debian Exchange is gap not all-ready' (-not $p.Ready -and @($p.Modules | Where-Object Status -eq 'Unsupported').Count -eq 3)}
}
$r=New-SetupTestRuntime;$r.State.Host.Family='macOS';$r.State.Host.Release='13.5';$p=Invoke-PrerequisiteSetup -Runtime $r -IncludeExchange
Check 'older macOS not silently declared supported' (@($p.Modules | Where-Object Status -eq 'Unsupported').Count -eq 3)
$r=New-SetupTestRuntime;$r.State.Installed['ExchangeOnlineManagement']=@(FakeModule '3.10.0');$p=Invoke-PrerequisiteSetup -Runtime $r -IncludeExchange
Check 'incompatible highest EXO version blocked not silently downgraded' (($p.Modules | Where-Object Name -eq 'ExchangeOnlineManagement').Status -eq 'Blocked')
$r=New-SetupTestRuntime;$r.State.Installed['Microsoft.Graph.Authentication']=@(FakeModule '3.0.0');$p=Invoke-PrerequisiteSetup -Runtime $r
Check 'unreviewed Graph major blocked' ($p.Modules[0].Status -eq 'Blocked')
$r=New-SetupTestRuntime;$r.State.Installed['Microsoft.Graph.Authentication']=@(FakeModule '2.10.0' 'preview1');$p=Invoke-PrerequisiteSetup -Runtime $r
Check 'preview module blocked' ($p.Modules[0].Status -eq 'Blocked')
$r=New-SetupTestRuntime;$r.State.Host.Elevated=$true
Check 'elevated installation refused before repository or install' (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install})
Check 'elevated refusal causes no mutation' (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq 0)
$r=New-SetupTestRuntime;$r.State.Installed.Remove('Microsoft.PowerShell.PSResourceGet')
Check 'missing installer does not bootstrap packages' (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install})
foreach($uri in @('https://evil.example/api/v2','http://www.powershellgallery.com/api/v2','https://www.powershellgallery.com.evil.example/api/v2','https://www.powershellgallery.com/api/v2?x=1')){
 $r=New-SetupTestRuntime;$r.State.Repo=@([pscustomobject]@{Uri=$uri})
 Check "wrong repository refused $($checks.Count)" (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install})
 Check "wrong repository no install $($checks.Count)" (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq 0)
}
$r=New-SetupTestRuntime;$r.State.Repo=@()
Check 'missing Gallery registration is not auto-added' (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install})
$r=New-SetupTestRuntime;$r.State.Swap=$true
Check 'repository change before write refused' (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install})
Check 'changed repository no install' (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq 0)
$r=New-SetupTestRuntime;$r.State.Fail=$true
Check 'installation failure stops without fallback' (Rejects {Invoke-PrerequisiteSetup -Runtime $r -Mode Install -IncludeExchange})
Check 'failure has one attempt only' (@($r.State.Calls | Where-Object Kind -eq 'Install').Count -eq 1)
$r=New-SetupTestRuntime;$r.State.Host.Version=[version]'5.1'
Check 'old PowerShell rejected' (Rejects {Invoke-PrerequisiteSetup -Runtime $r})
$files=@(Get-Item "$PSScriptRoot/../setup/Prerequisites.psm1","$PSScriptRoot/../Install-Prerequisites.ps1")
foreach($f in $files){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors)
 Check "native syntax $($f.Name)" ($errors.Count -eq 0)
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
 Check "no auth elevation trust-policy or download commands $($f.Name)" (@($commands | Where-Object {$_ -match '(^|\\)(Connect-|Set-ExecutionPolicy|Set-PSRepository|Set-PSResourceRepository|Register-PSResourceRepository|Register-PSRepository|Invoke-WebRequest|Invoke-RestMethod|Start-Process|Get-Credential|sudo|apt|apt-get|winget|brew|python|node)'}).Count -eq 0)
}
$result=@{Passed=$true;PrerequisiteChecks=$checks.Count;Details=$checks.ToArray();LiveInstallTested=$false;Platforms='Mocked Windows, macOS and Debian; local Linux plan/check only'}
if($ResultsPath){$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ResultsPath}
$result | ConvertTo-Json -Depth 10
