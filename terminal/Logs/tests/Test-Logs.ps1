#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/M365Bec.psm1" -Force -DisableNameChecking
$checks=[Collections.Generic.List[object]]::new()
function Check($name,$condition){if(-not $condition){throw "FAIL: $name"};$checks.Add(@{Name=$name;Passed=$true})}
function Rejects([scriptblock]$Body){try{& $Body | Out-Null;return $false}catch{return $true}}
$target='alex@contoso.example';$id='11111111-1111-1111-1111-111111111111';$s=[DateTimeOffset]'2026-11-01T00:00:00Z';$e=$s.AddDays(1)
Check 'UPN exact case insensitive' (Test-BecExactMailbox @{UserPrincipalName='ALEX@contoso.example'} $target)
Check 'alias exact accepted' (Test-BecExactMailbox @{EmailAddresses=@('smtp:alex@contoso.example')} $target)
Check 'fuzzy prefix rejected' (-not (Test-BecExactMailbox @{UserPrincipalName='alexander@contoso.example';DisplayName=$target} $target))
Check 'wrong mailbox rejected' (-not (Test-BecExactMailbox @{PrimarySmtpAddress='other@contoso.example'} $target))
$defaultContext=New-BecContext
foreach($attempt in @(@{Method='DELETE';Uri='https://graph.microsoft.com/v1.0/users/alex%40contoso.example'},@{Method='GET';Uri='https://graph.microsoft.com/v1.0/users/alex%40contoso.example/messages'})){
    $denied='';try{& $defaultContext.Transport 'Invoke-MgGraphRequest' $attempt}catch{$denied=$_.Exception.Message}
    Check ('default transport rejects unsafe method/content before command resolution: '+$attempt.Method) ($denied -eq 'Only allowlisted metadata GETs are permitted')
}
$filter="userPrincipalName eq '$target' and createdDateTime ge 2026-11-01T00:00:00Z and createdDateTime le 2026-11-02T00:00:00Z"
$uri='https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter='+[uri]::EscapeDataString($filter)
Check 'same scope plus opaque paging accepted' (-not (Rejects {Assert-BecScopedContinuation $uri ($uri+'&$skiptoken=abc')}))
Check 'dropped target filter refused' (Rejects {Assert-BecScopedContinuation $uri 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc'})
Check 'changed target filter refused' (Rejects {Assert-BecScopedContinuation $uri ($uri.Replace('alex','other')+'&$skiptoken=abc')})
Check 'added expand refused' (Rejects {Assert-BecScopedContinuation $uri ($uri+'&$expand=anything')})
Check 'duplicate filters refused' (Rejects {Assert-BecScopedContinuation $uri ($uri+'&$filter=other')})
Check 'changed collection refused' (Rejects {Assert-BecScopedContinuation $uri ($uri.Replace('/signIns','/directoryAudits'))})
$calls=[Collections.Generic.List[object]]::new()
$ctx=New-BecContext -Transport {param($command,$p)$calls.Add($p);@{value=@(@{id='first'});'@odata.nextLink'='https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=unsafe'}}
$r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx -Target $target -TargetId $id
Check 'broad nextlink never requested and first page retained' ($calls.Count -eq 1 -and $r.Status -eq 'Partial' -and $r.Items.Count -eq 1)
Check 'initial broad query refused before provider' (Rejects {Invoke-BecGraphCollection 'Entra.SignIns' 'https://graph.microsoft.com/v1.0/auditLogs/signIns' $ctx -Target $target})
Check 'initial OR broadening refused' (Rejects {Invoke-BecGraphCollection 'Entra.SignIns' ($uri+[uri]::EscapeDataString(' or true')) $ctx -Target $target})
Check 'forbidden audit collection refused' (Rejects {Invoke-BecGraphCollection 'Entra.Audit' 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits' $ctx -Target $target})
$calls.Clear();$page=@{N=0}
$ctx=New-BecContext -Transport {param($command,$p)$calls.Add($p);$page.N++;if($page.N -eq 1){@{value=@(@{id='first'});'@odata.nextLink'=($uri+'&$skiptoken=opaque')}}else{@{value=@(@{id='second'})}}}
$r=Invoke-BecGraphCollection 'Entra.SignIns' $uri $ctx -Target $target -TargetId $id
Check 'valid scoped continuation returns both pages' ($calls.Count -eq 2 -and $r.Status -eq 'Collected' -and $r.Items.Count -eq 2)
$calls.Clear();$ctx=New-BecContext -Transport {param($command,$p)$calls.Add(@{Command=$command;Parameters=$p});if($command -eq 'Get-Mailbox'){@{UserPrincipalName='wrong@contoso.example'}}}
$r=@(Invoke-BecExchange $target $ctx)
Check 'wrong Exchange resolution stops further requests' ($calls.Count -eq 1 -and ($r | Where-Object Source -eq 'Exchange.Mailbox').Status -eq 'Unavailable')
Check 'wrong mailbox payload removed' (($r | Where-Object Source -eq 'Exchange.Mailbox').Items.Count -eq 0)
$calls.Clear();$ctx=New-BecContext -Transport {param($command,$p)$calls.Add(@{Command=$command;Parameters=$p});if($command -eq 'Get-MgContext'){@{Environment='Global'}}else{@{id=$id;userPrincipalName='wrong@contoso.example'}}}
$r=@(Invoke-BecEntra $target $s $e $ctx)
Check 'wrong Graph resolution stops before logs' ($calls.Count -eq 2 -and @($r | Where-Object Status -eq 'Collected').Count -eq 0)
$ctx=New-BecContext -Transport {param($command,$p)
    if($command -eq 'Get-Mailbox'){return @{UserPrincipalName=$target}}
    if($command -eq 'Get-InboxRule'){if($p.ResultSize -isnot [int]){throw 'numeric result cap required'};return @(1..1000 | ForEach-Object {@{Identity=('rule-'+$_)}})}
    return @()
}
$r=@(Invoke-BecExchange $target $ctx);$rules=$r | Where-Object Source -eq 'Exchange.Rules'
Check 'inbox numeric limit saturation remains partial' ($rules.Items.Count -eq 1000 -and $rules.Status -eq 'Partial')
$ctx=New-BecContext -Transport {param($command,$p)
 $calls.Add(@{Command=$command;Parameters=$p})
 switch($command){
  'Get-Mailbox' {@{UserPrincipalName=$target;PrimarySmtpAddress=$target;EmailAddresses=@('SMTP:alex@contoso.example')}}
  'Get-MgContext' {@{Environment='Global'}}
  'Invoke-MgGraphRequest' {if($p.Uri -match '/users/[^/]+\?'){@{id=$id;userPrincipalName=$target}}else{@{value=@()}}}
  default {@()}
 }
}
$calls.Clear();$r=Invoke-BecInvestigation -Mode Live -TargetUpn $target -Start $s -End $e -Context $ctx
Check 'injected transport default writes no files' (-not $r.CasePath -and $null -eq $r.Manifest -and $null -eq $r.Report)
Check 'no prohibited broad requests' (@($calls | Where-Object {$_.Command -in @('Get-AcceptedDomain','Search-UnifiedAuditLog') -or $_.Parameters.Uri -match '/directoryAudits|/v1.0/oauth2PermissionGrants'}).Count -eq 0)
Check 'full terminal data objects returned' ($null -ne $r.Metadata -and $r.Collections.Count -eq 24 -and $r.Coverage.Count -eq 24 -and $null -ne $r.Correlations)
Check 'TenantContext rejected' (Rejects {Invoke-BecInvestigation -Mode Fixture -TargetUpn $target -Start $s -End $e -CollectionScope TenantContext})
$r=Invoke-BecInvestigation -TargetUpn $target -Start $s -End $e.AddDays(10) -OutputRoot "$root/cases/tests"
Check 'fixture output hashes verify' ($r.Manifest.Passed)
Check 'no HTML files or HTML result' (@(Get-ChildItem $r.CasePath -Recurse -Filter '*.html').Count -eq 0 -and $null -eq $r.Report)
Check 'only JSON CSV hash files emitted' (@(Get-ChildItem $r.CasePath -Recurse -File | Where-Object Extension -notin @('.json','.csv','.sha256')).Count -eq 0)
Check 'tenant scopes have zero fixture payloads' (@($r.Collections | Where-Object {$_.Source -in (Get-BecTenantContextSources) -and $_.Items.Count -gt 0}).Count -eq 0)
Check 'fixture optional sources disabled by default' (@($r.Collections | Where-Object {($_.Source -like 'Defender.*' -or $_.Source -eq 'Entra.NonInteractiveSignIns') -and ($_.Items.Count -gt 0 -or $_.Status -ne 'Unavailable')}).Count -eq 0)
$included=Invoke-BecInvestigation -TargetUpn $target -Start $s -End $e.AddDays(10) -IncludeDefender -IncludeNonInteractivePreview
Check 'fixture explicit Defender opt-in retains synthetic payloads' (@($included.Collections | Where-Object {$_.Source -like 'Defender.*' -and $_.Items.Count -gt 0}).Count -gt 0)
Check 'fixture explicit preview opt-in retains synthetic payloads' (($included.Collections | Where-Object Source -eq 'Entra.NonInteractiveSignIns').Items.Count -gt 0)
$defenderOnly=Invoke-BecInvestigation -TargetUpn $target -Start $s -End $e.AddDays(10) -IncludeDefender
Check 'fixture Defender opt-in does not enable preview' (($defenderOnly.Collections | Where-Object Source -eq 'Entra.NonInteractiveSignIns').Status -eq 'Unavailable')
Check 'CSV formula neutralized' ((ConvertTo-BecCsvValue '=1+1').StartsWith("'"))
$path=Join-Path $r.CasePath 'coverage.csv';$before=[IO.File]::ReadAllBytes($path);[IO.File]::AppendAllText($path,'tamper')
Check 'manifest detects tampering' (-not (Test-BecManifest $r.CasePath).Passed);[IO.File]::WriteAllBytes($path,$before)
Check 'manifest restored' ((Test-BecManifest $r.CasePath).Passed)
$errors=@(Get-ChildItem $root -Recurse -File | Where-Object Extension -in '.ps1','.psm1' | ForEach-Object {$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e);$e})
Check 'all native PowerShell parses' ($errors.Count -eq 0)
$result=@{Passed=$true;Checks=$checks.Count;Details=$checks.ToArray();LiveTenantTested=$false;CasePath=$r.CasePath}
if($ResultsPath){$result | ConvertTo-Json -Depth 20 | Set-Content $ResultsPath};$result | ConvertTo-Json -Depth 20
