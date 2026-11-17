#Requires -Version 7.4
# Offline tests only. Fake transports, invented policies, and local report files.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:AuditRoot=Split-Path $PSScriptRoot -Parent
foreach ($part in @('Catalog','Collect','Evaluate','Report','Run','Terminal')) { . (Join-Path $script:AuditRoot "src/$part.ps1") }
$script:Passed=0
function Assert([bool]$Condition,[string]$Name) { if (-not $Condition) { throw "FAIL: $Name" }; $script:Passed++ }
function Throws([scriptblock]$Action,[string]$Name) { $did=$false; try { & $Action | Out-Null } catch { $did=$true }; Assert $did $Name }
function HttpError([int]$Status,$RetryAfter=$null) { $e=[Exception]::new('SENSITIVE-EXCEPTION-MUST-NOT-BE-EXPORTED');$e.Data['HttpStatus']=$Status;if ($null -ne $RetryAfter) {$e.Data['RetryAfter']=$RetryAfter};throw $e }
$catalog=@(Get-AuditSourceCatalog)
Assert ($catalog.Count -eq 46) 'catalog has 46 explicit sources'
Assert (@($catalog.Id | Sort-Object -Unique).Count -eq $catalog.Count) 'source IDs unique'
Assert (@($catalog | Where-Object { $_.Provider -eq 'Graph' -and $_.Target -match '/beta|/users|signIns|oauth2PermissionGrants|credentials|managedDevices' }).Count -eq 0) 'no beta, users, logs, grants, credentials or devices endpoints'
Assert (@($catalog | Where-Object { $_.Provider -ne 'Graph' -and $_.Target -notmatch '^Get-' }).Count -eq 0) 'cmdlets read-only by catalog'
foreach ($source in $catalog) { Assert ($source.Documentation -match '^https://learn\.microsoft\.com/') ('official source '+$source.Id) }
$plan=Get-M365AuditPlan
Assert ($plan.Sources.Count -eq 7) 'core-only default'
Assert (@($plan.GraphReadPermissions).Count -eq 1 -and $plan.GraphReadPermissions[0] -eq 'Policy.Read.All') 'default one read permission'
$plan=Get-M365AuditPlan -Include Authentication,Consent,Administration,Intune
Assert ('Policy.Read.AuthenticationMethod' -notin $plan.GraphReadPermissions) 'no redundant authentication scope'
Assert ('Policy.Read.PermissionGrant' -in $plan.GraphReadPermissions) 'explicit consent read scope'
Assert (@($plan.GraphReadPermissions | Where-Object { $_ -match 'Write' }).Count -eq 0) 'no write permission recommendation'
$source=$catalog | Where-Object Id -eq 'conditional-access'
$initial='https://graph.microsoft.com/v1.0'+$source.Target
Assert (Test-AuditContinuation $initial $initial) 'initial allowlisted route'
Assert (Test-AuditContinuation ($initial+'?$skiptoken=opaque') $initial) 'same-resource continuation'
foreach ($uri in @('http://graph.microsoft.com/v1.0/identity/conditionalAccess/policies','https://evil.invalid/v1.0/identity/conditionalAccess/policies','https://graph.microsoft.com.evil.invalid/v1.0/identity/conditionalAccess/policies','https://graph.microsoft.com/v1.0/users','https://graph.microsoft.com:444/v1.0/identity/conditionalAccess/policies','https://x@graph.microsoft.com/v1.0/identity/conditionalAccess/policies',($initial+'#fragment'),($initial+'?$expand=users'),($initial+'?$skip=1&$skip=2'),'/v1.0/identity/conditionalAccess/policies')) {
 Assert (-not (Test-AuditContinuation $uri $initial)) ('reject unsafe continuation '+$uri)
}
$meta='https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$select=id,displayName'
Assert (Test-AuditContinuation ($meta+'&$skiptoken=x') $meta) 'projection retained'
Assert (-not (Test-AuditContinuation 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$skiptoken=x' $meta)) 'cannot drop projection'
Assert (-not (Test-AuditContinuation 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$select=*' $meta)) 'cannot expand projection'
$r=Read-AuditGraphSource $source {param($u) @{value=@()}}
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 0) 'genuine empty is collected'
$r=Read-AuditGraphSource $source {param($u) @{value=@(@{id='one'})}}
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 1) 'single item collection'
$script:calls=0
$r=Read-AuditGraphSource $source {param($u) $script:calls++; if ($script:calls -eq 1) { @{value=@(@{id='one'});'@odata.nextLink'=$initial+'?$skiptoken=two'} } else { @{value=@(@{id='two'})} }}
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 2 -and $r.PageCount -eq 2) 'all pages collected'
$script:calls=0
$r=Read-AuditGraphSource $source {param($u) $script:calls++; if ($script:calls -eq 1) { @{value=@();'@odata.nextLink'=$initial+'?$skiptoken=two'} } else { @{value=@(@{id='two'})} }}
Assert ($r.Count -eq 1 -and $r.PageCount -eq 2) 'empty intermediate page follows continuation'
$r=Read-AuditGraphSource $source {param($u) @{value=@(@{id='one'});'@odata.nextLink'=$initial}}
Assert ($r.Status -eq 'Partial' -and $r.Count -eq 1 -and $r.RequestCount -eq 1) 'repeated nextlink rejected before request'
$r=Read-AuditGraphSource $source {param($u) @{value=@(@{id='one'});'@odata.nextLink'='https://evil.invalid/steal'}}
Assert ($r.Status -eq 'Partial' -and $r.RequestCount -eq 1) 'foreign-host continuation not fetched'
$r=Read-AuditGraphSource $source {param($u) @{value=@(@{id='one'});'@odata.nextLink'=$initial+'?$skiptoken=two'}} -MaxPages 1
Assert ($r.Status -eq 'Partial' -and $r.Reason -eq 'PageLimit') 'page limit explicit'
$r=Read-AuditGraphSource $source {param($u) @{value=@(@{id='one'},@{id='two'})}} -MaxRecords 1
Assert ($r.Status -eq 'Partial' -and $r.Count -eq 1 -and $r.Reason -eq 'RecordLimit') 'record limit explicit'
foreach ($bad in @(@{},@{value=$null},@{value='not-array'},@{value=@{id='one'}},@{error=@{code='Denied'}},@{value=@('bad')})) {
 $script:badPage=$bad; $r=Read-AuditGraphSource $source {param($u) $script:badPage}
 Assert ($r.Status -eq 'Partial') 'malformed collection unknown, not empty'
}
$singleton=$catalog | Where-Object Id -eq 'security-defaults'
$r=Read-AuditGraphSource $singleton {param($u) @{isEnabled=$true}}
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 1) 'singleton collected'
$r=Read-AuditGraphSource $singleton {param($u) @{}}
Assert ($r.Status -eq 'Partial') 'empty singleton not accepted'
$auth=$catalog | Where-Object Id -eq 'authentication-methods-policy'
$r=Read-AuditGraphSource $auth {param($u) @{id='methods'}}
Assert ($r.Status -eq 'Partial') 'missing expanded auth configurations explicit'
$r=Read-AuditGraphSource $auth {param($u) @{id='methods';authenticationMethodConfigurations=@()}}
Assert ($r.Status -eq 'Collected') 'empty expanded auth configurations valid'
$r=Read-AuditGraphSource $auth {param($u) @{id='methods';authenticationMethodConfigurations=@();'authenticationMethodConfigurations@odata.nextLink'='next'}}
Assert ($r.Status -eq 'Partial') 'nested auth pagination not hidden'
$consent=$catalog | Where-Object Id -eq 'permission-grant-policies'
$r=Read-AuditGraphSource $consent {param($u) @{value=@(@{id='consent';includes=@();excludes=@()})}}
Assert ($r.Status -eq 'Collected') 'expanded consent conditions accepted'
$r=Read-AuditGraphSource $consent {param($u) @{value=@(@{id='consent'})}}
Assert ($r.Status -eq 'Partial') 'missing consent rules not clean'
foreach ($pair in @(@(401,'Unauthorized'),@(403,'AccessDenied'),@(404,'Unavailable'),@(500,'Error'))) {
 $script:status=[int]$pair[0];$r=Read-AuditGraphSource $source {param($u) HttpError $script:status} -Sleep {param($s) throw 'must not sleep'}
 Assert ($r.Status -eq $pair[1] -and $r.RequestCount -eq 1) ('classified HTTP'+$pair[0])
 Assert ($r.Reason -notmatch 'SENSITIVE') 'exception text not exported'
}
$script:calls=0;$script:sleeps=@()
$r=Read-AuditGraphSource $source {param($u) $script:calls++;if($script:calls -lt 3){HttpError 429 7};@{value=@(@{id='after-retry'})}} -Sleep {param($s) $script:sleeps+=,$s}
Assert ($r.Status -eq 'Collected' -and $r.RequestCount -eq 3) 'bounded throttle retries recover'
Assert ($script:sleeps.Count -eq 2 -and $script:sleeps[0] -eq 7) 'Retry-After honored'
$r=Read-AuditGraphSource $source {param($u) HttpError 429 121} -Sleep {param($s) throw 'must not retry too early'}
Assert ($r.Status -eq 'Throttled' -and $r.RequestCount -eq 1) 'long retry-after stops without premature retry'
$script:sleeps=@()
$r=Read-AuditGraphSource $source {param($u) HttpError 503} -Sleep {param($s) $script:sleeps+=,$s}
Assert ($r.Status -eq 'Error' -and $r.RequestCount -eq 4 -and $script:sleeps.Count -eq 3) 'retry limit honored'
$script:calls=0
$r=Read-AuditGraphSource $source {param($u) $script:calls++;if($script:calls -gt 1){HttpError 403};@{value=@(@{id='retained'});'@odata.nextLink'=$initial+'?$skiptoken=next'}}
Assert ($r.Status -eq 'Partial' -and $r.Count -eq 1) 'partial evidence survives later page failure'
Assert (@(Get-AuditObservations @($r)).Count -eq 0) 'no findings inferred from incomplete sources'
$r=New-AuditResult $source 'Collected';$r.Items=@();$r.Count=0
Assert (@(Get-AuditObservations @($r)).Count -eq 1) 'genuine empty CA creates review not pass'
$r.Status='AccessDenied';Assert (@(Get-AuditObservations @($r)).Count -eq 0) 'denial never interpreted as empty control'
foreach ($value in @('=1+1','+cmd','-2+4','@SUM(A1)',"`t=1+1","`r`n=1",'   =1',([string][char]0xfeff+'=1'))) {
 Assert ((ConvertTo-AuditCsvValue $value).StartsWith("'")) 'formula injection neutralized'
}
Assert ((ConvertTo-AuditCsvValue 'ordinary') -eq 'ordinary') 'ordinary CSV preserved'
Assert ((ConvertTo-AuditTerminalText ([string][char]27+'[31mred'+[char]27+'[0m')) -eq 'red') 'terminal ANSI escapes removed'
Assert ((ConvertTo-AuditCommandValue $true) -is [bool]) 'command Boolean preserved'
Assert (@((ConvertTo-AuditCommandValue @('a','b'))).Count -eq 2) 'command array preserved'
$runRoot=Join-Path ([IO.Path]::GetTempPath()) ('m365-audit-tests-'+[guid]::NewGuid().ToString('N'))
$allGroups=@('Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview')
$out=Invoke-M365SecurityAudit -Mode Synthetic -Include $allGroups -OutputPath $runRoot
Assert ($out.SelectedCount -eq $catalog.Count) 'all selected sources included'
Assert ($out.IncompleteCount -eq 3) 'synthetic known failures visible'
$validation=Test-M365AuditManifest $runRoot
Assert ($validation.Valid) 'all exported artifacts match hashes'
Assert (-not (Test-Path -LiteralPath (Join-Path $runRoot 'report.html'))) 'no HTML report emitted'
$csv=Import-Csv -LiteralPath (Join-Path $runRoot 'inventory.csv')
Assert (@($csv | Where-Object Name -like "'=HYPERLINK*").Count -eq 1) 'exported inventory formula neutralized'
$audit=Get-Content -LiteralPath (Join-Path $runRoot 'audit.json') -Raw | ConvertFrom-Json -Depth 100
Assert ($audit.Metadata.Mode -eq 'Synthetic') 'machine-readable mode retained'
Assert ($audit.Metadata.TenantId -eq 'SYNTHETIC-NOT-A-TENANT') 'no invented live tenant identifier'
Assert (@($audit.Coverage | Where-Object Status -eq 'NotProvided').Count -eq 0) 'all groups have synthetic fixtures'
Throws { Invoke-M365SecurityAudit -OutputPath $runRoot } 'existing report cannot be overwritten'
Throws { Invoke-M365SecurityAudit -Mode Live -OutputPath ($runRoot+'-blocked') } 'live requires tenant ID before collecting'
Assert (-not (Test-Path -LiteralPath ($runRoot+'-blocked'))) 'missing-tenant failure has no output side effect'
[IO.File]::AppendAllText((Join-Path $runRoot 'inventory.csv'),'tamper')
Assert (-not (Test-M365AuditManifest $runRoot).Valid) 'tampering detected'
$manifestPath=Join-Path $runRoot 'manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
$manifest.Files[0].Path='../outside.txt';Write-AuditJson $manifestPath $manifest
Assert (-not (Test-M365AuditManifest $runRoot).Valid) 'manifest path traversal rejected'
# Regression cases found by independent review.
$intune=$catalog | Where-Object Id -eq 'intune-configuration-policy-metadata'
$r=Read-AuditGraphSource $intune {param($u) @{value=@(@{id='one';displayName='one';unexpectedSecret='do-not-export'},@{id='two';displayName='two';preSharedKey='do-not-export'})}}
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 2) 'Intune projected response collected'
Assert ((ConvertTo-Json -InputObject $r.Items -Depth 20) -notmatch 'unexpectedSecret|preSharedKey|do-not-export') 'Intune unexpected settings discarded locally'
$r=New-AuditResult $source 'Collected';$r.Items=@(@{id='unknown-state'});$r.Count=1
$unknown=@(Get-AuditObservations @($r))
Assert ($unknown.Count -eq 1 -and $unknown[0].Rule -eq 'CA-STATE-UNKNOWN') 'missing CA state is unknown not disabled'
$r.Items=@(@{id='future-state';state='unknownFutureValue'})
Assert (@(Get-AuditObservations @($r))[0].Rule -eq 'CA-STATE-UNKNOWN') 'future CA state is unknown'
$r=Read-AuditGraphSource $auth {param($u) @{id='methods';authenticationMethodConfigurations='invalid'}}
Assert ($r.Status -eq 'Partial') 'auth expansion must be array'
$r=Read-AuditGraphSource $consent {param($u) @{value=@(@{id='consent';includes='invalid';excludes=@()})}}
Assert ($r.Status -eq 'Partial') 'consent conditions must be arrays'
Assert ('RoleEligibilitySchedule.Read.Directory' -notin (Get-M365AuditPlan -Include Administration).GraphReadPermissions) 'no redundant PIM scope'
if (-not $IsWindows) {
    $symlinkRoot=$runRoot+'-links';$outside=$runRoot+'-outside'
    [void][IO.Directory]::CreateDirectory($symlinkRoot);[void][IO.Directory]::CreateDirectory($outside)
    [IO.File]::WriteAllText((Join-Path $outside 'x.txt'),'synthetic')
    [void](New-Item -ItemType SymbolicLink -Path (Join-Path $symlinkRoot 'evidence') -Target $outside)
    Write-AuditJson (Join-Path $symlinkRoot 'manifest.json') @{SchemaVersion='1.0';Algorithm='SHA256';Files=@(@{Path='evidence/x.txt';Bytes=9;Sha256=(Get-FileHash (Join-Path $outside 'x.txt')).Hash})}
    Assert (-not (Test-M365AuditManifest $symlinkRoot).Valid) 'symlink ancestor rejected'
}
# Synthetic Exchange module is bound to a mock REST connection, not a real tenant.
$script:fakeCalls=[System.Collections.Generic.List[object]]::new()
$fakeModule=New-Module -Name SyntheticExchangeSession -ScriptBlock {
    function Get-OutboundConnector {
        [CmdletBinding()]param([bool]$IncludeTestModeConnectors,[bool]$IsTransportRuleScoped,[string]$ResultSize)
        [pscustomobject]@{Identity="test-$IncludeTestModeConnectors-scope-$IsTransportRuleScoped";Name=$ResultSize;Enabled=$true}
    }
    function Get-DkimSigningConfig { [CmdletBinding()]param([Parameter(Mandatory)][string]$Identity);throw 'should never prompt or invoke' }
    $script:omitRejectDirectSend=$false
    function Get-OrganizationConfig {
        [CmdletBinding()]param()
        $row=[ordered]@{Identity='synthetic-org';OAuth2ClientProfileEnabled=$true;AuditDisabled=$false;DefaultAuthenticationPolicy='synthetic';AutoExpandingArchiveEnabled=$false}
        if(-not $script:omitRejectDirectSend){$row.RejectDirectSend=$false}
        [pscustomobject]$row
    }
    function Get-TransportConfig { [CmdletBinding()]param();Write-Warning 'synthetic truncated result';[pscustomobject]@{Identity='x'} }
    function Get-RetentionCompliancePolicy {
        [CmdletBinding()]param([switch]$DistributionDetail)
        if (-not $DistributionDetail) { throw 'distribution detail required' }
        [pscustomobject]@{Identity='retention';Name='retention';Enabled=$true}
    }
    Export-ModuleMember -Function Get-OrganizationConfig,Get-OutboundConnector,Get-DkimSigningConfig,Get-TransportConfig,Get-RetentionCompliancePolicy
}
Import-Module $fakeModule -Force
$session=@{Connection=@{ModuleName='SyntheticExchangeSession'}}
$connectorSource=[pscustomobject]@{Id='test-connector';Group='Exchange';Provider='Exchange';Target='Get-OutboundConnector';Fields=@('Identity','Name','Enabled');Notes='synthetic'}
$r=Read-AuditCommandSource -Source $connectorSource -Session $session
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 4 -and $r.RequestCount -eq 4) 'all four outbound connector combinations collected'
Assert (@($r.Items | Where-Object Name -ne 'Unlimited').Count -eq 0) 'Exchange ResultSize Unlimited used'
$r=Read-AuditCommandSource -Source $connectorSource -Session $session -MaxRecords 1
Assert ($r.Status -eq 'Partial' -and $r.Count -eq 1) 'Exchange record cap explicit'
$r=Read-AuditCommandSource -Source $connectorSource -Session @{Connection=@{ModuleName='WrongSession'}}
Assert ($r.Status -eq 'Unavailable' -and $r.RequestCount -eq 0) 'wrong-session command refused'
$mandatorySource=$catalog | Where-Object Id -eq 'exchange-dkim'
$r=Read-AuditCommandSource -Source $mandatorySource -Session $session
Assert ($r.Status -eq 'Partial' -and $r.RequestCount -eq 0) 'mandatory prompt prevented'
$organizationSource=$catalog | Where-Object Id -eq 'exchange-organization'
$transportSource=$catalog | Where-Object Id -eq 'exchange-transport'
Assert ($organizationSource.Target -eq 'Get-OrganizationConfig' -and 'RejectDirectSend' -in $organizationSource.Fields) 'RejectDirectSend assigned to organization command'
Assert ('RejectDirectSend' -notin $transportSource.Fields) 'RejectDirectSend not requested from transport'
$r=Read-AuditCommandSource -Source $organizationSource -Session $session
Assert ($r.Status -eq 'Collected' -and $r.MissingFields.Count -eq 0) 'complete organization projection collected'
Assert ($r.Items[0].RejectDirectSend -is [bool] -and $r.Items[0].RejectDirectSend -eq $false) 'explicit RejectDirectSend false preserved as Boolean'
& $fakeModule { $script:omitRejectDirectSend=$true }
$r=Read-AuditCommandSource -Source $organizationSource -Session $session
Assert ($r.Status -eq 'Partial' -and 'RejectDirectSend' -in $r.MissingFields) 'absent organization RejectDirectSend remains unknown partial'
Assert ($null -eq $r.Items[0].PSObject.Properties['RejectDirectSend']) 'absent RejectDirectSend not invented as false'
$fixture=Get-Content (Join-Path $script:AuditRoot 'fixtures/synthetic.json') -Raw | ConvertFrom-Json
Assert ($fixture.'exchange-organization'.Items[0].RejectDirectSend -is [bool] -and $fixture.'exchange-organization'.Items[0].RejectDirectSend -eq $false) 'synthetic organization fixture preserves explicit false'
$warningSource=$catalog | Where-Object Id -eq 'exchange-transport'
$r=Read-AuditCommandSource -Source $warningSource -Session $session
Assert ($r.Status -eq 'Partial' -and $r.Reason -match 'Warning') 'Exchange warnings never labeled complete'
Assert ($r.MissingFields.Count -gt 0) 'missing Exchange properties tracked'
Assert ('RejectDirectSend' -notin $r.MissingFields) 'transport no longer reports incorrect RejectDirectSend gap'
$retentionSource=[pscustomobject]@{Id='test-retention';Group='Purview';Provider='Purview';Target='Get-RetentionCompliancePolicy';Fields=@('Identity','Name','Enabled');Notes='synthetic'}
$r=Read-AuditCommandSource -Source $retentionSource -Session $session
Assert ($r.Status -eq 'Collected' -and $r.Count -eq 1) 'Purview reads request DistributionDetail'
Remove-Module SyntheticExchangeSession
# Syntax validation for every shipped PowerShell file, independent of execution paths.
foreach ($file in Get-ChildItem -LiteralPath $script:AuditRoot -File -Recurse | Where-Object { $_.Extension -in '.ps1','.psm1' }) {
 $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 Assert ($errors.Count -eq 0) ('syntax '+$file.Name)
}
Write-Host "PASS: $script:Passed offline assertions. Synthetic report: $runRoot"
