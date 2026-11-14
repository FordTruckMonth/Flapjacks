#Requires -Version 7.4
# Pure context fixtures and intercepted collectors only. No Microsoft modules, sign-in or live API calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:AuditRoot=Split-Path $PSScriptRoot -Parent
foreach ($part in @('Catalog','Collect','Evaluate','Report','Run','Terminal')) { . (Join-Path $script:AuditRoot "src/$part.ps1") }
$script:Passed=0
function Assert([bool]$Condition,[string]$Name) { if(-not $Condition){throw "FAIL: $Name"};$script:Passed++ }
function Throws([scriptblock]$Action,[string]$Name){$failed=$false;try{&$Action|Out-Null}catch{$failed=$true};Assert $failed $Name}
$tenant=[guid]'11111111-1111-1111-1111-111111111111';$wrong=[guid]'22222222-2222-2222-2222-222222222222';$account='admin@tenant.invalid'
$script:checks=0;$script:requests=0
# Any context check during a failed gate is a test failure.
function Get-AuditGraphContext { $script:checks++;throw 'No session inspection permitted during failed gate' }
function Get-AuditCommandSession { $script:checks++;throw 'No session inspection permitted during failed gate' }
$base=Join-Path ([IO.Path]::GetTempPath()) ('audit-gates-'+[guid]::NewGuid().ToString('N'))
$path=$base+'-missing-tenant'
Throws { Invoke-M365OrganizationAudit -Mode Live -ExpectedAccount $account -ConfirmedTenantId $tenant -ConfirmOrganizationWide -OutputPath $path } 'tenant required'
Assert (-not (Test-Path $path)) 'missing tenant creates no files'
$path=$base+'-missing-scope'
Throws { Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmedTenantId $tenant -OutputPath $path } 'organization scope confirmation required'
Assert (-not (Test-Path $path)) 'missing scope creates no files'
$path=$base+'-missing-retype'
Throws { Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmOrganizationWide -OutputPath $path } 'repeated tenant required'
Assert (-not (Test-Path $path)) 'missing repeated tenant creates no files'
$path=$base+'-wrong-tenant'
Throws { Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmedTenantId $wrong -ConfirmOrganizationWide -OutputPath $path } 'retyped tenant must match'
Assert (-not (Test-Path $path)) 'tenant mismatch creates no files'
$path=$base+'-missing-account'
Throws { Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ConfirmedTenantId $tenant -ConfirmOrganizationWide -OutputPath $path } 'expected account required'
Assert (-not (Test-Path $path)) 'missing account creates no files'
Throws { Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ExpectedAccount "admin`n@tenant.invalid" -ConfirmedTenantId $tenant -ConfirmOrganizationWide } 'account controls rejected'
Throws { Invoke-M365SecurityAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmTenantId $tenant } 'underlying API cannot bypass scope gate'
Assert ($script:checks -eq 0) 'all rejected gates precede session checks'
$ctx=@{TenantId=$tenant.ToString();Environment='Global';AuthType='Delegated';Account=$account;Scopes=@('Policy.Read.All')}
Assert ((Test-AuditGraphIdentity $ctx $tenant $account).Status -eq 'Ready') 'matching Graph delegated context accepted'
Assert ((Test-AuditGraphIdentity $ctx $tenant 'ADMIN@TENANT.INVALID').Status -eq 'Ready') 'UPN case-insensitive exact match'
Assert ((Test-AuditGraphIdentity $ctx $wrong $account).Status -eq 'TenantMismatch') 'Graph tenant mismatch refused'
Assert ((Test-AuditGraphIdentity $ctx $tenant 'other@tenant.invalid').Status -eq 'IdentityMismatch') 'Graph account mismatch refused'
Assert ((Test-AuditGraphIdentity $null $tenant $account).Status -eq 'NotConnected') 'missing Graph context refused'
$ctx.AuthType='AppOnly';Assert ((Test-AuditGraphIdentity $ctx $tenant $account).Status -eq 'IdentityMismatch') 'Graph app-only refused';$ctx.AuthType='Delegated'
$ctx.Environment='USGov';Assert ((Test-AuditGraphIdentity $ctx $tenant $account).Status -eq 'UnsupportedCloud') 'non-global Graph refused';$ctx.Environment='Global'
$connection=@{State='Connected';IsEopSession=$false;TenantID=$tenant.ToString();ModulePrefix='';TokenStatus='Active';ModuleName='Synthetic';UserPrincipalName=$account;CertificateAuthentication=$false;DelegatedOrganization=''}
Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'Ready') 'matching Exchange identity accepted'
Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Purview' $account).Status -eq 'NotConnected') 'Exchange context cannot serve Purview'
Assert ((Test-AuditCommandIdentity @($connection) $wrong 'Exchange' $account).Status -eq 'TenantMismatch') 'Exchange tenant mismatch refused'
Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' 'other@tenant.invalid').Status -eq 'IdentityMismatch') 'Exchange account mismatch refused'
Assert ((Test-AuditCommandIdentity @($connection,$connection) $tenant 'Exchange' $account).Status -eq 'NotConnected') 'ambiguous Exchange contexts refused'
$connection.CertificateAuthentication=$true;Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'IdentityMismatch') 'certificate-only workload context refused';$connection.CertificateAuthentication=$false
$connection.Remove('CertificateAuthentication');Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'IdentityMismatch') 'missing workload auth type refused';$connection.CertificateAuthentication=$false
$connection.DelegatedOrganization='other-tenant.invalid';Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'TenantMismatch') 'delegated organization session refused';$connection.DelegatedOrganization=''
$connection.ModulePrefix='Other';Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'NotConnected') 'prefixed workload session refused';$connection.ModulePrefix=''
$connection.TokenStatus='Expired';Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Exchange' $account).Status -eq 'NotConnected') 'expired workload session refused';$connection.TokenStatus='Active'
$connection.IsEopSession=$true;Assert ((Test-AuditCommandIdentity @($connection) $tenant 'Purview' $account).Status -eq 'Ready') 'matching Purview identity accepted'
# Synthetic, terminal-only wrapper: no context checks and no file writer calls.
function Export-AuditReport { throw 'No report writes expected when OutputPath is omitted' }
$r=Invoke-M365OrganizationAudit -Mode Synthetic
Assert ($r.SelectedCount -eq 46 -and $r.Coverage.Count -eq 46 -and $r.Evidence.Count -eq 46) 'organization wrapper selects all46 sources'
Assert ($r.OutputPath -eq '' -and $r.Metadata.Mode -eq 'Synthetic') 'terminal-only returns memory result without path'
Assert ($script:checks -eq 0) 'synthetic never inspects sessions'
$summary=@(Write-M365AuditSummary $r 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
Assert ($summary -match 'SYNTHETIC DATA ONLY' -and $summary -match 'No files saved') 'terminal summary mode and no-file notice'
Assert ($summary -match 'AccessDenied' -and $summary -match 'Partial') 'terminal coverage gaps visible'
$esc=[char]27
Assert ((ConvertTo-AuditTerminalText ("before${esc}]0;fake-title"+[char]7+'after')) -eq 'beforeafter') 'OSC title sequence removed'
Assert ((ConvertTo-AuditTerminalText ("${esc}[31mred${esc}[0m")) -eq 'red') 'ANSI color removed'
Assert ((ConvertTo-AuditTerminalText "one`ntwo`rthree`tfour") -eq 'one two three four') 'provider newline/tab controls flattened'
$detail=@(Write-M365AuditSource -Result $r -SourceId 'conditional-access' -Limit 2 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
Assert ($detail -match 'ca-synthetic-01' -and $detail -match 'Displaying 2 records' -and $detail -notmatch 'ca-synthetic-03') 'terminal detail viewer retains evidence and bounds displayed records'
Throws { Write-M365AuditSource -Result $r -SourceId 'unknown-source' } 'terminal detail viewer requires exact source id'
Assert ((ConvertTo-AuditTerminalText ('before'+[char]0x202e+'after')) -eq 'before after') 'bidi terminal reordering controls neutralized'
# Valid gates proceed only into fake collectors; every source rechecks identity.
$script:checks=0;$script:requests=0
function Get-AuditGraphContext { param($TenantId,$ExpectedAccount);$script:checks++;@{Status='IdentityMismatch';Reason='Synthetic switched Graph account'} }
function Get-AuditCommandSession { param($TenantId,$Provider,$ExpectedAccount);$script:checks++;@{Status='IdentityMismatch';Reason='Synthetic switched workload account'} }
function Read-AuditGraphSource { $script:requests++;throw 'No read allowed after failed identity check' }
function Read-AuditCommandSource { $script:requests++;throw 'No read allowed after failed identity check' }
$r=Invoke-M365OrganizationAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmedTenantId $tenant -ConfirmOrganizationWide
Assert ($script:checks -eq 46) 'identity checked separately for every selected source'
Assert ($script:requests -eq 0) 'no collector invoked for mismatched account'
Assert ($r.IncompleteCount -eq 46 -and @($r.Coverage | Where-Object Status -ne 'IdentityMismatch').Count -eq 0) 'identity failures preserved as explicit gaps'
Assert ($r.Metadata.OrganizationWideConfirmed -eq $true -and $r.OutputPath -eq '') 'confirmed in-memory live-mode fixture records scope without files'
# Simulate valid identity but absent Graph scopes: core sources are skipped, not consented.
$script:checks=0;$script:requests=0
function Get-AuditGraphContext { param($TenantId,$ExpectedAccount);$script:checks++;@{Status='Ready';Context=@{AuthType='Delegated';Scopes=@()}} }
$r=Invoke-M365SecurityAudit -Mode Live -TenantId $tenant -ExpectedAccount $account -ConfirmTenantId $tenant -ConfirmOrganizationScope
Assert ($script:checks -eq 7 -and $script:requests -eq 0) 'missing scopes do not trigger reads'
Assert (@($r.Coverage | Where-Object Status -eq 'InsufficientPermissions').Count -eq 7) 'missing scope gaps explicit'
Write-Host "PASS: $script:Passed terminal gate/identity assertions. No tenant calls or auth flows."
