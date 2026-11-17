#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/M365Toolkit.psm1" -Force -DisableNameChecking
$checks=[Collections.Generic.List[object]]::new()
function Check($name,$condition){$checks.Add(@{Name=$name;Passed=[bool]$condition});if(-not $condition){throw "FAIL $name"}}
function Rejects([scriptblock]$body){try{& $body | Out-Null;return $false}catch{return $true}}
$tenant=[guid]'11111111-2222-3333-4444-555555555555';$account='operator@contoso.example'
function New-TestRuntime([string[]]$Inputs=@()){
    $state=@{Inputs=[Collections.Generic.Queue[string]]::new();Output=[Collections.Generic.List[string]]::new();Prompts=[Collections.Generic.List[string]]::new();Calls=[Collections.Generic.List[object]]::new();Denial=$false;
      Graph=@{TenantId=$tenant.ToString();Account=$account;AuthType='Delegated';Environment='Global';Scopes=@('User.Read','AuditLog.Read.All','Directory.Read.All','IdentityRiskEvent.Read.All')};
      Exchange=@(@{TenantID=$tenant.ToString();UserPrincipalName=$account;State='Connected';TokenStatus='Active';CertificateAuthentication=$false;IsEopSession=$false;ModulePrefix='';DelegatedOrganization='';ModuleName='SyntheticExchange';ConnectionUri='https://outlook.office365.com/powershell-liveid/'})}
    foreach($input in $Inputs){$state.Inputs.Enqueue($input)}
    return @{State=$state;
      Read={param($p)$state.Prompts.Add($p);if(-not $state.Inputs.Count){throw "Unexpected prompt: $p"};$state.Inputs.Dequeue()}.GetNewClosure();
      Write={param($s)$state.Output.Add([string]$s)}.GetNewClosure();
      Local={param($c,$p)$state.Calls.Add(@{Kind='Local';Command=$c});if($c -eq 'Get-MgContext'){return $state.Graph};return $state.Exchange}.GetNewClosure();
      Connect={param($s,$p)$state.Calls.Add(@{Kind='Connect';Service=$s;Parameters=$p});if($state.Denial){throw 'Synthetic CA denial'};if($s -eq 'Graph'){$state.Graph.Scopes=$p.Scopes}}.GetNewClosure();
      ReadCommand={param($c,$p,$session)
        $state.Calls.Add(@{Kind='Read';Command=$c;Parameters=$p})
        if($c -eq 'Get-Mailbox'){return @{UserPrincipalName=$p.Identity;PrimarySmtpAddress=$p.Identity;EmailAddresses=@('SMTP:'+$p.Identity);ExchangeGuid='77777777-7777-7777-7777-777777777777'}}
        if($c -eq 'Invoke-MgGraphRequest'){
            if($p.Uri -match '/users/([^/]+)\?\$select='){return @{id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';userPrincipalName=[uri]::UnescapeDataString($Matches[1])}}
            return @{value=@()}
        }
        return @()
      }.GetNewClosure()}
}
Check 'exact targets normalize duplicates' ((ConvertTo-ToolkitTargets 'alex,BOB@example.com,bob@example.com' 'contoso.example').Count -eq 2)
Check 'bare user requires explicit domain' (Rejects {ConvertTo-ToolkitTargets 'alex'})
foreach($bad in @('*@contoso.example','Alex Smith','alex@contoso.example;*','a?@contoso.example',"bad$([char]27)@contoso.example",'x@@contoso.example')){Check "unsafe target rejected $($checks.Count)" (Rejects {ConvertTo-ToolkitTargets $bad})}
Check 'too many targets rejected' (Rejects {ConvertTo-ToolkitTargets ((1..51 | ForEach-Object {"u$_@contoso.example"}) -join ',')})
Check 'timezone explicit window accepted' ((ConvertTo-ToolkitWindow '2026-11-01T01:00:00+01:00' '2026-11-02T00:00:00Z').Start.Hour -eq 0)
foreach($pair in @(@('2026-11-01','2026-11-02'),@('2026-11-02T00:00:00Z','2026-11-01T00:00:00Z'),@('2026-01-01T00:00:00Z','2026-11-01T00:00:00Z'),@('2099-01-01T00:00:00Z','2099-01-02T00:00:00Z'))){Check "invalid window rejected $($checks.Count)" (Rejects {ConvertTo-ToolkitWindow $pair[0] $pair[1]})}
$unsafe="hello$([char]27)]52;c;payload$([char]7)`rforged"
$safe=ConvertTo-ToolkitText $unsafe
Check 'terminal OSC ESC CR controls escaped' ($safe -notmatch '[\x00-\x1f\x7f-\x9f]' -and $safe.Contains('\u001b'))
Check 'terminal values bounded' ((ConvertTo-ToolkitText ('a'*900)).Length -lt 700)
$r=New-TestRuntime
$null=Assert-ToolkitGraphSession $r $tenant $account
Check 'matching graph metadata accepted without request' (@($r.State.Calls | Where-Object Kind -eq 'Read').Count -eq 0)
foreach($change in @(@('TenantId','99999999-2222-3333-4444-555555555555'),@('Account','other@contoso.example'),@('AuthType','AppOnly'),@('Environment','USGov'))){
 $r=New-TestRuntime;$r.State.Graph[$change[0]]=$change[1]
 Check "Graph mismatch rejected $($change[0])" (Rejects {Assert-ToolkitGraphSession $r $tenant $account})
}
$r=New-TestRuntime;Connect-ToolkitDevice $r Graph $tenant $account -Scopes @('User.Read')
$connect=@($r.State.Calls | Where-Object Kind -eq 'Connect')
Check 'bootstrap uses only explicit device code minimal scope' ($connect.Count -eq 1 -and $connect[0].Parameters.UseDeviceCode -and $connect[0].Parameters.ContextScope -eq 'Process' -and $connect[0].Parameters.Scopes.Count -eq 1 -and $connect[0].Parameters.Scopes[0] -eq 'User.Read')
$r=New-TestRuntime;$r.State.Denial=$true
Check 'CA denial stops authentication' (Rejects {Connect-ToolkitDevice $r Graph $tenant $account -Scopes @('User.Read')})
Check 'CA denial not retried or changed flow' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 1)
$r=New-TestRuntime
Check 'write scopes refused before auth' (Rejects {Connect-ToolkitDevice $r Graph $tenant $account -Scopes @('Directory.ReadWrite.All')})
Check 'write scope makes no auth call' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
$r=New-TestRuntime @('S');$r.State.Graph.Scopes=@('User.Read');Request-ToolkitGraphScopes $r $tenant $account @('AuditLog.Read.All')
Check 'missing scope skipped without grant or reconnect' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
$r=New-TestRuntime @('D');$r.State.Graph.Scopes=@('User.Read');Request-ToolkitGraphScopes $r $tenant $account @('AuditLog.Read.All')
$connect=@($r.State.Calls | Where-Object Kind -eq 'Connect')
Check 'explicit action auth requests only action read scopes' ($connect.Count -eq 1 -and @($connect[0].Parameters.Scopes).Count -eq 1 -and 'Policy.Read.All' -notin $connect[0].Parameters.Scopes)
$r=New-TestRuntime;$null=Assert-ToolkitExchangeSession $r $tenant $account
Check 'matching Exchange REST metadata accepted' ($true)
foreach($change in @(@('TenantID','99999999-2222-3333-4444-555555555555'),@('UserPrincipalName','other@contoso.example'),@('TokenStatus','Expired'),@('CertificateAuthentication',$true),@('ModulePrefix','other'),@('DelegatedOrganization','other.example'),@('ConnectionUri','https://evil.example/'))){
 $r=New-TestRuntime;$r.State.Exchange[0][$change[0]]=$change[1]
 Check "Exchange mismatch rejected $($change[0])" (Rejects {Assert-ToolkitExchangeSession $r $tenant $account})
}
$r=New-TestRuntime;$r.State.Exchange+=@($r.State.Exchange[0].Clone())
Check 'ambiguous Exchange sessions refused' (Rejects {Assert-ToolkitExchangeSession $r $tenant $account})
$r=New-TestRuntime;$transport=New-ToolkitMailboxTransport $r $tenant $account 'alex@contoso.example'
foreach($command in @('Get-AcceptedDomain','Search-UnifiedAuditLog','Set-Mailbox','Get-Credential')){Check "transport refuses $command" (Rejects {& $transport $command @{}})}
foreach($method in @('POST','PATCH','PUT','DELETE')){Check "transport blocks metadata mutation $method" (Rejects {& $transport 'Invoke-MgGraphRequest' @{Method=$method;Uri='https://graph.microsoft.com/v1.0/users/alex%40contoso.example'}})}
Check 'hunting rejects non-POST methods' (Rejects {& $transport 'Invoke-MgGraphRequest' @{Method='DELETE';Uri='https://graph.microsoft.com/v1.0/security/runHuntingQuery'}})
Check 'transport blocks broad Graph collection' (Rejects {& $transport 'Invoke-MgGraphRequest' @{Method='GET';Uri='https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'}})
$r.State.Graph.Scopes=@('User.Read')
Check 'transport blocks missing scopes before provider' (Rejects {& $transport 'Invoke-MgGraphRequest' @{Method='GET';Uri='https://graph.microsoft.com/v1.0/auditLogs/signIns'}})
Check 'guarded failures issued no provider requests' (@($r.State.Calls | Where-Object Kind -eq 'Read').Count -eq 0)
$r=New-TestRuntime;$transport=New-ToolkitMailboxTransport $r $tenant $account 'alex@contoso.example'
$null=& $transport 'Get-Mailbox' @{Identity='alex@contoso.example'};$r.State.Exchange[0].UserPrincipalName='other@contoso.example'
Check 'session changed mid-run refused' (Rejects {& $transport 'Get-Mailbox' @{Identity='alex@contoso.example'}})
Check 'mid-run change prevented second provider call' (@($r.State.Calls | Where-Object Kind -eq 'Read').Count -eq 1)

# Provider-first startup: authenticated metadata is the authority, never typed tenant/account.
$r=New-TestRuntime @('','Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
$connect=@($r.State.Calls | Where-Object Kind -eq 'Connect')
Check 'first prompt offers Microsoft sign-in and reuse without tenant entry' ($r.State.Prompts[0] -like 'G = Microsoft Graph identity-only device sign-in*' -and @($r.State.Prompts | Where-Object {$_ -eq 'Tenant ID (exact GUID)' -or $_ -like 'Admin/operator account UPN*'}).Count -eq 0)
Check 'default Graph discovery uses documented device code without manual TenantId' ($connect.Count -eq 1 -and $connect[0].Service -eq 'Graph' -and $connect[0].Parameters.Count -eq 3 -and $connect[0].Parameters.UseDeviceCode -and $connect[0].Parameters.Scopes.Count -eq 1 -and $connect[0].Parameters.Scopes[0] -eq 'User.Read' -and -not $connect[0].Parameters.ContainsKey('TenantId'))
Check 'Graph startup never requires Exchange' (@($r.State.Calls | Where-Object {$_.Kind -eq 'Local' -and $_.Command -eq 'Get-ConnectionInformation'}).Count -eq 0)
Check 'authenticated tenant and account displayed before menu' (($r.State.Output -join ' ') -match [regex]::Escape($tenant.ToString()) -and ($r.State.Output -join ' ') -match [regex]::Escape($account) -and $r.State.Prompts[1] -like 'A = Audit*')
$r=New-TestRuntime @('E','Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
$connect=@($r.State.Calls | Where-Object Kind -eq 'Connect')
Check 'Exchange startup uses only documented Device parameter' ($connect.Count -eq 1 -and $connect[0].Service -eq 'Exchange' -and $connect[0].Parameters.Count -eq 1 -and $connect[0].Parameters.Device)
Check 'Exchange startup never touches Graph before action selection' (@($r.State.Calls | Where-Object {$_.Kind -eq 'Local' -and $_.Command -eq 'Get-MgContext'}).Count -eq 0)
foreach($provider in @('G','E')){
 $r=New-TestRuntime @('R',$provider,'Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
 Check "existing $provider reused without authentication" (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
}
$r=New-TestRuntime @('Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'startup quit makes no session or auth calls' ($r.State.Calls.Count -eq 0)
foreach($provider in @('G','E')){
 $r=New-TestRuntime @($provider);$r.State.Denial=$true
 Check "startup $provider CA denial propagates" (Rejects {Invoke-M365Terminal -Mode Live -Runtime $r})
 Check "startup $provider denial not retried or changed flow" (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 1 -and $r.State.Prompts.Count -eq 1)
}
$r=New-TestRuntime @('R','G','Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'resolved context reaches menu without extra confirmation; quit does not collect' ($r.State.Prompts.Count -eq 3 -and @($r.State.Calls | Where-Object {$_.Kind -in @('Connect','Read')}).Count -eq 0)
foreach($provider in @('G','E')){foreach($bad in @('','not-a-guid',[guid]::Empty.ToString())){
 $r=New-TestRuntime @('R',$provider)
 if($provider -eq 'G'){$r.State.Graph.TenantId=$bad}else{$r.State.Exchange[0].TenantID=$bad}
 Check "unreliable $provider tenant refused $($checks.Count)" (Rejects {Invoke-M365Terminal -Mode Live -Runtime $r})
 Check "unreliable tenant never prompted manually or queried $($checks.Count)" ($r.State.Prompts.Count -eq 2 -and @($r.State.Calls | Where-Object {$_.Kind -in @('Connect','Read')}).Count -eq 0)
}}
$r=New-TestRuntime @('R','E');$r.State.Exchange[0].UserPrincipalName=''
Check 'missing Exchange operator identity refused' (Rejects {Invoke-M365Terminal -Mode Live -Runtime $r})
$r=New-TestRuntime @('R','G');$r.State.Graph.Account=''
Check 'missing Graph operator identity refused' (Rejects {Invoke-M365Terminal -Mode Live -Runtime $r})
$r=New-TestRuntime @('R','E');$r.State.Exchange+=@($r.State.Exchange[0].Clone())
Check 'ambiguous startup Exchange sessions fail closed before confirmation' (Rejects {Invoke-M365Terminal -Mode Live -Runtime $r})
$r=New-TestRuntime @('D');$r.State.Graph.Account='other@contoso.example'
Check 'wrong Graph account after explicit device sign-in is refused' (Rejects {Request-ToolkitGraphScopes $r $tenant $account @('AuditLog.Read.All')})
$connect=@($r.State.Calls | Where-Object Kind -eq 'Connect')
Check 'subsequent Graph auth receives verified tenant and only selected scope' ($connect.Count -eq 1 -and $connect[0].Parameters.TenantId -eq $tenant.ToString() -and $connect[0].Parameters.Scopes.Count -eq 1 -and $connect[0].Parameters.Scopes[0] -eq 'AuditLog.Read.All')
$r=New-TestRuntime @('D');$r.State.Graph.TenantId='99999999-2222-3333-4444-555555555555'
Check 'wrong Graph tenant after explicit sign-in is refused' (Rejects {Request-ToolkitGraphScopes $r $tenant $account @('AuditLog.Read.All')})
$r=New-TestRuntime @('S');$r.State.Graph=$null
Request-ToolkitGraphScopes $r $tenant $account @('AuditLog.Read.All')
Check 'absent Graph can be skipped without authentication' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
$r=New-TestRuntime
Check 'nonbootstrap Graph auth requires a confirmed context' (Rejects {Connect-ToolkitDevice $r Graph -Scopes @('AuditLog.Read.All')})
Check 'missing verified context makes no additional Graph auth call' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
# Full menu and logs use real local collectors with only synthetic data/transports.
$r=New-TestRuntime @('L','alex@contoso.example','7','Y','N','N','Q')
$history=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'synthetic logs through complete menu produces triage' (@($r.State.Output | Where-Object {$_ -match '^MAILBOX: alex@contoso.example$'}).Count -eq 1)
Check 'synthetic menu never touches auth/provider sessions' ($r.State.Calls.Count -eq 0)
Check 'synthetic no-export produces no case path' ($null -eq $history[0][0].CasePath)
$r=New-TestRuntime @('R','E','L','alex@contoso.example,bob@contoso.example','1','Y','N','N','Q')
$history=Invoke-M365Terminal -Mode Live -Runtime $r
$reads=@($r.State.Calls | Where-Object Kind -eq 'Read')
Check 'mocked live menu triages two exact mailboxes' (@($r.State.Output | Where-Object {$_ -like 'MAILBOX:*'}).Count -eq 2)
Check 'multiple mailboxes remain exact separate queries' (@($reads | Where-Object Command -eq 'Get-Mailbox').Count -eq 2 -and @($reads | Where-Object {$_.Command -eq 'Get-Mailbox' -and $_.Parameters.Identity -notin @('alex@contoso.example','bob@contoso.example')}).Count -eq 0)
Check 'mailbox menu never requests broad audit' (@($reads | Where-Object {$_.Command -in @('Get-AcceptedDomain','Search-UnifiedAuditLog') -or [string](Get-ToolkitValue $_.Parameters 'Uri') -match '/directoryAudits|/v1.0/oauth2PermissionGrants'}).Count -eq 0)
Check 'reused sufficient sessions require no reconnect' (@($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
$r=New-TestRuntime @('R','E','L','alex@contoso.example','1','Y','N','N','Q');$r.State.Graph=$null
$history=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'Exchange-only selected mailbox runs with explicit Graph gaps' (@($r.State.Output | Where-Object {$_ -like 'MAILBOX:*'}).Count -eq 1 -and @($r.State.Calls | Where-Object Kind -eq 'Connect').Count -eq 0)
Check 'Exchange-only path makes no Graph provider request' (@($r.State.Calls | Where-Object {$_.Kind -eq 'Read' -and $_.Command -eq 'Invoke-MgGraphRequest'}).Count -eq 0)
$r=New-TestRuntime @('L','alex@contoso.example','7','N','Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'mailbox cancellation does not collect' (@($r.State.Output | Where-Object {$_ -like 'MAILBOX:*'}).Count -eq 0 -and $r.State.Calls.Count -eq 0)
if(Test-Path "$root/Audit/M365SecurityAudit.psm1"){
 Import-Module "$root/Audit/M365SecurityAudit.psm1" -DisableNameChecking
 foreach($exchangeState in @('absent','wrong-tenant')){
  $r=New-TestRuntime @('R','G','A','AUDIT','Q')
  $r.State.Graph.Scopes=@((Get-M365OrganizationAuditPlan).GraphReadPermissions)
  if($exchangeState -eq 'absent'){$r.State.Exchange=@()}else{$r.State.Exchange[0].TenantID='99999999-2222-3333-4444-555555555555'}
  $auditState=$r.State
  $r.AuditRun={param($p)
   $auditState.Calls.Add(@{Kind='Audit';Parameters=$p.Clone()})
   # Real collector in synthetic mode only; no SDK or tenant calls even on a connected host.
   $synthetic=$p.Clone();$synthetic.Mode='Synthetic';Invoke-M365OrganizationAudit @synthetic
  }.GetNewClosure()
  $history=Invoke-M365Terminal -Mode Live -Runtime $r
  $auditCalls=@($r.State.Calls | Where-Object Kind -eq 'Audit')
  Check "Graph-primary audit completes with $exchangeState Exchange" ($history.Count -eq 1 -and $history[0].SelectedCount -eq 46 -and $auditCalls.Count -eq 1)
  Check "Graph-only audit preserves resolved tenant and scope gates $exchangeState" ($auditCalls[0].Parameters.TenantId -eq $tenant -and $auditCalls[0].Parameters.ExpectedAccount -eq $account -and $auditCalls[0].Parameters.ConfirmedTenantId -eq $tenant -and $auditCalls[0].Parameters.ConfirmOrganizationWide)
  Check "Graph-only audit does not force component sign-in or tenant reads $exchangeState" (@($r.State.Calls | Where-Object {$_.Kind -in @('Connect','Read')}).Count -eq 0)
 }
 $r=New-TestRuntime @('A','wrong','Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
 Check 'audit incorrect approval cancellation safe' (@($r.State.Output | Where-Object {$_ -like 'Audit canceled*'}).Count -eq 1 -and $r.State.Calls.Count -eq 0)
 $r=New-TestRuntime @('A','','Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
 Check 'audit blank approval decline safe' (@($r.State.Output | Where-Object {$_ -like 'Audit canceled*'}).Count -eq 1 -and $r.State.Calls.Count -eq 0)
 $r=New-TestRuntime @('A','AUDIT','Q');$history=Invoke-M365Terminal -Mode Synthetic -Runtime $r
 Check 'full synthetic audit through menu completes' ($history.Count -eq 1 -and $history[0].SelectedCount -eq 46)
 Check 'synthetic audit makes no auth/session calls' ($r.State.Calls.Count -eq 0)
}
$r=New-TestRuntime @('L','alex@contoso.example','7','Y','N','N','V','1','Exchange.Mailbox','@coverage 1','','Q')
$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'terminal source viewer displays JSON without a file' (@($r.State.Output | Where-Object {$_ -match 'DeliverToMailboxAndForward'}).Count -ge 1)
Check 'terminal viewer emits no control sequences' (@($r.State.Output | Where-Object {$_ -match '[\x00-\x1f\x7f-\x9f]'}).Count -eq 0)
Check 'URLs defanged in terminal evidence' ((ConvertTo-ToolkitText 'https://evil.example') -eq 'hxxps://evil.example')
Check 'bidirectional formatting characters escaped' ((ConvertTo-ToolkitText ([string][char]0x202e)) -eq '\u202e')
$production=@(Get-ChildItem "$root/src" -Filter *.ps1)+@(Get-Item "$root/Start-M365Toolkit.ps1","$root/M365Toolkit.psm1")
foreach($file in $production){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 Check "syntax $($file.Name)" ($errors.Count -eq 0)
 $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()} | Where-Object {$_})
 Check "no server browser install secret commands $($file.Name)" (@($commands | Where-Object {$_ -match '^(Start-Process|Invoke-Item|Install-Module|Install-PSResource|Get-Credential|Start-Transcript|Invoke-WebRequest|Invoke-RestMethod|python|node|open|xdg-open)$'}).Count -eq 0)
 Check "no listener type $($file.Name)" ((Get-Content $file.FullName -Raw) -notmatch '(?i)HttpListener|TcpListener|SocketType')
}

# Streamlined UI: one deliberate scope confirmation, no repeated consent/save prompts.
$r=New-TestRuntime @('A','','Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
$c=@($r.State.Calls | Where-Object Kind -eq 'Connect')
$expected=@((Get-M365OrganizationAuditPlan).GraphReadPermissions|Sort-Object)
Check 'explicit startup Audit uses one device flow' ($c.Count -eq 1 -and $c[0].Service -eq 'Graph' -and $c[0].Parameters.UseDeviceCode)
Check 'startup Audit scopes exactly planned reads' ((@($c[0].Parameters.Scopes|Sort-Object) -join ',') -ceq ($expected -join ','))
Check 'startup Audit access does not itself collect' (@($r.State.Calls|Where-Object {$_.Kind -in @('Read','Audit')}).Count -eq 0)
Check 'startup displays exact scopes and new consent stop notice' (($r.State.Output -join ' ') -match 'Policy.Read.All' -and ($r.State.Output -join ' ') -match 'Stop at any new Microsoft consent')
Check 'startup Audit goes straight to one confirmation then cancellation returns menu' ($r.State.Prompts.Count -eq 3 -and $r.State.Prompts[1] -like 'Type AUDIT*' -and $r.State.Prompts[2] -like 'A = Audit*')
$r=New-TestRuntime @('A','AUDIT','Q');$st=$r.State
$r.AuditRun={param($p)$st.Calls.Add(@{Kind='Audit';Parameters=$p.Clone()});$sp=$p.Clone();$sp.Mode='Synthetic';Invoke-M365OrganizationAudit @sp}.GetNewClosure()
$h=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'startup Audit runs with no duplicate action selection' ($h.Count -eq 1 -and $r.State.Prompts.Count -eq 3 -and $r.State.Prompts[1] -like 'Type AUDIT*')
Check 'startup Audit one authentication only' (@($r.State.Calls|Where-Object Kind -eq 'Connect').Count -eq 1)
Check 'startup Audit retains underlying tenant authorization' (@($r.State.Calls|Where-Object Kind -eq 'Audit')[0].Parameters.ConfirmedTenantId -eq $tenant)
foreach($approval in @('','Y','AUDIT wrong','audit')){
 $r=New-TestRuntime @('A',$approval,'Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
 Check "only exact AUDIT approval accepted $($checks.Count)" ($r.State.Calls.Count -eq 0 -and @($r.State.Output|Where-Object {$_ -like 'Audit canceled*'}).Count -eq 1)
}
$r=New-TestRuntime @('R','G','A','AUDIT','Q');$r.State.Graph.Scopes=@('User.Read');$r.State.Exchange=@()
$st=$r.State
$r.AuditRun={param($p)$st.Calls.Add(@{Kind='Audit';Parameters=$p.Clone()});$sp=$p.Clone();$sp.Mode='Synthetic';Invoke-M365OrganizationAudit @sp}.GetNewClosure()
$h=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'existing minimal session never silently expands' (@($r.State.Calls|Where-Object Kind -eq 'Connect').Count -eq 0)
Check 'standard audit prompt count bounded' ($r.State.Prompts.Count -eq 5)
Check 'one scope confirmation no provider/save prompts' (@($r.State.Prompts|Where-Object {$_ -like 'Type AUDIT*'}).Count -eq 1 -and @($r.State.Prompts|Select-Object -Skip 2|Where-Object {$_ -match 'Save optional|Device sign-in|Confirm you|Use this resolved|Intune'}).Count -eq 0)
$ac=@($r.State.Calls|Where-Object Kind -eq 'Audit')
Check 'standard audit no export request' ($ac.Count -eq 1 -and -not $ac[0].Parameters.ContainsKey('OutputPath') -and -not $h[0].OutputPath)
Check 'audit no saving prompt or auto output' (@($r.State.Prompts|Where-Object {$_ -match 'file path|Save optional'}).Count -eq 0)
Check 'consolidated coverage gap notice' (@($r.State.Output|Where-Object {$_ -like 'Coverage gaps*'}).Count -eq 1)
$r=New-TestRuntime @('R','G','Q');$null=Invoke-M365Terminal -Mode Live -Runtime $r
Check 'menu quit no default organization collection' (@($r.State.Calls|Where-Object {$_.Kind -in @('Audit','Read','Connect')}).Count -eq 0)
$r=New-TestRuntime @('S','Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'save without result makes no file prompt' ($r.State.Prompts.Count -eq 2 -and ($r.State.Output -join ' ') -match 'No in-memory result to save')
$r=New-TestRuntime @('A','AUDIT','S','','Q');$null=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'explicit save blank cancellation' (($r.State.Output -join ' ') -match 'Save canceled; no file created' -and $r.State.Calls.Count -eq 0)
$saveDir=Join-Path $root ('test-output/ui-save-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($saveDir);$savePath=Join-Path $saveDir 'synthetic.json'
$r=New-TestRuntime @('A','AUDIT','S',$savePath,'Q');$h=Invoke-M365Terminal -Mode Synthetic -Runtime $r
Check 'explicit save produces JSON from existing result' ((Test-Path $savePath) -and (Get-Content $savePath -Raw|ConvertFrom-Json).Mode -eq 'Synthetic' -and $h.Count -eq 1)
Check 'explicit save no extra provider/auth' ($r.State.Calls.Count -eq 0)
$r=New-TestRuntime @($savePath);Check 'save refuses existing file' (Rejects {Save-ToolkitResult $h[0] $r})
$result=[pscustomobject]@{Passed=$true;Checks=$checks.Count;Details=$checks.ToArray();PowerShell=$PSVersionTable.PSVersion.ToString();LiveTenantTested=$false;Authentication='Mocks only';Providers='Synthetic fixtures and injected transports only'}
if($ResultsPath){$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ResultsPath}
$result | ConvertTo-Json -Depth 20
