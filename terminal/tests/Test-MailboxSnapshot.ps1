#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop';$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/M365Toolkit.psm1" -Force -DisableNameChecking
$checks=[Collections.Generic.List[object]]::new()
function Check($name,$condition){$checks.Add(@{Name=$name;Passed=[bool]$condition});if(-not $condition){throw "FAIL $name"}}
function Rejects([scriptblock]$body){try{& $body | Out-Null;return $false}catch{return $true}}
function Fixture {Get-Content "$root/fixtures/mailbox-snapshot-input.synthetic.json" -Raw | ConvertFrom-Json -Depth 100}
$tenant=[guid]'11111111-2222-3333-4444-555555555555'
$r=Fixture;$s=ConvertTo-ToolkitMailboxSnapshot $r $tenant
Check 'schema' ($s.schema -ceq 'response-menu.mailbox-snapshot.v1')
Check 'tenant' ($s.tenant_id -ceq $tenant.ToString())
Check 'canonical lowercase' ($s.mailbox_upn -ceq 'alex@contoso.example')
Check 'UTC timestamp' ($s.acquired_at -match 'Z$')
Check 'synthetic boolean' ($s.synthetic -is [bool] -and $s.synthetic)
Check 'honest evidence class' ($s.evidence_class -ceq 'reserialized-source-objects')
Check 'three source groups' ($s.sources.Count -eq 3)
foreach($name in @('inbox_rules','forwarding','delegates')){Check "$name collected" ($s.sources[$name].status -eq 'collected');Check "$name array" ($s.sources[$name].records -is [array])}
Check 'raw rule retained' ($s.sources.inbox_rules.records[0].Name -ceq $r.Collections[1].Items[0].Name)
Check 'forwarding retained' ($s.sources.forwarding.records[0].ForwardingSmtpAddress -eq 'smtp:archive@outside.example')
Check 'delegate types' ((@($s.sources.delegates.records.source|Sort-Object) -join ',') -eq 'Exchange.FullAccess,Exchange.Mailbox.SendOnBehalf,Exchange.SendAs')
Check 'send-on-behalf retained' ($s.sources.delegates.records[2].record.GrantSendOnBehalfTo[0] -eq 'assistant@contoso.example')
$r.Mode='Live';Check 'live marked non-synthetic' (-not (ConvertTo-ToolkitMailboxSnapshot $r $tenant).synthetic)
$r=Fixture;$r.Collections[1].Items=@();$s=ConvertTo-ToolkitMailboxSnapshot $r $tenant
Check 'empty collected remains distinct' ($s.sources.inbox_rules.status -eq 'collected' -and $s.sources.inbox_rules.records.Count -eq 0)
$r=Fixture;$r.Collections=@($r.Collections|Where-Object Source -ne 'Exchange.Rules');$s=ConvertTo-ToolkitMailboxSnapshot $r $tenant
Check 'absent unavailable' ($s.sources.inbox_rules.status -eq 'unavailable' -and $s.sources.inbox_rules.records.Count -eq 0)
foreach($status in @('Partial','Denied','Unavailable')){
 $r=Fixture;$r.Collections[1].Status=$status;$s=ConvertTo-ToolkitMailboxSnapshot $r $tenant
 Check "status $status preserved" ($s.sources.inbox_rules.status -eq $status.ToLowerInvariant())
 if($status -ne 'Partial'){Check "$status does not retain contradictory records" ($s.sources.inbox_rules.records.Count -eq 0)}
}
$r=Fixture;$r.Collections[2].Status='Denied';Check 'mixed delegate coverage partial' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.delegates.status -eq 'partial')
$r=Fixture;foreach($c in $r.Collections){$c.Status='Denied'};Check 'all delegates denied' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.delegates.status -eq 'denied')
$r=Fixture;$r.Collections[0].Items[0].PSObject.Properties.Remove('ForwardingAddress');Check 'missing forwarding field partial' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.forwarding.status -eq 'partial')
$r=Fixture;$r.Collections[0].Items[0].PSObject.Properties.Remove('GrantSendOnBehalfTo');Check 'missing behalf field partial' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.delegates.status -eq 'partial')
$r=Fixture;$r.Collections[1].Kind='Historical';Check 'historical not relabeled current' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$r.Collections+=@($r.Collections[1]);Check 'duplicate source refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$r.Collections[0].Items[0].UserPrincipalName='different@contoso.example';Check 'mismatched mailbox export refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$r.Collections[0].Items[0].PSObject.Properties.Remove('UserPrincipalName');Check 'missing canonical UPN refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;Check 'empty tenant refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r ([guid]::Empty)})
$r.Metadata.TargetUpn='*@contoso.example';Check 'wildcard refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$r.Mode='unknown';Check 'unknown provenance refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$r.Metadata.CollectionFinishedUtc='yesterday';Check 'bad timestamp refused' (Rejects {ConvertTo-ToolkitMailboxSnapshot $r $tenant})
$r=Fixture;$dir=Join-Path $root ('test-output/snapshot-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$file=Join-Path $dir 'synthetic.json';$null=Export-ToolkitMailboxSnapshot $r $tenant $file
$disk=Get-Content $file -Raw|ConvertFrom-Json
Check 'JSON roundtrip arrays' ($disk.sources.inbox_rules.records -is [array] -and $disk.synthetic)
Check 'no overwrite' (Rejects {Export-ToolkitMailboxSnapshot $r $tenant $file})
Check 'no implicit parent creation' (Rejects {Export-ToolkitMailboxSnapshot $r $tenant (Join-Path $dir 'missing/file.json')})
# Injected transport: strictly no Microsoft/network calls.
$state=@{Reads=[Collections.Generic.List[object]]::new();Mismatch=$false;DenyRules=$false;WrongMailbox=$false;Cap=$false}
$rt=@{
 Local={param($c,$p)if($c -ne 'Get-ConnectionInformation'){throw 'Unexpected Graph/local command'};@{TenantID=$(if($state.Mismatch){'99999999-2222-3333-4444-555555555555'}else{$tenant.ToString()});UserPrincipalName='operator@contoso.example';State='Connected';TokenStatus='Active';CertificateAuthentication=$false;IsEopSession=$false;ModulePrefix='';DelegatedOrganization='';ModuleName='Mock';ConnectionUri='https://outlook.office365.com/powershell-liveid/'}}.GetNewClosure()
 ReadCommand={param($c,$p,$session)
  $state.Reads.Add(@{Command=$c;Parameters=$p})
  switch($c){
   'Get-Mailbox' {return @{UserPrincipalName=$(if($state.WrongMailbox){'wrong@contoso.example'}else{$p.Identity});ForwardingAddress=$null;ForwardingSmtpAddress=$null;DeliverToMailboxAndForward=$false;GrantSendOnBehalfTo=@()}}
   'Get-InboxRule' {if($state.DenyRules){throw 'Access denied'};if($state.Cap){return @(1..1000|ForEach-Object {@{Identity="rule-$_"}})};return @()}
   'Get-MailboxPermission' {return @()}
   'Get-RecipientPermission' {return @()}
   default {throw 'Unexpected wider read'}
  }
 }.GetNewClosure()
 Connect={throw 'No authentication allowed in test'}
}
$r=Invoke-ToolkitCurrentMailboxSnapshot $rt $tenant 'operator@contoso.example' 'alex@contoso.example'
Check 'exact four source reads' (($state.Reads.Command -join ',') -ceq 'Get-Mailbox,Get-InboxRule,Get-MailboxPermission,Get-RecipientPermission')
Check 'one exact target each read' (@($state.Reads|Where-Object {($_.Parameters.Identity -ne 'alex@contoso.example') -and ($_.Parameters.Mailbox -ne 'alex@contoso.example')}).Count -eq 0)
Check 'hidden rules bounded' ($state.Reads[1].Parameters.IncludeHidden -and $state.Reads[1].Parameters.ResultSize -eq 1000)
Check 'current only' (@($r.Collections|Where-Object Kind -ne 'CurrentSnapshot').Count -eq 0)
$state.Reads.Clear();$state.Mismatch=$true
Check 'mismatched tenant aborts' (Rejects {Invoke-ToolkitCurrentMailboxSnapshot $rt $tenant 'operator@contoso.example' 'alex@contoso.example'})
Check 'mismatched tenant no provider calls' ($state.Reads.Count -eq 0)
$state.Mismatch=$false;$state.WrongMailbox=$true
Check 'wrong mailbox aborts' (Rejects {Invoke-ToolkitCurrentMailboxSnapshot $rt $tenant 'operator@contoso.example' 'alex@contoso.example'})
Check 'wrong mailbox stops after resolution' ($state.Reads.Count -eq 1)
$state.Reads.Clear();$state.WrongMailbox=$false;$state.DenyRules=$true
$r=Invoke-ToolkitCurrentMailboxSnapshot $rt $tenant 'operator@contoso.example' 'alex@contoso.example'
Check 'denied rule source preserved' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.inbox_rules.status -eq 'denied')
$state.DenyRules=$false;$state.Cap=$true
$r=Invoke-ToolkitCurrentMailboxSnapshot $rt $tenant 'operator@contoso.example' 'alex@contoso.example'
Check 'rule cap explicitly partial' ((ConvertTo-ToolkitMailboxSnapshot $r $tenant).sources.inbox_rules.status -eq 'partial')
$summary=[pscustomobject]@{Passed=$true;Checks=$checks.Count;LiveTenantTested=$false;ProviderCalls='Injected mocks only';ChecksDetail=$checks}
if($ResultsPath){$summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultsPath}
$summary
