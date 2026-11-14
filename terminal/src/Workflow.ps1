function Get-ToolkitEvidenceRoot {
    param([hashtable]$Runtime,[string]$Operation)
    $answer=Read-ToolkitInput $Runtime 'Save optional local JSON/CSV evidence? Y/N [N]'
    if(-not $answer -or $answer -ieq 'N'){return $null}
    if($answer -ine 'Y'){throw 'Unknown evidence choice; nothing collected.'}
    $path=Join-Path $script:ToolkitRoot ('evidence/'+$Operation+'-'+[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    $probe=$path
    while($probe){
        if((Test-Path -LiteralPath $probe) -and ((Get-Item -LiteralPath $probe -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Evidence output refuses symlink/reparse directories.'}
        $probe=[IO.Path]::GetDirectoryName($probe)
    }
    Write-ToolkitText $Runtime ('Evidence will stay local under '+$path+'. Protect the directory; no encryption or permission changes are performed.')
    return $path
}
function Invoke-ToolkitAuditWorkflow {
    param([hashtable]$Runtime,[ValidateSet('Live','Synthetic')][string]$Mode,[guid]$TenantId,[string]$Account,[ValidateSet('Graph','Exchange')][string]$PrimaryService='Graph')
    Import-Module (Join-Path $script:ToolkitRoot 'Audit/M365SecurityAudit.psm1') -DisableNameChecking
    $plan=Get-M365OrganizationAuditPlan
    Write-ToolkitText $Runtime 'AUDIT: organization-wide CURRENT configuration, not mailbox logs. All 46 supported policy/configuration sources are selected; this is not every M365 setting or a compliance certification.'
    Write-ToolkitText $Runtime ('Tenant: '+$TenantId+' | Operator: '+(ConvertTo-ToolkitText $Account))
    Write-ToolkitText $Runtime 'Component sessions: Graph for identity/configuration reads; Exchange for messaging policies; Purview requires an existing approved matching session. Missing components remain independent coverage gaps.'
    Write-ToolkitText $Runtime 'Includes Conditional Access, identity/consent policies, roles, limited Intune metadata, Exchange protection and selected Purview settings. No writes or content collection. Missing privileges/licensing remain explicit gaps.'
    $confirm=Read-ToolkitInput $Runtime ('Type AUDIT '+$TenantId+' to confirm this exact tenant')
    if($confirm -cne ('AUDIT '+$TenantId)){Write-ToolkitText $Runtime 'Audit canceled before authentication changes, queries or file creation.';return}
    $scope=Read-ToolkitInput $Runtime 'Confirm you are authorized for these organization-wide configuration reads (Y/N) [N]'
    if($scope -ine 'Y'){Write-ToolkitText $Runtime 'Audit canceled before authentication changes, queries or file creation.';return}
    $output=Get-ToolkitEvidenceRoot $Runtime 'audit'
    if($Mode -eq 'Live'){
        Request-ToolkitGraphScopes $Runtime $TenantId $Account -Scopes @($plan.GraphReadPermissions)
        Request-ToolkitExchangeSession $Runtime $TenantId $Account
        Write-ToolkitText $Runtime 'Purview uses an existing same-account/same-tenant session only. No documented device-code switch is available; unavailable Purview sources are skipped.'
        Assert-ToolkitPrimarySession $Runtime $TenantId $Account $PrimaryService
    }
    $parameters=@{Mode=$Mode;TenantId=$TenantId;ExpectedAccount=$Account;ConfirmedTenantId=$TenantId;ConfirmOrganizationWide=$true}
    if($output){$parameters.OutputPath=$output}
    # Injectable adapter seam is used only by offline tests; the standard runtime has none.
    $result=if($Runtime.ContainsKey('AuditRun')){& $Runtime.AuditRun $parameters}else{Invoke-M365OrganizationAudit @parameters}
    # Summary is generated locally from safe metadata, never raw terminal control sequences.
    Write-M365AuditSummary -Result $result
    return $result
}
function Invoke-ToolkitLogsWorkflow {
    param([hashtable]$Runtime,[ValidateSet('Live','Synthetic')][string]$Mode,[guid]$TenantId,[string]$Account,[ValidateSet('Graph','Exchange')][string]$PrimaryService='Graph')
    Import-Module (Join-Path $script:ToolkitRoot 'Logs/M365Bec.psm1') -DisableNameChecking
    Write-ToolkitText $Runtime 'PULL LOGS: exact selected mailboxes only. No tenant-wide UAL/directory audit/grant inventory, message bodies or attachments. Delegate/admin activity may therefore be missing.'
    if($Mode -eq 'Synthetic'){Write-ToolkitText $Runtime 'Synthetic demo identity: alex@contoso.example. No account is contacted.'}
    $inputTargets=Read-ToolkitInput $Runtime 'Exact usernames/UPNs/emails, separated by commas (maximum 50)'
    $domain=''
    if(@($inputTargets -split '[,;\r\n]+' | Where-Object {$_ -and -not $_.Contains('@')}).Count){$domain=Read-ToolkitInput $Runtime 'Exact UPN suffix for bare usernames (required; not guessed)'}
    $targets=ConvertTo-ToolkitTargets $inputTargets $domain
    $now=if($Mode -eq 'Synthetic'){[DateTimeOffset]'2026-11-11T00:00:00Z'}else{[DateTimeOffset]::UtcNow}
    $period=Read-ToolkitInput $Runtime 'Lookback days 1-90 [7], or C for explicit UTC timestamps'
    if($period -ieq 'C'){
        $startText=Read-ToolkitInput $Runtime 'Start ISO timestamp with timezone (inclusive)'
        $endText=Read-ToolkitInput $Runtime 'End ISO timestamp with timezone (exclusive)'
        $window=ConvertTo-ToolkitWindow $startText $endText -Now $now
    }else{
        $days=7
        if($period -and (-not [int]::TryParse($period,[ref]$days) -or $days -lt 1 -or $days -gt 90)){throw 'Lookback must be 1-90 days.'}
        $window=@{Start=$now.AddDays(-$days);End=$now}
    }
    Write-ToolkitText $Runtime ('Targets: '+($targets -join ', '))
    Write-ToolkitText $Runtime ('UTC window ['+$window.Start.ToString('o')+', '+$window.End.ToString('o')+')')
    $answer=Read-ToolkitInput $Runtime 'Confirm authorized collection for only these exact mailboxes and dates (Y/N) [N]'
    if($answer -ine 'Y'){Write-ToolkitText $Runtime 'Mailbox collection canceled before queries or permission requests.';return}
    $defender=(Read-ToolkitInput $Runtime 'Include target-filtered Defender hunting metadata if already licensed/approved? Y/N [N]') -ieq 'Y'
    $preview=(Read-ToolkitInput $Runtime 'Include explicitly approved beta non-interactive USER sign-ins? Y/N [N]') -ieq 'Y'
    $output=Get-ToolkitEvidenceRoot $Runtime 'mailboxes'
    if($Mode -eq 'Live'){
        $scopes=@('AuditLog.Read.All','Directory.Read.All','IdentityRiskEvent.Read.All')
        if($defender){$scopes+='ThreatHunting.Read.All'}
        Request-ToolkitGraphScopes $Runtime $TenantId $Account -Scopes $scopes
        Request-ToolkitExchangeSession $Runtime $TenantId $Account
        Assert-ToolkitPrimarySession $Runtime $TenantId $Account $PrimaryService
    }
    $results=[Collections.Generic.List[object]]::new()
    foreach($target in $targets){
        try{
            $parameters=@{TargetUpn=$target;Start=$window.Start;End=$window.End;Mode=$(if($Mode -eq 'Synthetic'){'Fixture'}else{'Live'});FixturePath=(Join-Path $script:ToolkitRoot 'Logs/fixtures/bec-synthetic.json');ProjectRoot=$script:ToolkitRoot;IncludeDefender=$defender;IncludeNonInteractivePreview=$preview}
            if($output){$parameters.OutputRoot=$output}
            if($Mode -eq 'Live'){
                # Each mailbox receives an isolated, bound transport and independent request log.
                $transport=New-ToolkitMailboxTransport $Runtime $TenantId $Account $target
                $parameters.Context=New-BecContext -Transport $transport
            }
            $result=Invoke-BecInvestigation @parameters
            Write-ToolkitLogsSummary $result $Runtime
            $results.Add($result)
        }catch{
            Write-ToolkitText $Runtime ('Mailbox '+(ConvertTo-ToolkitText $target)+' failed: '+(ConvertTo-ToolkitText $_.Exception.Message)+'. No clean verdict is inferred.')
            $results.Add([pscustomobject]@{Target=$target;Failed=$true;Reason='Collection failed or input cannot be resolved exactly. Review terminal message.'})
        }
    }
    return ,$results.ToArray()
}
function Invoke-M365Terminal {
    [CmdletBinding()]
    param([ValidateSet('Live','Synthetic')][string]$Mode='Live',[hashtable]$Runtime)
    if(-not $Runtime){$Runtime=New-ToolkitRuntime}
    Write-ToolkitText $Runtime 'M365 TERMINAL TOOLKIT | PowerShell 7.4+ | Read-only review build'
    Write-ToolkitText $Runtime 'No localhost, local listener, browser launch or HTML UI. All workflow and triage are in this terminal; optional evidence is local JSON/CSV.'
    Write-ToolkitText $Runtime 'Admin means an approved operator with scoped READ roles, not a request for Global Administrator. No automatic consent, escalation, remediation or external uploads.'
    Write-ToolkitText $Runtime 'Official device-code authentication still requires approval on a Microsoft web page using an approved browser/device. Tenant policy can block it; this app will not bypass that restriction.'
    if($Mode -eq 'Synthetic'){
        $tenant=[guid]'11111111-2222-3333-4444-555555555555';$account='operator@contoso.example';$primary='Graph'
        Write-ToolkitText $Runtime 'SYNTHETIC MODE: no real sign-in, tenant or mailbox. Authentication and providers are not exercised.'
    }else{
        $choice=Read-ToolkitInput $Runtime 'G = Microsoft Graph device sign-in; E = Exchange Online device sign-in; R = reuse an existing session; Q = quit [G]'
        if($choice -ieq 'Q'){return}
        if(-not $choice -or $choice -ieq 'G'){$resolved=Connect-ToolkitInitialSession $Runtime Graph}
        elseif($choice -ieq 'E'){$resolved=Connect-ToolkitInitialSession $Runtime Exchange}
        elseif($choice -ieq 'R'){
            $provider=Read-ToolkitInput $Runtime 'Reuse G = Graph or E = Exchange session [G]'
            if(-not $provider -or $provider -ieq 'G'){$resolved=Resolve-ToolkitGraphContext $Runtime}
            elseif($provider -ieq 'E'){$resolved=Resolve-ToolkitExchangeContext $Runtime}
            else{throw 'Unknown session provider.'}
        }else{throw 'Unknown sign-in choice.'}
        $tenant=$resolved.TenantId;$account=$resolved.Account;$primary=$resolved.Service
        Write-ToolkitText $Runtime ('Authenticated '+$primary+' operator: '+(ConvertTo-ToolkitText $account))
        Write-ToolkitText $Runtime ('Organization / tenant ID verified by '+$primary+': '+$tenant)
        Write-ToolkitText $Runtime 'This context comes from the authenticated Microsoft session, not a typed tenant ID or inferred email domain. Every additional component must match this tenant and account. Action-specific permissions are deferred.'
        $confirm=Read-ToolkitInput $Runtime 'Use this resolved account and organization? Y/N [N]'
        if($confirm -ine 'Y'){Write-ToolkitText $Runtime 'Canceled before the action menu, additional sign-in, collection or evidence writes.';return}
        Assert-ToolkitPrimarySession $Runtime $tenant $account $primary
    }
    $history=[Collections.Generic.List[object]]::new()
    while($true){
        $action=Read-ToolkitInput $Runtime 'A = Audit organization configuration; L = Pull Logs; V = view latest in-memory result; Q = quit'
        if($action -ieq 'Q' -or -not $action){break}
        try{
            if($Mode -eq 'Live' -and $action -in @('A','L')){Assert-ToolkitPrimarySession $Runtime $tenant $account $primary}
            switch($action.ToUpperInvariant()){
                'A' {$result=Invoke-ToolkitAuditWorkflow $Runtime $Mode $tenant $account -PrimaryService $primary;if($null -ne $result){$history.Add($result)}}
                'L' {$result=Invoke-ToolkitLogsWorkflow $Runtime $Mode $tenant $account -PrimaryService $primary;if($null -ne $result){$history.Add($result)}}
                'V' {if($history.Count){Show-ToolkitResult $history[$history.Count-1] $Runtime}else{Write-ToolkitText $Runtime 'No in-memory result to inspect.'}}
                default {Write-ToolkitText $Runtime 'Choose A, L, V or Q. No action performed.'}
            }
        }catch{Write-ToolkitText $Runtime ('Action stopped safely: '+(ConvertTo-ToolkitText $_.Exception.Message)+'. No fallback or permission grant was attempted.')}
    }
    Write-ToolkitText $Runtime 'Finished. Unsaved in-memory results are no longer available after process exit. Existing Microsoft sessions were not disconnected or modified by cleanup.'
    return ,$history.ToArray()
}
