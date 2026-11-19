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
    param([hashtable]$Runtime,[ValidateSet('Live')][string]$Mode,[guid]$TenantId,[string]$Account,[ValidateSet('Graph','Exchange')][string]$PrimaryService='Graph',[switch]$Workbook)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live workflow requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    Import-Module (Join-Path $script:ToolkitRoot 'Audit/M365SecurityAudit.psm1') -DisableNameChecking
    $plan=Get-M365OrganizationAuditPlan -Workbook:$Workbook
    if($Workbook) {
        Write-ToolkitText $Runtime ('WORKBOOK: current settings plus selected registration and last successful sign-in timestamps, not sign-in events or mailbox content. '+$plan.Sources.Count+' planned sources.')
        Write-ToolkitText $Runtime 'Stored mail settings will be compared with Microsoft Standard recommendations; preset assignment and effective protection are not evaluated.'
        Write-ToolkitText $Runtime 'Optional identity evidence needs existing AuditLog.Read.All and applicable user scope and roles. This mode never requests or broadens permissions. Selected SharePoint tenant settings require existing SharePointTenantSettings.Read.All and supported role. Native Teams and SharePoint/OneDrive PowerShell snapshots are separate, unverified supplemental evidence.'
    }else{
        Write-ToolkitText $Runtime 'AUDIT: organization-wide CURRENT configuration, not mailbox logs. All 46 supported policy/configuration sources are selected; this is not every M365 setting or a compliance certification.'
    }
    Write-ToolkitText $Runtime ('Tenant: '+$TenantId+' | Operator: '+(ConvertTo-ToolkitText $Account))
    Write-ToolkitText $Runtime 'Component sessions: Graph for identity/configuration reads; Exchange for messaging policies; Purview requires an existing approved matching session. Missing components remain independent coverage gaps.'
    Write-ToolkitText $Runtime 'Includes Conditional Access, identity/consent policies, roles, limited Intune metadata, Exchange protection and selected Purview settings. No writes or content collection. Missing privileges/licensing remain explicit gaps.'
    Write-ToolkitText $Runtime ('Graph read permissions used only if already present: '+($plan.GraphReadPermissions -join ', '))
    Write-ToolkitText $Runtime 'Uses existing matching sessions only. Missing scopes/modules/providers are skipped and reported. No new sign-in, consent, scope expansion or automatic files.'
    $requiredConfirmation=if($Workbook){'WORKBOOK'}else{'AUDIT'}
    $confirm=Read-ToolkitInput $Runtime ('Type '+$requiredConfirmation+' to authorize these organization-wide reads for the displayed tenant, or Enter to cancel')
    if($confirm -cne $requiredConfirmation){Write-ToolkitText $Runtime 'Audit canceled before authentication changes, queries or file creation.';return}
    Assert-ToolkitPrimarySession $Runtime $TenantId $Account $PrimaryService
    $parameters=@{Mode=$Mode;TenantId=$TenantId;ExpectedAccount=$Account;ConfirmedTenantId=$TenantId;ConfirmOrganizationWide=$true}
    if($Workbook){$parameters.Workbook=$true;$parameters.WorkbookAntiPhishBaseline='Standard'}
    $result=Invoke-M365OrganizationAudit @parameters
    # Summary is generated locally from safe metadata, never raw terminal control sequences.
    Write-M365AuditSummary -Result $result
    $gaps=@($result.Coverage | Where-Object {$_.Status -notin @('Collected','NotSelected')})
    if($gaps.Count){
        $groups=@($gaps | Group-Object Status | ForEach-Object {$_.Name+': '+$_.Count})
        Write-ToolkitText $Runtime ('Coverage gaps ('+$gaps.Count+'): '+($groups -join '; ')+'. View @coverage for source-level reasons; unknown is not a pass.')
    }
    return $result
}
function Invoke-ToolkitLogsWorkflow {
    param([hashtable]$Runtime,[ValidateSet('Live')][string]$Mode,[guid]$TenantId,[string]$Account,[ValidateSet('Graph','Exchange')][string]$PrimaryService='Graph')
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live workflow requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
    Import-Module (Join-Path $script:ToolkitRoot 'Logs/M365Bec.psm1') -DisableNameChecking
    Write-ToolkitText $Runtime 'PULL LOGS: exact selected mailboxes only. No tenant-wide UAL/directory audit/grant inventory, message bodies or attachments. Delegate/admin activity may therefore be missing.'
    $inputTargets=Read-ToolkitInput $Runtime 'Exact usernames/UPNs/emails, separated by commas (maximum 50)'
    $domain=''
    if(@($inputTargets -split '[,;\r\n]+' | Where-Object {$_ -and -not $_.Contains('@')}).Count){$domain=Read-ToolkitInput $Runtime 'Exact UPN suffix for bare usernames (required; not guessed)'}
    $targets=ConvertTo-ToolkitTargets $inputTargets $domain
    $now=[DateTimeOffset]::UtcNow
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
    # Results remain in memory; saving is a separate explicit menu action.
    Write-ToolkitText $Runtime 'Uses existing matching Graph/Exchange sessions only. Missing scopes/providers remain source-level gaps; no reconnect or consent request.'
    Assert-ToolkitPrimarySession $Runtime $TenantId $Account $PrimaryService
    $results=[Collections.Generic.List[object]]::new()
    foreach($target in $targets){
        try{
            $parameters=@{TargetUpn=$target;Start=$window.Start;End=$window.End;Mode='Live';ProjectRoot=$script:ToolkitRoot;IncludeDefender=$defender;IncludeNonInteractivePreview=$preview}
            # Each mailbox receives an isolated, bound transport and independent request log.
            $transport=New-ToolkitMailboxTransport $Runtime $TenantId $Account $target
            $parameters.Context=New-BecContext -Transport $transport
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
    param([ValidateSet('Live')][string]$Mode,[hashtable]$Runtime)
    if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'The live terminal requires an explicit -Mode Live. No session was inspected or opened and nothing was collected or written.'}
    if(-not $Runtime){$Runtime=New-ToolkitRuntime}
    Write-ToolkitText $Runtime 'FLAPJACKS | PowerShell 7.4+ | Read-only review build'
    Write-ToolkitText $Runtime 'No localhost, local listener, browser launch or HTML UI. All workflow and triage are in this terminal; explicit menu S saves the latest in-memory result as local JSON; P saves an Audit Posture Report with PDF, Excel, CSV and local evidence.'
    Write-ToolkitText $Runtime 'Admin means an approved operator with scoped READ roles, not a request for Global Administrator. No automatic consent, escalation, remediation or external uploads.'
    Write-ToolkitText $Runtime 'Official device-code authentication still requires approval on a Microsoft web page using an approved browser/device. Tenant policy can block it; this app will not bypass that restriction.'
    $pendingAction=''
    Import-Module (Join-Path $script:ToolkitRoot 'Audit/M365SecurityAudit.psm1') -DisableNameChecking
    $startupPlan=Get-M365OrganizationAuditPlan
    Write-ToolkitText $Runtime ('Optional A = Graph Audit sign-in: tenant-wide configuration READ access: '+($startupPlan.GraphReadPermissions -join ', '))
    Write-ToolkitText $Runtime 'Choose A only if this access is already approved. Stop at any new Microsoft consent request. It proceeds to the same tenant-bound AUDIT authorization; no reads occur before you approve. G is identity-only (User.Read), so configuration sources may be skipped. Existing Exchange/Purview sessions are never opened automatically.'
    try{$choice=Read-ToolkitInput $Runtime 'G = Microsoft Graph identity-only device sign-in; A = Graph Audit approved-read sign-in; E = Exchange device sign-in; R = reuse; Q or Enter = quit'}
    catch{Write-ToolkitText $Runtime 'Startup canceled; no Microsoft session was inspected or opened.';return}
    if([string]::IsNullOrWhiteSpace($choice) -or $choice -ieq 'Q'){return}
    if($choice -ieq 'G'){$resolved=Connect-ToolkitInitialSession $Runtime Graph}
    elseif($choice -ieq 'A'){$resolved=Connect-ToolkitInitialSession $Runtime Graph -AuditReadAccess;$pendingAction='A'}
    elseif($choice -ieq 'E'){$resolved=Connect-ToolkitInitialSession $Runtime Exchange}
    elseif($choice -ieq 'R'){
        try{$provider=Read-ToolkitInput $Runtime 'Reuse G = Graph or E = Exchange session; Q or Enter = quit'}
        catch{Write-ToolkitText $Runtime 'Startup canceled; no Microsoft session was inspected or opened.';return}
        if([string]::IsNullOrWhiteSpace($provider) -or $provider -ieq 'Q'){return}
        if($provider -ieq 'G'){$resolved=Resolve-ToolkitGraphContext $Runtime}
        elseif($provider -ieq 'E'){$resolved=Resolve-ToolkitExchangeContext $Runtime}
        else{throw 'Unknown session provider.'}
    }else{throw 'Unknown sign-in choice.'}
    $tenant=$resolved.TenantId;$account=$resolved.Account;$primary=$resolved.Service
    Write-ToolkitText $Runtime ('Authenticated '+$primary+' operator: '+(ConvertTo-ToolkitText $account))
    Write-ToolkitText $Runtime ('Organization / tenant ID verified by '+$primary+': '+$tenant)
    Write-ToolkitText $Runtime 'This context comes from the authenticated Microsoft session, not a typed tenant ID or inferred email domain. Every additional component must match this tenant and account. Actions use existing approved access only; missing capabilities are reported, never silently expanded.'
    Assert-ToolkitPrimarySession $Runtime $tenant $account $primary
    $history=[Collections.Generic.List[object]]::new()
    while($true){
        if($pendingAction){$action=$pendingAction;$pendingAction=''}else{$action=Read-ToolkitInput $Runtime 'A = Audit organization configuration; W = extended workbook posture (existing access only); L = Pull Logs; V = view latest result; S = save latest JSON; P = save Audit posture bundle; Q = quit'}
        if($action -ieq 'Q' -or -not $action){break}
        try{
            if($action -in @('A','W','L')){Assert-ToolkitPrimarySession $Runtime $tenant $account $primary}
            switch($action.ToUpperInvariant()){
                'A' {$result=Invoke-ToolkitAuditWorkflow $Runtime $Mode $tenant $account -PrimaryService $primary;if($null -ne $result){$history.Add($result)}}
                'W' {$result=Invoke-ToolkitAuditWorkflow $Runtime $Mode $tenant $account -PrimaryService $primary -Workbook;if($null -ne $result){$history.Add($result)}}
                'L' {$result=Invoke-ToolkitLogsWorkflow $Runtime $Mode $tenant $account -PrimaryService $primary;if($null -ne $result){$history.Add($result)}}
                'S' {if($history.Count){Save-ToolkitResult $history[$history.Count-1] $Runtime}else{Write-ToolkitText $Runtime 'No in-memory result to save.'}}
                'P' {if($history.Count){Save-ToolkitPostureBundle $history[$history.Count-1] $Runtime}else{Write-ToolkitText $Runtime 'No in-memory result to save.'}}
                'V' {if($history.Count){Show-ToolkitResult $history[$history.Count-1] $Runtime}else{Write-ToolkitText $Runtime 'No in-memory result to inspect.'}}
                default {Write-ToolkitText $Runtime 'Choose A, W, L, V, S, P or Q. No action performed.'}
            }
        }catch{Write-ToolkitText $Runtime ('Action stopped safely: '+(ConvertTo-ToolkitText $_.Exception.Message)+'. No fallback or permission grant was attempted.')}
    }
    Write-ToolkitText $Runtime 'Finished. Unsaved in-memory results are no longer available after process exit. Existing Microsoft sessions were not disconnected or modified by cleanup.'
    return ,$history.ToArray()
}

function Save-ToolkitResult {
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)][hashtable]$Runtime)
    Write-ToolkitText $Runtime 'Save the latest existing result only; no new collection. JSON may contain sensitive identities, policy targeting and mailbox metadata. Use approved private local storage; no encryption or permission changes are provided.'
    $path=Read-ToolkitInput $Runtime 'New local JSON file path (existing private directory), or Enter to cancel'
    if(-not $path){Write-ToolkitText $Runtime 'Save canceled; no file created.';return}
    $full=[IO.Path]::GetFullPath($path);$parent=[IO.Path]::GetDirectoryName($full)
    if(-not [IO.Directory]::Exists($parent)){throw 'Choose an existing private local directory.'}
    for($p=$parent;$p;$p=[IO.Path]::GetDirectoryName($p)){
        if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Symlink/reparse export directory refused.'}
    }
    $json=ConvertTo-Json -InputObject $Result -Depth 100 -WarningAction Stop
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
    Write-ToolkitText $Runtime ('Saved local JSON: '+$full)
}

function Save-ToolkitPostureBundle {
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)][hashtable]$Runtime)
    if($null -eq $Result.PSObject.Properties['Evidence'] -or $null -eq $Result.PSObject.Properties['Metadata']){throw 'Posture export requires the latest Audit result, not mailbox Logs. Run Audit explicitly first.'}
    Write-ToolkitText $Runtime 'Save existing Audit only: local CSV/JSON evidence, Excel and display-only posture PDF. No collection or authentication. Evidence may contain sensitive identities and policy targeting; use approved private local storage. No encryption or permission changes.'
    $path=Read-ToolkitInput $Runtime 'NEW posture bundle directory under an existing private directory, or Enter to cancel'
    if(-not $path){Write-ToolkitText $Runtime 'Posture save canceled; no files created.';return}
    Import-Module (Join-Path $script:ToolkitRoot 'Audit/M365SecurityAudit.psm1') -DisableNameChecking
    $saved=Export-FlapjacksPostureBundle -Result $Result -OutputDirectory $path
    Write-ToolkitText $Runtime ('Saved local posture bundle: '+(ConvertTo-ToolkitText $saved.OutputDirectory)+'. Unavailable evidence stays Not assessed. Not a compliance verdict.')
}
