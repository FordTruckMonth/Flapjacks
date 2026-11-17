function Invoke-ToolkitAuthenticationCommand {
    # Device-code instructions may be emitted on the success stream. Render them
    # immediately at this boundary, before callers capture the resolved session.
    # Never collect, persist, parse, or forward authentication output as result data.
    param([Parameter(Mandatory)]$Command,[Parameter(Mandatory)][hashtable]$Parameters)
    & $Command @Parameters -ErrorAction Stop | Out-Host
}
function New-ToolkitRuntime {
    @{Read={param($prompt)Read-Host $prompt};Write={param($text)Write-Host $text};
      Local={param($command,$parameters)
        $map=@{'Get-MgContext'='Microsoft.Graph.Authentication\Get-MgContext';'Get-ConnectionInformation'='ExchangeOnlineManagement\Get-ConnectionInformation'}
        if(-not $map.ContainsKey($command)){throw 'Local session command not allowed'}
        & $map[$command] @parameters -ErrorAction Stop
      };
      Connect={param($service,$parameters)
        $module=if($service -eq 'Graph'){'Microsoft.Graph.Authentication'}elseif($service -eq 'Exchange'){'ExchangeOnlineManagement'}else{throw 'Unsupported device-code service'}
        Import-Module $module -ErrorAction Stop
        $name=if($service -eq 'Graph'){'Microsoft.Graph.Authentication\Connect-MgGraph'}else{'ExchangeOnlineManagement\Connect-ExchangeOnline'}
        $command=Get-Command $name -ErrorAction Stop
        foreach($key in $parameters.Keys){if(-not $command.Parameters.ContainsKey($key)){throw 'Installed Microsoft module lacks required device-code parameters; no fallback attempted.'}}
        $connectParameters=$parameters.Clone()
        if($service -eq 'Graph' -and $command.Parameters.ContainsKey('NoWelcome')){$connectParameters.NoWelcome=$true}
        Invoke-ToolkitAuthenticationCommand -Command $command -Parameters $connectParameters
      };
      ReadCommand={param($command,$parameters,$session)
        if($command -eq 'Get-MgContext'){return Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop}
        if($command -eq 'Invoke-MgGraphRequest'){return Microsoft.Graph.Authentication\Invoke-MgGraphRequest @parameters -ErrorAction Stop}
        $cmd=Get-Command -Name $command -CommandType Function,Cmdlet -ErrorAction Stop | Select-Object -First 1
        $expected=[string](Get-ToolkitValue $session 'ModuleName' '')
        $actualName=[string]$cmd.ModuleName;$actualPath=if($cmd.Module){[string]$cmd.Module.Path}else{''}
        $base=[IO.Path]::GetFileName($expected)
        if(-not $expected -or (-not ($actualName -ceq $base) -and -not ($actualPath -ceq $expected) -and -not $actualPath.StartsWith($expected+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal))){throw 'Read cmdlet is not bound to the verified Exchange REST session; refused.'}
        & $cmd @parameters -ErrorAction Stop
      }}
}
function Resolve-ToolkitGraphContext {
    param([hashtable]$Runtime)
    $context=& $Runtime.Local 'Get-MgContext' @{}
    if(-not $context){throw 'No Graph session. Use approved Microsoft device-code sign-in or reuse a connected session.'}
    if((Get-ToolkitValue $context 'AuthType') -ne 'Delegated' -or (Get-ToolkitValue $context 'Environment') -ne 'Global'){throw 'This workflow requires a delegated operator session in Microsoft Global cloud.'}
    $tenant=[guid]::Empty;$account=[string](Get-ToolkitValue $context 'Account' '')
    if(-not [guid]::TryParse([string](Get-ToolkitValue $context 'TenantId' ''),[ref]$tenant) -or $tenant -eq [guid]::Empty -or -not (Test-ToolkitAddress $account)){
        throw 'Graph did not return a reliable authenticated TenantId and operator account. No collection allowed. Reconnect with an approved Microsoft.Graph.Authentication module and inspect Get-MgContext; do not substitute a manually guessed tenant.'
    }
    return [pscustomobject]@{Service='Graph';TenantId=$tenant;Account=$account;Context=$context}
}
function Assert-ToolkitGraphSession {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account)
    $resolved=Resolve-ToolkitGraphContext $Runtime
    if($resolved.TenantId -ne $TenantId){throw 'Graph tenant mismatch; no collection allowed.'}
    if($resolved.Account -ine $Account){throw 'Graph operator account mismatch; no collection allowed.'}
    return $resolved.Context
}
function Resolve-ToolkitExchangeContext {
    param([hashtable]$Runtime,[switch]$Purview)
    $connections=@(& $Runtime.Local 'Get-ConnectionInformation' @{})
    $active=@($connections | Where-Object {(Get-ToolkitValue $_ 'State') -eq 'Connected' -and [bool](Get-ToolkitValue $_ 'IsEopSession' $false) -eq [bool]$Purview})
    if($active.Count -ne 1){throw 'Exactly one active REST session for the selected workload is required; missing/ambiguous connections refused.'}
    $connection=$active[0]
    if((Get-ToolkitValue $connection 'DelegatedOrganization') -or (Get-ToolkitValue $connection 'ModulePrefix') -or (Get-ToolkitValue $connection 'TokenStatus') -ne 'Active'){throw 'Require an active unprefixed, non-delegated REST session; no collection allowed.'}
    $certificate=Get-ToolkitValue $connection 'CertificateAuthentication'
    if($null -eq $certificate -or [bool]$certificate){throw 'This workflow requires documented delegated-user authentication, not a certificate/app-only or unknown session.'}
    $uri=[uri](Get-ToolkitValue $connection 'ConnectionUri' '')
    $allowedHost=if($Purview){'ps.compliance.protection.outlook.com'}else{'outlook.office365.com'}
    if(-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Host -ine $allowedHost -or $uri.Port -ne 443){throw 'Unsupported Exchange service endpoint; Microsoft Global cloud only.'}
    $tenant=[guid]::Empty
    $account=[string](Get-ToolkitValue $connection 'UserPrincipalName' '')
    if(-not [guid]::TryParse([string](Get-ToolkitValue $connection 'TenantID' ''),[ref]$tenant) -or $tenant -eq [guid]::Empty -or -not (Test-ToolkitAddress $account)){
        throw 'Exchange did not return a reliable TenantID GUID and operator UPN. No collection allowed. Use an approved current ExchangeOnlineManagement module in a clean PowerShell 7 session, reconnect with -Device, and inspect Get-ConnectionInformation. Do not substitute a manually guessed tenant.'
    }
    # Organization is documented as the CBA/managed-identity input, not a delegated tenant name.
    # The authenticated TenantID is authoritative; do not infer organization from the UPN suffix.
    return [pscustomobject]@{Service='Exchange';TenantId=$tenant;Account=$account;Connection=$connection}
}
function Assert-ToolkitExchangeSession {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account,[switch]$Purview)
    $resolved=Resolve-ToolkitExchangeContext $Runtime -Purview:$Purview
    if($resolved.TenantId -ne $TenantId -or $resolved.Account -ine $Account){throw 'Exchange/Purview tenant or operator account mismatch; no collection allowed.'}
    return $resolved.Connection
}
function Connect-ToolkitDevice {
    param([hashtable]$Runtime,[ValidateSet('Graph','Exchange')][string]$Service,[guid]$TenantId=[guid]::Empty,[string]$Account,[string[]]$Scopes=@())
    Write-ToolkitText $Runtime 'Microsoft will show a device code and approval URL. Complete MFA on an approved device/browser. No browser is launched by this app. Never enter a password here.'
    Write-ToolkitText $Runtime 'Use only already-approved access. If new consent or a Conditional Access block appears, stop. No grants, policy changes or fallback are performed.'
    if($Service -eq 'Graph'){
        if($TenantId -eq [guid]::Empty -or -not (Test-ToolkitAddress $Account)){throw 'Graph connection requires the confirmed tenant and operator account.'}
        $allowed=@('User.Read','AuditLog.Read.All','Directory.Read.All','IdentityRiskEvent.Read.All','Policy.Read.ConditionalAccess','ThreatHunting.Read.All','Policy.Read.All','Policy.Read.AuthenticationMethod','Policy.Read.PermissionGrant','RoleManagement.Read.Directory','RoleEligibilitySchedule.Read.Directory','Domain.Read.All','LicenseAssignment.Read.All','DeviceManagementConfiguration.Read.All')
        if(-not $Scopes.Count -or @($Scopes | Where-Object {$_ -cnotin $allowed}).Count){throw 'Only explicit supported read scopes can be requested.'}
        & $Runtime.Connect 'Graph' @{UseDeviceCode=$true;ContextScope='Process';TenantId=$TenantId.ToString();Scopes=$Scopes}
        $null=Assert-ToolkitGraphSession $Runtime $TenantId $Account
    }else{
        # -UserPrincipalName is not used as proof of identity; verify the returned REST session.
        & $Runtime.Connect 'Exchange' @{Device=$true}
        $resolved=Resolve-ToolkitExchangeContext $Runtime
        if(($TenantId -ne [guid]::Empty -and $resolved.TenantId -ne $TenantId) -or ($Account -and $resolved.Account -ine $Account)){throw 'Exchange sign-in returned a different tenant or account; no collection allowed.'}
        return $resolved
    }
}
function Connect-ToolkitInitialSession {
    param([hashtable]$Runtime,[ValidateSet('Graph','Exchange')][string]$Service,[switch]$AuditReadAccess)
    if($Service -eq 'Exchange'){return Connect-ToolkitDevice $Runtime Exchange}
    Write-ToolkitText $Runtime 'Microsoft will show a device code and approval URL. Complete sign-in/MFA on an approved Microsoft page using a browser/device. No browser is launched and no password is collected here.'
    $scopes=@('User.Read')
    if($AuditReadAccess){
        Import-Module (Join-Path $script:ToolkitRoot 'Audit/M365SecurityAudit.psm1') -DisableNameChecking
        $scopes=@((Get-M365OrganizationAuditPlan).GraphReadPermissions)
        Write-ToolkitText $Runtime ('Explicit Graph Audit sign-in uses only the displayed already-approved read access: '+($scopes -join ', '))
    }else{Write-ToolkitText $Runtime 'Identity-only Graph sign-in uses User.Read; Audit sources needing other permissions will be skipped.'}
    Write-ToolkitText $Runtime 'If Microsoft requests NEW consent or Conditional Access blocks access, STOP. No grant, automatic expansion or fallback is performed.'
    # TenantId is optional in this documented delegated parameter set. The authenticated
    # context, not an operator-entered GUID or inferred email domain, supplies the tenant.
    & $Runtime.Connect 'Graph' @{UseDeviceCode=$true;ContextScope='Process';Scopes=$scopes}
    return Resolve-ToolkitGraphContext $Runtime
}
function Assert-ToolkitPrimarySession {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account,[ValidateSet('Graph','Exchange')][string]$Service)
    if($Service -eq 'Graph'){$null=Assert-ToolkitGraphSession $Runtime $TenantId $Account}
    else{$null=Assert-ToolkitExchangeSession $Runtime $TenantId $Account}
}
function Request-ToolkitGraphScopes {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account,[string[]]$Scopes)
    $context=$null
    try{$context=Assert-ToolkitGraphSession $Runtime $TenantId $Account}catch{
        Write-ToolkitText $Runtime 'No verified Graph session matching the confirmed tenant and operator. Graph sources remain unavailable unless you explicitly sign in below.'
    }
    $current=if($context){@(Get-ToolkitValue $context 'Scopes' @())}else{@()}
    $missing=@($Scopes | Where-Object {$_ -notin $current})
    if($context -and -not $missing.Count){return}
    Write-ToolkitText $Runtime ('Action-specific Graph read scopes needed: '+($missing -join ', '))
    $answer=Read-ToolkitInput $Runtime 'D = Graph device sign-in for these already-approved read scopes; S = skip unavailable Graph sources [S]'
    if($answer -ieq 'D'){$null=Connect-ToolkitDevice $Runtime Graph $TenantId $Account -Scopes ($Scopes | Sort-Object -Unique)}
    elseif($answer -and $answer -ine 'S'){throw 'Unknown scope choice; no collection started.'}
}
function Request-ToolkitExchangeSession {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account)
    try{$null=Assert-ToolkitExchangeSession $Runtime $TenantId $Account;return}catch{
        Write-ToolkitText $Runtime 'No acceptable matching Exchange session. Reuse requires one active, same-account/same-tenant Microsoft Global REST session.'
    }
    $answer=Read-ToolkitInput $Runtime 'D = approved Exchange device-code sign-in; S = skip Exchange sources [S]'
    if($answer -ieq 'D'){$null=Connect-ToolkitDevice $Runtime Exchange $TenantId $Account}
    elseif($answer -and $answer -ine 'S'){throw 'Unknown Exchange choice; no collection started.'}
}
function New-ToolkitMailboxTransport {
    param([hashtable]$Runtime,[guid]$TenantId,[string]$Account,[string]$Target)
    $allow=@('Get-Mailbox','Get-MailboxStatistics','Get-InboxRule','Get-MailboxPermission','Get-RecipientPermission','Get-CASMailbox','Get-MobileDeviceStatistics','Get-MailboxFolderStatistics','Get-MailboxFolderPermission','Get-MessageTraceV2','Get-MessageTraceDetailV2','Get-MgContext','Invoke-MgGraphRequest')
    return {param($command,$parameters)
        if($command -notin $allow){throw 'Organization-wide or unsupported command refused in Pull Logs.'}
        if($command -in @('Get-MgContext','Invoke-MgGraphRequest')){
            $graph=Assert-ToolkitGraphSession $Runtime $TenantId $Account
            if($command -eq 'Get-MgContext'){return $graph}
            $uri=[uri]$parameters.Uri
            if($uri.Scheme -ne 'https' -or $uri.Host -ine 'graph.microsoft.com' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment){throw 'Unsupported Graph endpoint refused.'}
            if($uri.AbsolutePath -ceq '/v1.0/security/runHuntingQuery'){
                if($parameters.Method -cne 'POST'){throw 'Hunting permits only the documented read-only POST operation.'}
            }elseif($parameters.Method -cne 'GET'){throw 'Only read-only Graph GET operations are allowed for mailbox metadata.'}
            # Collector further checks exact target, path, filters, method and continuation scope.
            if($uri.AbsolutePath -notmatch '^/(v1\.0|beta)/(users/[^/]+(?:/oauth2PermissionGrants)?|auditLogs/signIns|identityProtection/riskDetections|security/runHuntingQuery)$'){throw 'Organization-wide Graph collection refused in Pull Logs.'}
            $required=if($uri.AbsolutePath -match '/signIns$'){'AuditLog.Read.All'}elseif($uri.AbsolutePath -match '/riskDetections$'){'IdentityRiskEvent.Read.All'}elseif($uri.AbsolutePath -match '/runHuntingQuery$'){'ThreatHunting.Read.All'}else{'Directory.Read.All'}
            if($required -notin @(Get-ToolkitValue $graph 'Scopes' @())){throw "Module unavailable: source needs already-approved $required; no request was made."}
            return & $Runtime.ReadCommand $command $parameters $null
        }
        $session=Assert-ToolkitExchangeSession $Runtime $TenantId $Account
        return & $Runtime.ReadCommand $command $parameters $session
    }.GetNewClosure()
}
