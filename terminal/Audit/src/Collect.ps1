function Test-AuditProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}
function Get-AuditProperty($Object, [string]$Name, $Default=$null) {
    if (Test-AuditProperty $Object $Name) { return ,($Object.$Name) }
    return ,$Default
}
function New-AuditResult($Source, [string]$Status, [string]$Reason='') {
    [pscustomobject]@{
        SourceId=$Source.Id; Group=$Source.Group; Provider=$Source.Provider; Target=$Source.Target
        Status=$Status; Reason=$Reason; CollectedAtUtc=[DateTime]::UtcNow.ToString('o')
        PageCount=0; RequestCount=0; Count=0; Items=@(); MissingFields=@(); Notes=$Source.Notes
    }
}
function Get-AuditHttpStatus($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    for ($i=0; $i -lt 5 -and $null -ne $ex; $i++) {
        if ($ex.Data.Contains('HttpStatus')) { return [int]$ex.Data['HttpStatus'] }
        foreach ($prop in @('ResponseStatusCode','StatusCode')) {
            $v = Get-AuditProperty $ex $prop
            if ($null -ne $v) { try { return [int]$v } catch {} }
        }
        $response = Get-AuditProperty $ex 'Response'
        $v = Get-AuditProperty $response 'StatusCode'
        if ($null -ne $v) { try { return [int]$v } catch {} }
        $ex = $ex.InnerException
    }
    return 0
}
function Get-AuditFailureName([int]$HttpStatus) {
    switch ($HttpStatus) {
        401 { 'Unauthorized' }
        403 { 'AccessDenied' }
        404 { 'Unavailable' }
        429 { 'Throttled' }
        default { 'Error' }
    }
}
function Get-AuditRetryDelay($ErrorRecord, [int]$Attempt) {
    # Honor Retry-After; do not retry sooner if a server asks for more than our wait budget.
    $ex=$ErrorRecord.Exception
    $value=$null
    if ($ex.Data.Contains('RetryAfter')) { $value=$ex.Data['RetryAfter'] }
    $headers=Get-AuditProperty (Get-AuditProperty $ex 'Response') 'Headers'
    if ($null -eq $value -and $null -ne $headers) {
        try { $value=@($headers.GetValues('Retry-After'))[0] } catch {}
    }
    if ($null -ne $value) {
        $seconds=0
        if ([int]::TryParse([string]$value,[ref]$seconds)) { return [Math]::Max(0,$seconds) }
        $date=[DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse([string]$value,[ref]$date)) {
            return [Math]::Max(0,[int][Math]::Ceiling(($date-[DateTimeOffset]::UtcNow).TotalSeconds))
        }
    }
    return [int][Math]::Pow(2,$Attempt+1)
}
function Test-AuditContinuation([string]$Next, [string]$Initial) {
    try {
        $nextUri=[uri]$Next; $initialUri=[uri]$Initial
        if (-not $nextUri.IsAbsoluteUri -or $nextUri.Scheme -cne 'https' -or
            $nextUri.Host -cne 'graph.microsoft.com' -or $nextUri.Port -ne 443 -or
            $nextUri.UserInfo -or $nextUri.Fragment -or
            $nextUri.AbsolutePath -cne $initialUri.AbsolutePath) { return $false }
        $original=@{}
        foreach ($pair in $initialUri.Query.TrimStart('?').Split('&',[StringSplitOptions]::RemoveEmptyEntries)) {
            $parts=$pair.Split('=',2); $original[[System.Net.WebUtility]::UrlDecode($parts[0])]=[System.Net.WebUtility]::UrlDecode($parts[-1])
        }
        $seen=@{}
        foreach ($pair in $nextUri.Query.TrimStart('?').Split('&',[StringSplitOptions]::RemoveEmptyEntries)) {
            $parts=$pair.Split('=',2); $key=[System.Net.WebUtility]::UrlDecode($parts[0]); $val=[System.Net.WebUtility]::UrlDecode($parts[-1])
            if ($seen.ContainsKey($key)) { return $false }; $seen[$key]=$true
            if ($key -in @('$skiptoken','$skip','$top')) { continue }
            if (-not $original.ContainsKey($key) -or $original[$key] -cne $val) { return $false }
        }
        # Metadata projections must survive continuation: never fetch secret-bearing settings on page 2.
        foreach ($key in $original.Keys) {
            if ($key -ne '$top' -and -not $seen.ContainsKey($key)) { return $false }
        }
        return $true
    } catch { return $false }
}
function Protect-AuditGraphItem($Source,$Item) {
    if ($Source.Group -eq 'WorkbookIdentity') { return Protect-FlapjacksWorkbookIdentityItem -Source $Source -Item $Item }
    if ($Source.Group -eq 'WorkbookCollaboration' -and $Source.Provider -eq 'Graph') { return Protect-FlapjacksWorkbookCollaborationItem -Source $Source -Item $Item }
    if ($Source.Group -ne 'Intune') { return $Item }
    # Intune policy objects can contain passwords or keys. Project again locally even when
    # the API is expected to honor $select; unexpected response fields never reach artifacts.
    $safe=[ordered]@{}
    foreach ($name in @('id','displayName','description','createdDateTime','lastModifiedDateTime','version')) {
        if (Test-AuditProperty $Item $name) { $safe[$name]=Get-AuditProperty $Item $name }
    }
    return [pscustomobject]$safe
}
function Read-AuditGraphSource {
    param($Source,[scriptblock]$Request,[scriptblock]$Sleep={param($Seconds) Start-Sleep -Seconds $Seconds},[int]$MaxPages=100,[int]$MaxRecords=50000)
    $r=New-AuditResult $Source 'Collected'
    $items=[System.Collections.Generic.List[object]]::new()
    $initial='https://graph.microsoft.com/v1.0'+$Source.Target
    $next=$initial; $seen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($next) {
        if (-not (Test-AuditContinuation $next $initial) -or -not $seen.Add($next)) { $r.Status='Partial'; $r.Reason='InvalidOrRepeatedContinuation'; break }
        if ($r.PageCount -ge $MaxPages) { $r.Status='Partial'; $r.Reason='PageLimit'; break }
        $page=$null; $success=$false
        for ($attempt=0; $attempt -le 3; $attempt++) {
            try {
                $r.RequestCount++
                $page=& $Request $next
                $success=$true; break
            } catch {
                $status=Get-AuditHttpStatus $_
                if ($status -in @(429,503,504) -and $attempt -lt 3) {
                    $delay=Get-AuditRetryDelay $_ $attempt
                    if ($delay -le 120) { & $Sleep $delay; continue }
                }
                $r.Status=Get-AuditFailureName $status
                $r.Reason=if ($status) { "HTTP$status; permission, role, licensing or service availability must be checked separately." } else { 'RequestFailed; details suppressed to avoid exporting account/session data.' }
                break
            }
        }
        if (-not $success) { if ($items.Count -gt 0) { $r.Reason=$r.Status+': '+$r.Reason; $r.Status='Partial' }; break }
        $r.PageCount++
        if ($null -eq $page -or (Test-AuditProperty $page 'error')) { $r.Status='Partial'; $r.Reason='InvalidResponse'; break }
        if ($Source.Shape -eq 'Singleton') {
            # Microsoft documents the SharePoint settings singleton inside a value object.
            # Permit that exact envelope for this source only, alongside an unwrapped object.
            if ($Source.Id -ceq 'workbook-sharepoint-settings' -and (Test-AuditProperty $page 'value')) {
                $outerNames=if($page -is [System.Collections.IDictionary]){@($page.Keys)}else{@($page.PSObject.Properties.Name)}
                if (@($outerNames | Where-Object {$_ -cnotin @('value','@odata.context','@odata.type')}).Count) { $r.Status='Partial'; $r.Reason='InvalidSharePointSingletonEnvelope'; break }
                $page=Get-AuditProperty $page 'value'
            }
            if ($null -eq $page -or $page -is [string] -or $page -is [ValueType] -or $page -is [array] -or
                (Test-AuditProperty $page 'error') -or (Test-AuditProperty $page '@odata.nextLink') -or (Test-AuditProperty $page 'value') -or
                ($page -is [System.Collections.IDictionary] -and $page.Count -eq 0) -or @($page.PSObject.Properties).Count -eq 0) {
                $r.Status='Partial'; $r.Reason='InvalidSingletonResponse'; break
            }
            $projected=Protect-AuditGraphItem $Source $page
            if ($Source.Id -ceq 'workbook-sharepoint-settings') {
                $missing=@($Source.Fields | Where-Object { -not (Test-AuditProperty $projected $_) })
                if($missing.Count){$r.Status='Partial';$r.Reason='SomeSelectedPropertiesUnavailable';$r.MissingFields=$missing}
            }
            $items.Add($projected); $next=$null
        } else {
            $values=Get-AuditProperty $page 'value'
            if (-not (Test-AuditProperty $page 'value') -or $null -eq $values -or
                $values -is [string] -or $values -is [System.Collections.IDictionary] -or
                $values -isnot [System.Collections.IEnumerable]) { $r.Status='Partial'; $r.Reason='InvalidCollectionResponse'; break }
            foreach ($item in $values) {
                if ($null -eq $item -or $item -is [string] -or $item -is [ValueType]) { $r.Status='Partial'; $r.Reason='InvalidCollectionItem'; break }
                if ($items.Count -ge $MaxRecords) { $r.Status='Partial'; $r.Reason='RecordLimit'; break }
                $items.Add((Protect-AuditGraphItem $Source $item))
            }
            if ($r.Status -ne 'Collected') { break }
            $next=[string](Get-AuditProperty $page '@odata.nextLink' '')
            if ($next -and $items.Count -ge $MaxRecords) { $r.Status='Partial'; $r.Reason='RecordLimit'; break }
        }
    }
    $r.Items=$items.ToArray(); $r.Count=$items.Count
    if ($r.Status -eq 'Collected' -and $Source.Id -eq 'authentication-methods-policy') {
        if ($r.Count -ne 1 -or -not (Test-AuditProperty $r.Items[0] 'authenticationMethodConfigurations') -or
            $null -eq (Get-AuditProperty $r.Items[0] 'authenticationMethodConfigurations') -or
            (Get-AuditProperty $r.Items[0] 'authenticationMethodConfigurations') -isnot [System.Collections.IEnumerable] -or
            (Get-AuditProperty $r.Items[0] 'authenticationMethodConfigurations') -is [string] -or
            (Get-AuditProperty $r.Items[0] 'authenticationMethodConfigurations') -is [System.Collections.IDictionary] -or
            (Get-AuditProperty $r.Items[0] 'authenticationMethodConfigurations@odata.nextLink')) {
            $r.Status='Partial'; $r.Reason='MissingExpandedAuthenticationMethodConfigurations'
        }
    }
    if ($r.Status -eq 'Collected' -and $Source.Id -eq 'permission-grant-policies') {
        foreach ($item in $r.Items) {
            foreach ($name in @('includes','excludes')) {
                if (-not (Test-AuditProperty $item $name) -or $null -eq (Get-AuditProperty $item $name) -or (Get-AuditProperty $item $name) -isnot [System.Collections.IEnumerable] -or (Get-AuditProperty $item $name) -is [string] -or (Get-AuditProperty $item $name) -is [System.Collections.IDictionary] -or (Get-AuditProperty $item "$name@odata.nextLink")) {
                    $r.Status='Partial'; $r.Reason='IncompleteExpandedPermissionGrantConditions'
                }
            }
        }
    }
    return $r
}
function Get-AuditGraphContext([guid]$TenantId,[string]$ExpectedAccount) {
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { return @{Status='ModuleUnavailable';Reason='Microsoft.Graph.Authentication is not installed; no installation attempted.'} }
    try { $context=Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop } catch { return @{Status='NotConnected';Reason='Cannot inspect an existing Graph session; no sign-in attempted.'} }
    return Test-AuditGraphIdentity $context $TenantId $ExpectedAccount
}
function Test-AuditGraphIdentity($Context,[guid]$TenantId,[string]$ExpectedAccount) {
    if ($null -eq $context) { return @{Status='NotConnected';Reason='No existing Graph session; no sign-in attempted.'} }
    if ((Get-AuditProperty $context 'TenantId') -ne $TenantId.ToString()) { return @{Status='TenantMismatch';Reason='Graph session tenant does not match -TenantId; no requests made.'} }
    if ((Get-AuditProperty $context 'Environment') -ne 'Global') { return @{Status='UnsupportedCloud';Reason='This release supports Microsoft global cloud only; no requests made.'} }
    if ((Get-AuditProperty $context 'AuthType') -ne 'Delegated') { return @{Status='IdentityMismatch';Reason='A delegated administrator-user Graph session is required; no requests made.'} }
    if (-not [string]::Equals([string](Get-AuditProperty $context 'Account'),$ExpectedAccount,[StringComparison]::OrdinalIgnoreCase)) { return @{Status='IdentityMismatch';Reason='Graph account does not match the confirmed administrator account; no requests made.'} }
    return @{Status='Ready';Reason='';Context=$context}
}

function Get-AuditCommandSession([guid]$TenantId,[string]$Provider,[string]$ExpectedAccount) {
    if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) { return @{Status='ModuleUnavailable';Reason='ExchangeOnlineManagement is not installed; no installation attempted.'} }
    try { $connections=@(ExchangeOnlineManagement\Get-ConnectionInformation -ErrorAction Stop) } catch { return @{Status='NotConnected';Reason='REST session information unavailable; no sign-in attempted.'} }
    return Test-AuditCommandIdentity $connections $TenantId $Provider $ExpectedAccount
}
function Test-AuditCommandIdentity($Connections,[guid]$TenantId,[string]$Provider,[string]$ExpectedAccount) {
    $isPurview=$Provider -eq 'Purview'
    $active=@($connections | Where-Object { (Get-AuditProperty $_ 'State') -eq 'Connected' -and [bool](Get-AuditProperty $_ 'IsEopSession' $false) -eq $isPurview })
    if ($active.Count -ne 1) { return @{Status='NotConnected';Reason='Exactly one active REST session for this workload is required; ambiguous or absent sessions refused.'} }
    $connection=$active[0]
    if ((Get-AuditProperty $connection 'TenantID') -ne $TenantId.ToString() -or (Get-AuditProperty $connection 'DelegatedOrganization')) { return @{Status='TenantMismatch';Reason='Tenant mismatch or delegated-organization session; delegated cross-tenant collection is not supported.'} }
    if ((Get-AuditProperty $connection 'ModulePrefix') -or (Get-AuditProperty $connection 'TokenStatus') -ne 'Active') { return @{Status='NotConnected';Reason='An active, unprefixed REST session is required.'} }
    if (-not (Test-AuditProperty $connection 'CertificateAuthentication') -or [bool](Get-AuditProperty $connection 'CertificateAuthentication') -or
        -not [string]::Equals([string](Get-AuditProperty $connection 'UserPrincipalName'),$ExpectedAccount,[StringComparison]::OrdinalIgnoreCase)) {
        return @{Status='IdentityMismatch';Reason='Workload session is not the confirmed delegated administrator account; no commands invoked.'}
    }
    return @{Status='Ready';Reason='';Connection=$connection}
}

function ConvertTo-AuditCommandValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary]) {
        return ,@(foreach ($entry in $Value) { ConvertTo-AuditCommandValue $entry })
    }
    # Exchange identity/address wrappers can carry many extra properties. Serialize their display
    # representation only; never recursively export the backing session or directory objects.
    return [string]$Value
}
function Read-AuditCommandSource {
    param($Source,$Session,[int]$MaxRecords=50000,[switch]$IncludeWorkbookMailFields)
    $r=New-AuditResult $Source 'Collected'
    $eligible=@(Get-Command -Name $Source.Target -CommandType Function,Cmdlet -All -ErrorAction SilentlyContinue)
    if ($eligible.Count -eq 0) { $r.Status='Unavailable'; $r.Reason='Read cmdlet unavailable in the selected session; check RBAC and installed module.'; return $r }
    # The same Get-* name can be exposed by Exchange and Security & Compliance.
    # Select exactly one command from the already-verified session, never the
    # shell's precedence winner or a command from another workload.
    $expected=[string](Get-AuditProperty $Session.Connection 'ModuleName')
    $sessionModule=[IO.Path]::GetFileName($expected)
    $bound=@(foreach($candidate in $eligible) {
        if(-not $expected -or $null -eq $candidate.Module){continue}
        $actualPath=[string]$candidate.Module.Path
        $pathBound=$actualPath -ceq $expected -or $actualPath.StartsWith($expected+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal)
        $nameBound=-not [IO.Path]::IsPathRooted($expected) -and [string]$candidate.ModuleName -ceq $sessionModule
        if($pathBound -or $nameBound){$candidate}
    })
    if ($bound.Count -ne 1) {
        $r.Status='Unavailable'; $r.Reason='Cmdlet origin could not be uniquely bound to the validated REST session; refused.'; return $r
    }
    $command=$bound[0]
    $variants=@(@{})
    if ($Source.Target -eq 'Get-OutboundConnector') {
        $variants=@(
            @{IncludeTestModeConnectors=$false;IsTransportRuleScoped=$false},
            @{IncludeTestModeConnectors=$false;IsTransportRuleScoped=$true},
            @{IncludeTestModeConnectors=$true;IsTransportRuleScoped=$false},
            @{IncludeTestModeConnectors=$true;IsTransportRuleScoped=$true})
    }
    $items=[System.Collections.Generic.List[object]]::new(); $missing=[System.Collections.Generic.HashSet[string]]::new(); $seen=[System.Collections.Generic.HashSet[string]]::new()
    foreach ($variant in $variants) {
        $parameters=@{ErrorAction='Stop';WarningAction='SilentlyContinue';WarningVariable='commandWarnings'}
        if ($command.Parameters.ContainsKey('ResultSize')) { $parameters.ResultSize='Unlimited' }
        foreach ($key in $variant.Keys) { $parameters[$key]=$variant[$key] }
        if ($Source.Target -in @('Get-DlpCompliancePolicy','Get-RetentionCompliancePolicy')) {
            if (-not $command.Parameters.ContainsKey('DistributionDetail')) {
                $r.Status='Partial'; $r.Reason='DistributionDetailUnavailable; refusing potentially inaccurate location/status summary.'; continue
            }
            $parameters.DistributionDetail=$true
        }
        # Refuse to trigger any interactive mandatory-parameter prompt.
        $canInvoke=@($command.ParameterSets | Where-Object {
            @($_.Parameters | Where-Object { $_.IsMandatory -and -not $parameters.ContainsKey($_.Name) }).Count -eq 0
        }).Count -gt 0
        if (-not $canInvoke) { $r.Status='Partial'; $r.Reason='RequiredParametersUnavailable; command not invoked.'; continue }
        $commandWarnings=@()
        try {
            $r.RequestCount++
            $rows=@(& $command @parameters | Select-Object -First ($MaxRecords+1))
            $r.PageCount++
            foreach ($row in $rows) {
                $identity=[string](Get-AuditProperty $row 'Identity' '')
                if ($variants.Count -gt 1 -and $identity -and -not $seen.Add($identity)) { continue }
                if ($items.Count -ge $MaxRecords) { $r.Status='Partial'; $r.Reason='RecordLimit'; break }
                $selected=[ordered]@{}
                foreach ($field in $Source.Fields) {
                    if (Test-AuditProperty $row $field) { $selected[$field]=ConvertTo-AuditCommandValue (Get-AuditProperty $row $field) } else { [void]$missing.Add($field) }
                }
                if($IncludeWorkbookMailFields){
                    foreach($field in (Get-AuditProperty $Source 'OptionalFields' @())){
                        # These fields are additive projections from the already fetched policy.
                        # Absence leaves the corresponding new control unknown, not older fields.
                        if(Test-AuditProperty $row $field){$selected[$field]=ConvertTo-AuditCommandValue (Get-AuditProperty $row $field)}
                    }
                }
                $items.Add([pscustomobject]$selected)
            }
            if ($commandWarnings.Count -gt 0) { $r.Status='Partial'; $r.Reason='CmdletReportedWarning; inspect the source directly in your approved administration session.' }
        } catch {
            $status=Get-AuditHttpStatus $_
            $r.Status=if ($items.Count -gt 0 -or $variants.Count -gt 1) { 'Partial' } else { Get-AuditFailureName $status }
            $r.Reason='CmdletFailed; exception details suppressed to avoid exporting account/session data.'
        }
    }
    $r.Items=$items.ToArray(); $r.Count=$items.Count; $r.MissingFields=@($missing | Sort-Object)
    if ($missing.Count -gt 0 -and $r.Status -eq 'Collected') { $r.Status='Partial'; $r.Reason='SomeSelectedPropertiesUnavailable; inspect MissingFields. Missing is not false.' }
    return $r
}

function Test-FlapjacksGraphScope($Source,$Session) {
    $present=@((Get-AuditProperty $Session.Context 'Scopes' @()))
    if (@($Source.Scopes | Where-Object { $_ -in $present }).Count -eq 0) { return $false }
    foreach ($required in (Get-AuditProperty $Source 'RequiredScopes' @())) {
        if ($required -notin $present) { return $false }
    }
    return $true
}
