#requires -Version 7.4
# Optional identity workbook profile. Evaluators and projection are pure saved-evidence
# functions. No authentication, consent, requests, installation or remediation occurs here.
function Get-FlapjacksWorkbookIdentitySources {
    [pscustomobject]@{
        Id='workbook-identity-registration'; Group='WorkbookIdentity'; Provider='Graph'
        Target='/reports/authenticationMethods/userRegistrationDetails?$select=id,isAdmin,isMfaRegistered,isSsprEnabled,isSsprRegistered,isSsprCapable,lastUpdatedDateTime'
        Scopes=@('AuditLog.Read.All'); RequiredScopes=@(); Shape='Collection'
        Fields=@('id','isAdmin','isMfaRegistered','isSsprEnabled','isSsprRegistered','isSsprCapable','lastUpdatedDateTime')
        Documentation='https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
        Notes='Optional sensitive identity snapshot. No names, UPNs, method details or activity events selected. Disabled users are not supported by this report. Reports Reader or another documented supported role and eligible licensing are required. The v1.0 SDK documents -Property/-Select; REST prose explicitly lists only $filter. Projection must be retained on every page and locally; never retry without $select. Service validation is still required. Registration does not prove effective MFA enforcement; report refresh can lag.'
    }
    [pscustomobject]@{
        Id='workbook-identity-users'; Group='WorkbookIdentity'; Provider='Graph'
        Target='/users?$select=id,accountEnabled,signInActivity'
        Scopes=@('User.Read.All','Directory.Read.All'); RequiredScopes=@('AuditLog.Read.All'); Shape='Collection'
        Fields=@('id','accountEnabled','signInActivity')
        Documentation='https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0'
        Notes='Optional identity denominator and latest-success snapshot only, not sign-in events. Requires one listed read scope AND AuditLog.Read.All, an eligible Entra P1/P2 license and a supported role. Locally retain only id, accountEnabled and signInActivity.lastSuccessfulSignInDateTime; discard all request IDs and attempt timestamps. Null or absent success time is unknown, not never-used or dormant. Last-success history starts December 2023 and is not backfilled.'
    }
}

function Protect-FlapjacksWorkbookIdentityItem {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Source,[Parameter(Mandatory)]$Item)
    function Has($o,[string]$n) { if($null -eq $o){return $false}; if($o -is [Collections.IDictionary]){return $o.Contains($n)}; return $null -ne $o.PSObject.Properties[$n] }
    function SafeTime($v) {
        if($v -is [datetime] -or $v -is [datetimeoffset]) { return $v.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture) }
        $parsed=[datetimeoffset]::MinValue
        if($v -is [string] -and $v -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$' -and [datetimeoffset]::TryParse($v,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)) { return $parsed.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture) }
        return $null
    }
    if($Source.Id -notin @('workbook-identity-registration','workbook-identity-users')) { throw 'Unknown workbook identity source; refusing an unprojected identity item.' }
    $safe=[ordered]@{}
    if(Has $Item 'id') {
        $id=[guid]::Empty
        $safe.id=if($Item.id -is [string] -and [guid]::TryParse($Item.id,[ref]$id) -and $id -ne [guid]::Empty){$id.ToString()}else{$null}
    }
    $boolFields=if($Source.Id -eq 'workbook-identity-registration') {@('isAdmin','isMfaRegistered','isSsprEnabled','isSsprRegistered','isSsprCapable')} else {@('accountEnabled')}
    foreach($n in $boolFields) { if(Has $Item $n){$safe[$n]=if($Item.$n -is [bool]){$Item.$n}else{$null}} }
    if($Source.Id -eq 'workbook-identity-registration' -and (Has $Item 'lastUpdatedDateTime')) { $safe.lastUpdatedDateTime=SafeTime $Item.lastUpdatedDateTime }
    if($Source.Id -eq 'workbook-identity-users' -and (Has $Item 'signInActivity')) {
        $activity=[ordered]@{}
        if(Has $Item.signInActivity 'lastSuccessfulSignInDateTime') { $activity.lastSuccessfulSignInDateTime=SafeTime $Item.signInActivity.lastSuccessfulSignInDateTime }
        $safe.signInActivity=if($null -eq $Item.signInActivity){$null}else{[pscustomobject]$activity}
    }
    return [pscustomobject]$safe
}

function Get-FlapjacksWorkbookIdentityChecks {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    function Has($o,[string]$n) { if($null -eq $o){return $false}; if($o -is [Collections.IDictionary]){return $o.Contains($n)}; return $null -ne $o.PSObject.Properties[$n] }
    function Val($o,[string]$n,$fallback=$null) { if(Has $o $n){return ,($o.$n)}; return ,$fallback }
    function Time($v) {
        if($v -is [datetimeoffset]){return $v.ToUniversalTime()}
        if($v -is [datetime]){return [datetimeoffset]$v.ToUniversalTime()}
        $parsed=[datetimeoffset]::MinValue
        if($v -is [string] -and $v -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$' -and [datetimeoffset]::TryParse($v,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)){return $parsed.ToUniversalTime()}
        return $null
    }
    $contracts=@{};foreach($contract in Get-FlapjacksWorkbookIdentitySources){$contracts[$contract.Id]=$contract}
    function ValidateSource($source,[string]$id) {
        if($null -eq $source){return 'No saved source evidence was supplied.'}
        if ((Val $source 'Provider') -cne 'Graph' -or (Val $source 'Target') -cne $contracts[$id].Target) { return 'The saved evidence does not carry the expected Graph source provenance.' }
        $status=Val $source 'Status'
        if($status -isnot [string] -or $status -cne 'Collected'){return 'Source is not a complete Collected result; permission, licensing, scope or collection gaps cannot establish posture.'}
        if(-not (Has $source 'Items')){return 'Summary-only coverage has no Items evidence.'}
        $items=Val $source 'Items'
        if($null -eq $items -or $items -is [string] -or $items -is [Collections.IDictionary] -or $items -isnot [Collections.IEnumerable]){return 'Items must be an evidence collection.'}
        $count=Val $source 'Count'
        if(($count -isnot [int] -and $count -isnot [long]) -or $count -ne @($items).Count){return 'Count does not establish complete matching Items evidence.'}
        if(@((Val $source 'MissingFields' @())|ForEach-Object {$_}).Count){return 'Source reports missing fields; no complete denominator can be established.'}
        if(@($items).Count -eq 0){return 'Successful empty response; applicability and a nonzero denominator are not established.'}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($item in $items) {
            $id=Val $item 'id'; $guid=[guid]::Empty
            if($id -isnot [string] -or -not [guid]::TryParse($id,[ref]$guid) -or $guid -eq [guid]::Empty -or -not $seen.Add($guid.ToString())){return 'Missing, invalid or duplicate user IDs make the denominator ambiguous.'}
        }
        return ''
    }
    $rows=Val $Result 'Evidence' @()
    if($null -eq $rows -or -not @($rows).Count){$rows=Val $Result 'Coverage' @()}
    $byId=@{}
    foreach($row in $rows) {
        $id=Val $row 'SourceId' ''
        if($id -isnot [string] -or $id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or $byId.ContainsKey($id)){throw 'Invalid or duplicate source ID; combining runs requires provenance-aware reconciliation.'}
        $byId[$id]=$row
    }
    $reg=$byId['workbook-identity-registration']; $users=$byId['workbook-identity-users']
    $userGap=ValidateSource $users 'workbook-identity-users'; $regGap=ValidateSource $reg 'workbook-identity-registration'
    $enabled=[Collections.Generic.List[object]]::new(); $enabledIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if(-not $userGap) {
        foreach($user in $users.Items) {
            $flag=Val $user 'accountEnabled'
            if($flag -isnot [bool]){$userGap='An accountEnabled value is missing, null or non-Boolean; the enabled-user denominator is unknown.';break}
            if($flag){$enabled.Add($user);[void]$enabledIds.Add(([guid]$user.id).ToString())}
        }
        if(-not $userGap -and $enabled.Count -eq 0){$userGap='No enabled accounts were returned; this does not establish applicability.'}
    }
    $denominatorGap=$userGap
    if(-not $denominatorGap){$denominatorGap=$regGap}
    if(-not $denominatorGap) {
        $regIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($item in $reg.Items){[void]$regIds.Add(([guid]$item.id).ToString())}
        if(-not $regIds.SetEquals($enabledIds)){$denominatorGap='Registration IDs do not exactly match the enabled-user inventory; report lag, missing users or scope gaps leave the denominator unresolved.'}
    }
    $reportTimes=[Collections.Generic.List[datetimeoffset]]::new()
    if(-not $denominatorGap) {
        $collected=Time (Val $reg 'CollectedAtUtc')
        if($null -eq $collected){$denominatorGap='Registration collection time is unavailable; report freshness cannot be described.'}
        else {
            foreach($item in $reg.Items) {
                $updated=Time (Val $item 'lastUpdatedDateTime')
                if($null -eq $updated -or $updated -gt $collected){$denominatorGap='A report update time is missing, invalid or later than collection; source freshness is unresolved.';break}
                $reportTimes.Add($updated)
            }
        }
    }
    $reportRange=''
    if(-not $denominatorGap) {
        $orderedTimes=@($reportTimes|Sort-Object)
        $reportRange=' Report update range: '+$orderedTimes[0].ToString('o',[Globalization.CultureInfo]::InvariantCulture)+' to '+$orderedTimes[-1].ToString('o',[Globalization.CultureInfo]::InvariantCulture)+'.'
    }
    $ref='https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0'
    $commonLimit='Only the complete matching enabled-user inventory and returned registration snapshot are evaluated. Disabled accounts are excluded. Report refresh can lag; no effective MFA enforcement, authentication strength, Conditional Access coverage or successful challenge is proved.'
    $defs=@(
        @{Id='ENTRA-MFA-ADMIN-REG';Name='MFA registration for reported enabled admins';Field='isMfaRegistered';GroupField='isAdmin';GroupValue=$true;GroupName='reported enabled admins';Source='workbook-identity-registration';Expected='All accounts in the known reported-admin denominator have isMfaRegistered = true.';Why='Review missing MFA registrations for the report-defined admin population.';Limit=$commonLimit+' isAdmin is the report flag, not an independent effective-role or PIM-eligibility evaluation.';Ref=$ref;Map='PR.AA-03'},
        @{Id='ENTRA-MFA-USER-REG';Name='MFA registration for reported enabled non-admins';Field='isMfaRegistered';GroupField='isAdmin';GroupValue=$false;GroupName='reported enabled non-admins';Source='workbook-identity-registration';Expected='All accounts in the known reported non-admin denominator have isMfaRegistered = true.';Why='Review missing MFA registrations for the report-defined non-admin population.';Limit=$commonLimit+' Non-admin classification relies on explicit isAdmin = false, never an absent flag.';Ref=$ref;Map='PR.AA-03'},
        @{Id='ENTRA-SSPR-REG';Name='SSPR registration for reported SSPR-enabled accounts';Field='isSsprRegistered';GroupField='isSsprEnabled';GroupValue=$true;GroupName='reported SSPR-enabled accounts';Source='workbook-identity-registration';Expected='All accounts in the known SSPR-enabled denominator have isSsprRegistered = true.';Why='Review required registration completion among accounts reported as enabled for self-service password reset.';Limit=$commonLimit+' Does not require SSPR for accounts outside the reported enabled scope or prove that a password reset succeeds.';Ref=$ref;Map='PR.AA-01'},
        @{Id='ENTRA-SSPR-CAPABLE';Name='SSPR capability for reported SSPR-enabled accounts';Field='isSsprCapable';GroupField='isSsprEnabled';GroupValue=$true;GroupName='reported SSPR-enabled accounts';Source='workbook-identity-registration';Expected='All accounts in the known SSPR-enabled denominator have isSsprCapable = true.';Why='Review report-defined SSPR readiness within the enabled scope.';Limit=$commonLimit+' Capability combines report-defined registration and policy eligibility; it is not an observed successful password reset.';Ref=$ref;Map='PR.AA-01'},
        @{Id='ENTRA-DORMANT-ACCOUNTS';Name='Enabled accounts with no successful sign-in for at least 90 days';Field='signInActivity.lastSuccessfulSignInDateTime';Source='workbook-identity-users';Expected='No enabled account has a known last successful sign-in at least 90 days before collection; missing times remain unknown.';Why='Flag known dormant candidates for owner review using a selected 90-day threshold. Do not disable accounts automatically.';Limit='Latest-success snapshot only, not an activity log or proof an account is unused. Null is unknown; data begins December 2023 and is not backfilled. Includes interactive and non-interactive success. Service lag, emergency-access and workload accounts need review. Evaluation is anchored to saved collection time, not the current clock.';Ref='https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0';Map='PR.AA-01'}
    )
    foreach($d in $defs) {
        $source=$byId[$d.Source]; $status='Not assessed'; $observed=''; $evidenceIds=[Collections.Generic.List[string]]::new()
        if($d.Id -eq 'ENTRA-DORMANT-ACCOUNTS') {
            $observed=$userGap
            $at=Time (Val $users 'CollectedAtUtc')
            if(-not $observed -and $null -eq $at){$observed='A valid saved collection timestamp is required for a reproducible 90-day assessment.'}
            if(-not $observed) {
                $dormant=0;$recent=0;$unknown=0;$cutoff=$at.AddDays(-90)
                foreach($user in $enabled) {
                    $last=Time (Val (Val $user 'signInActivity') 'lastSuccessfulSignInDateTime')
                    if($null -eq $last -or $last -gt $at){$unknown++}
                    elseif($last -le $cutoff){$dormant++;$evidenceIds.Add(([guid]$user.id).ToString())}
                    else{$recent++}
                }
                if($dormant -gt 0){$status='Needs action'}elseif($unknown -eq 0){$status='Meets selected setting'}
                $observed="$dormant of $($enabled.Count) enabled accounts have a known last successful sign-in at least 90 days before collection; $recent are more recent; $unknown are unknown. Review candidates, not automatic disablement."
            }
        } else {
            $observed=$denominatorGap
            $members=[Collections.Generic.List[object]]::new()
            if(-not $observed) {
                foreach($item in $reg.Items) {
                    $flag=Val $item $d.GroupField
                    if($flag -isnot [bool]){$observed='A '+$d.GroupField+' flag is missing, null or non-Boolean; the subgroup denominator is unknown.';break}
                    if($flag -ceq $d.GroupValue){$members.Add($item)}
                }
                if(-not $observed -and $members.Count -eq 0){$observed='The known subgroup contains no '+$d.GroupName+'; applicability is not inferred.'}
            }
            if(-not $observed) {
                $yes=0;$no=0;$unknown=0
                foreach($member in $members) {
                    $value=Val $member $d.Field
                    if($value -isnot [bool]){$unknown++}elseif($value){$yes++}else{$no++;$evidenceIds.Add(([guid]$member.id).ToString())}
                }
                if($unknown -eq 0){$status=if($no -eq 0){'Meets selected setting'}else{'Needs action'}}
                $observed="$yes of $($members.Count) $($d.GroupName) have $($d.Field) = true; $no false; $unknown unknown. Denominator reconciled to $($enabled.Count) enabled directory accounts."+$reportRange
            }
        }
        $rawStatus=Val $source 'Status' 'Missing';$sourceStatus=if($rawStatus -is [string]){$rawStatus}else{'Unrecognized'}
        $time=Time (Val $source 'CollectedAtUtc');$stamp=if($null -eq $time){''}else{$time.ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
        [pscustomobject][ordered]@{
            ControlId=$d.Id;Control=$d.Name;Status=$status;SourceId=$d.Source;Field=$d.Field;SourceStatus=$sourceStatus
            EvidenceIds=$evidenceIds.ToArray();EvidenceTime=$stamp;Observed=$observed;Expected=$d.Expected;Rationale=$d.Why;Limitation=$d.Limit;Reference=$d.Ref
            ProfileVersion='Flapjacks workbook identity 0.1';NistCsf20EvidenceMapping=$d.Map;NistFramework='NIST CSF 2.0'
            NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
            NistMappingNote='Analyst-selected supporting evidence only; not proof of CSF outcome attainment or NIST certification.'
            AccessPrerequisites='Optional WorkbookIdentity profile; exact approved tenant/account session, User.Read.All (or Directory.Read.All) AND AuditLog.Read.All; eligible licensing and supported reporting role. No consent or escalation is performed.'
        }
    }
}
