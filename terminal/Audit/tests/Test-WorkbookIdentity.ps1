#requires -Version 7.4
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../src/WorkbookIdentity.ps1')
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$name,[bool]$ok){$tests.Add([pscustomobject]@{Test=$name;Passed=$ok});if(-not $ok){throw "FAILED: $name"}}
function Evidence([string]$id,$items){$c=Get-FlapjacksWorkbookIdentitySources|Where-Object Id -ceq $id;[pscustomobject]@{SourceId=$id;Provider=$c.Provider;Target=$c.Target;Status='Collected';Count=@($items).Count;Items=@($items);MissingFields=@();CollectedAtUtc='2026-11-17T00:00:00Z'}}
function Sample {
    [pscustomobject]@{Metadata=[pscustomobject]@{Mode='Synthetic';SelectedGroups=@('Core','WorkbookIdentity')};Evidence=@(
        (Evidence 'workbook-identity-registration' @(
            [pscustomobject]@{id='00000000-0000-0000-0000-000000000001';isAdmin=$true;isMfaRegistered=$true;isSsprEnabled=$true;isSsprRegistered=$true;isSsprCapable=$true;lastUpdatedDateTime='2026-11-16T22:00:00Z'},
            [pscustomobject]@{id='00000000-0000-0000-0000-000000000002';isAdmin=$false;isMfaRegistered=$false;isSsprEnabled=$true;isSsprRegistered=$true;isSsprCapable=$false;lastUpdatedDateTime='2026-11-16T22:00:00Z'}
        )),
        (Evidence 'workbook-identity-users' @(
            [pscustomobject]@{id='00000000-0000-0000-0000-000000000001';accountEnabled=$true;signInActivity=[pscustomobject]@{lastSuccessfulSignInDateTime='2026-11-16T12:00:00Z'}},
            [pscustomobject]@{id='00000000-0000-0000-0000-000000000002';accountEnabled=$true;signInActivity=[pscustomobject]@{lastSuccessfulSignInDateTime='2026-01-01T00:00:00Z'}},
            [pscustomobject]@{id='00000000-0000-0000-0000-000000000003';accountEnabled=$false;signInActivity=$null}
        ))
    )}
}
function Run($r){@(Get-FlapjacksWorkbookIdentityChecks -Result $r)}
function By($rows,[string]$id){@($rows|Where-Object ControlId -eq $id)[0]}
function Expect($r,[string]$id,[string]$status){(By (Run $r) $id).Status -eq $status}
$sources=@(Get-FlapjacksWorkbookIdentitySources)
Check 'Two fixed identity sources' ($sources.Count -eq 2)
Check 'Both optional Graph Collection contracts' (@($sources|Where-Object {$_.Group -cne 'WorkbookIdentity' -or $_.Provider -cne 'Graph' -or $_.Shape -cne 'Collection'}).Count -eq 0)
Check 'Registration exact minimal projection' ($sources[0].Target -ceq '/reports/authenticationMethods/userRegistrationDetails?$select=id,isAdmin,isMfaRegistered,isSsprEnabled,isSsprRegistered,isSsprCapable,lastUpdatedDateTime')
Check 'Users exact projection with extra required audit scope' ($sources[1].Target -ceq '/users?$select=id,accountEnabled,signInActivity' -and $sources[1].Scopes[0] -ceq 'User.Read.All' -and $sources[1].RequiredScopes.Count -eq 1 -and $sources[1].RequiredScopes[0] -ceq 'AuditLog.Read.All')
Check 'No event-entry endpoint is allowed' (@($sources|Where-Object Target -match '/auditLogs/|/signIns|/users/').Count -eq 0)
Check 'No identity names or auth methods requested' (@($sources|Where-Object Target -match 'userPrincipalName|displayName|methodsRegistered|mobilePhone|mail|lastSignInDateTime').Count -eq 0)
$r=Sample;$rows=Run $r
Check 'Five stable workbook identity controls' ($rows.Count -eq 5)
Check 'MFA admin and non-admin populations evaluated separately' ((Expect $r 'ENTRA-MFA-ADMIN-REG' 'Meets selected setting') -and (Expect $r 'ENTRA-MFA-USER-REG' 'Needs action'))
Check 'Report freshness is separate from collection time' ((By $rows 'ENTRA-MFA-ADMIN-REG').Observed -match 'Report update range: 2026-11-16T22:00:00')
Check 'SSPR registered does not imply capable' ((Expect $r 'ENTRA-SSPR-REG' 'Meets selected setting') -and (Expect $r 'ENTRA-SSPR-CAPABLE' 'Needs action'))
Check 'Known stale enabled account is review candidate' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Needs action')
Check 'Disabled inventory excluded from denominator' ((By $rows 'ENTRA-SSPR-REG').Observed -match '2 enabled directory accounts')
Check 'Only failed identities appear in detail IDs' ((By $rows 'ENTRA-MFA-ADMIN-REG').EvidenceIds.Count -eq 0 -and (By $rows 'ENTRA-MFA-USER-REG').EvidenceIds.Count -eq 1 -and (By $rows 'ENTRA-MFA-USER-REG').EvidenceIds[0] -eq '00000000-0000-0000-0000-000000000002')
Check 'Official reference and limitations retained' (@($rows|Where-Object {$_.Reference -notlike 'https://learn.microsoft.com/*' -or $_.NistReference -notlike 'https://csrc.nist.gov/*' -or $_.NistMappingNote -notmatch 'not proof'}).Count -eq 0)
Check 'Registration is explicitly not enforcement' ((By $rows 'ENTRA-MFA-ADMIN-REG').Limitation -match 'no effective MFA enforcement')
Check 'Unavailable sources still emit five rows' ((Run ([pscustomobject]@{Evidence=@()})).Count -eq 5)
Check 'Empty input never passes' (@(Run ([pscustomobject]@{Evidence=@()})|Where-Object Status -ne 'Not assessed').Count -eq 0)
foreach($state in @('Partial','InsufficientPermissions','AccessDenied','NotConnected','NotSelected','Unavailable','Unlicensed','Error','collected',123)) {
    $r=Sample;$r.Evidence[0].Status=$state
    Check ("Registration status $state cannot establish pass") (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
    $r=Sample;$r.Evidence[1].Status=$state
    Check ("Inventory status $state blocks denominator and dormant pass") ((Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed') -and (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Not assessed'))
}
foreach($index in @(0,1)) {
    $r=Sample;$r.Evidence[$index].Items=@();$r.Evidence[$index].Count=0
    Check "Successful empty source $index unknown" (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
    $r=Sample;$r.Evidence[$index].PSObject.Properties.Remove('Items')
    Check "Summary-only source $index unknown" (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
    $r=Sample;$r.Evidence[$index].MissingFields=@('id')
    Check "MissingFields source $index blocks denominator" (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
    $r=Sample;$r.Evidence[$index].Items[1].id=$r.Evidence[$index].Items[0].id
    Check "Duplicate identity source $index unknown" (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
    $r=Sample;$r.Evidence[$index].Items[1].id='not-an-object-id'
    Check "Invalid identity source $index unknown" (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
}
foreach($count in @(99,'2',$true,2.0,-1)) {
    $r=Sample;$r.Evidence[0].Count=$count
    Check ('Invalid evidence count '+$count.GetType().Name+' '+$count) (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
}
$r=Sample;$r.Evidence[0].Items=@($r.Evidence[0].Items[0]);$r.Evidence[0].Count=1
Check 'Missing registration user blocks subgroup pass even admin present' (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[1].id='00000000-0000-0000-0000-000000000003'
Check 'Same count but mismatched IDs not a denominator' (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
foreach($value in @($null,'false',0)) {
    $r=Sample;$r.Evidence[0].Items[1].isAdmin=$value
    Check ('Unknown admin flag blocks both subgroup denominators: '+[string]$value) ((Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed') -and (Expect $r 'ENTRA-MFA-USER-REG' 'Not assessed'))
    $r=Sample;$r.Evidence[1].Items[1].accountEnabled=$value
    Check ('Unknown enabled flag blocks denominator: '+[string]$value) (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
}
foreach($value in @($null,'invalid','2026-11-18T00:00:00Z')) {
    $r=Sample;$r.Evidence[0].Items[0].lastUpdatedDateTime=$value
    Check ('Unknown report freshness prevents registration pass: '+[string]$value) (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
}
$r=Sample;$r.Evidence[0].CollectedAtUtc=$null
Check 'Missing report collection time cannot imply fresh registration evidence' (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].PSObject.Properties.Remove('isAdmin')
Check 'Absent admin flag is not non-admin' (Expect $r 'ENTRA-MFA-USER-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[1].isAdmin=$true
Check 'Zero non-admin group does not pass or infer N/A' (Expect $r 'ENTRA-MFA-USER-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].isMfaRegistered=$null
Check 'Null registered is unknown' (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[1].isSsprEnabled=$null
Check 'Unknown SSPR enablement blocks SSPR subgroup' (Expect $r 'ENTRA-SSPR-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[1].isSsprEnabled=$false
Check 'Out-of-scope SSPR incapability does not fail enabled scope' (Expect $r 'ENTRA-SSPR-CAPABLE' 'Meets selected setting')
$r=Sample;foreach($item in $r.Evidence[0].Items){$item.isSsprEnabled=$false}
Check 'Zero SSPR-enabled group unknown, not N/A' (Expect $r 'ENTRA-SSPR-REG' 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].isSsprRegistered='true'
Check 'String SSPR registered is unknown' (Expect $r 'ENTRA-SSPR-REG' 'Not assessed')
foreach($value in @($null,'','not-a-date','2026-12-01T00:00:00Z',123,'01/01/2026')) {
    $r=Sample;$r.Evidence[1].Items[1].signInActivity.lastSuccessfulSignInDateTime=$value
    Check ('Unknown or future success time never means dormant: '+[string]$value) (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Not assessed')
}
$r=Sample;$r.Evidence[1].Items[1].signInActivity=$null
Check 'Null signInActivity is unknown' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Not assessed')
$r=Sample;$r.Evidence[1].Items[1].signInActivity=[pscustomobject]@{lastSignInDateTime='2026-11-16T00:00:00Z';lastNonInteractiveSignInDateTime='2026-11-16T00:00:00Z'}
Check 'Attempt dates do not substitute for successful usage' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Not assessed')
$r=Sample;$r.Evidence[1].Items[0].signInActivity.lastSuccessfulSignInDateTime=$null
Check 'Known dormant finding retained alongside unknown timestamp' ((Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Needs action') -and (By (Run $r) 'ENTRA-DORMANT-ACCOUNTS').Observed -match '1 are unknown')
$r=Sample;$r.Evidence[1].Items[1].signInActivity.lastSuccessfulSignInDateTime='2026-11-15T00:00:00Z'
Check 'All enabled timestamps recent meets selected snapshot' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Meets selected setting')
$r=Sample;$r.Evidence[1].Items[1].signInActivity.lastSuccessfulSignInDateTime=([datetimeoffset]'2026-11-17T00:00:00Z').AddDays(-90).ToString('o')
Check 'Exactly 90 days is included in review threshold' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Needs action')
$r=Sample;$r.Evidence[1].Items[1].signInActivity.lastSuccessfulSignInDateTime=([datetimeoffset]'2026-11-17T00:00:00Z').AddDays(-90).AddSeconds(1).ToString('o')
Check 'One second newer than threshold is recent' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Meets selected setting')
$r=Sample;$r.Evidence[1].CollectedAtUtc='bad'
Check 'Invalid assessment clock unknown' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Not assessed')
$r=Sample;$r.Evidence[1].CollectedAtUtc=[datetime]'2026-11-17T00:00:00Z'
Check 'Deserialized collection date supported' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Needs action')
$r=Sample;$r.Evidence=@($r.Evidence[0])
Check 'Registration without independent inventory unknown' (Expect $r 'ENTRA-MFA-ADMIN-REG' 'Not assessed')
$r=Sample;$r.Evidence=@($r.Evidence[1])
Check 'Missing registration does not prevent dormancy assessment' (Expect $r 'ENTRA-DORMANT-ACCOUNTS' 'Needs action')
$r=Sample;$coverage=[pscustomobject]@{Coverage=$r.Evidence}
Check 'Full saved Coverage works' (Expect $coverage 'ENTRA-MFA-ADMIN-REG' 'Meets selected setting')
$r=Sample;$saved=$r|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20
Check 'JSON round-trip supported' (Expect $saved 'ENTRA-MFA-ADMIN-REG' 'Meets selected setting')
$saved=$r|ConvertTo-Json -Depth 20|ConvertFrom-Json -Depth 20 -AsHashtable
Check 'Hashtable evidence supported' (Expect $saved 'ENTRA-MFA-ADMIN-REG' 'Meets selected setting')
$r=Sample;$before=$r|ConvertTo-Json -Depth 20;$null=Run $r
Check 'Evaluation never mutates supplied evidence' (($r|ConvertTo-Json -Depth 20) -ceq $before)
$r=Sample;$r.Evidence+=$r.Evidence[0];$threw=$false;try{$null=Run $r}catch{$threw=$true}
Check 'Duplicate sources reject merged evidence' $threw
# Projection is independent of the API honoring its select clause. Synthetic extras must disappear.
$dirty=@{id='00000000-0000-0000-0000-000000000001';accountEnabled=$true;displayName='SYNTHETIC DO NOT EXPORT';userPrincipalName='synthetic@example.invalid';passwordProfile=@{password='SYNTHETIC-NOT-A-SECRET'};signInActivity=@{lastSuccessfulSignInDateTime='2026-11-16T01:00:00Z';lastSignInDateTime='2026-11-17T00:00:00Z';lastSuccessfulSignInRequestId='SYNTHETIC REQUEST'}}
$safe=Protect-FlapjacksWorkbookIdentityItem -Source $sources[1] -Item $dirty
Check 'Local user projection retains exactly three fields' (($safe.PSObject.Properties.Name -join ',') -ceq 'id,accountEnabled,signInActivity')
Check 'Nested activity contains only last successful timestamp' (($safe.signInActivity.PSObject.Properties.Name -join ',') -ceq 'lastSuccessfulSignInDateTime')
Check 'No user or request details survive projection' (($safe|ConvertTo-Json -Depth 10) -notmatch 'DO NOT EXPORT|example.invalid|passwordProfile|SYNTHETIC REQUEST|lastSignInDateTime')
$dirty=@{id='00000000-0000-0000-0000-000000000001';isAdmin=$true;isMfaRegistered=$true;isSsprEnabled=$false;isSsprRegistered=$true;isSsprCapable=$false;lastUpdatedDateTime='2026-11-16T00:00:00Z';methodsRegistered=@('SYNTHETIC');userPrincipalName='synthetic@example.invalid'}
$safe=Protect-FlapjacksWorkbookIdentityItem -Source $sources[0] -Item $dirty
Check 'Registration projection retains only seven fields' ($safe.PSObject.Properties.Name.Count -eq 7 -and ($safe|ConvertTo-Json) -notmatch 'methodsRegistered|userPrincipalName')
$dirty=@{id=@{secret='SYNTHETIC'};isAdmin='true';isMfaRegistered=@{secret='SYNTHETIC'};lastUpdatedDateTime='arbitrary string'}
$safe=Protect-FlapjacksWorkbookIdentityItem -Source $sources[0] -Item $dirty
Check 'Unexpected scalar field types reduced to null' ($null -eq $safe.id -and $null -eq $safe.isAdmin -and $null -eq $safe.isMfaRegistered -and $null -eq $safe.lastUpdatedDateTime)
$dirty=@{id='00000000-0000-0000-0000-000000000001';accountEnabled='false';signInActivity=@{lastSuccessfulSignInDateTime=@{secret='SYNTHETIC'}}}
$safe=Protect-FlapjacksWorkbookIdentityItem -Source $sources[1] -Item $dirty
Check 'Malformed nested timestamp reduced to null' ($null -eq $safe.accountEnabled -and $null -eq $safe.signInActivity.lastSuccessfulSignInDateTime)
$threw=$false;try{$null=Protect-FlapjacksWorkbookIdentityItem -Source @{Id='unknown-source'} -Item @{id='x'}}catch{$threw=$true}
Check 'Unknown projection source refused' $threw
$r=Sample; $r.Evidence[0].Provider='OfflineSnapshot'
$o=@(Get-FlapjacksWorkbookIdentityChecks -Result $r)
Check 'Mislabeled registration provider cannot establish posture' (@($o|Where-Object { $_.SourceId -eq 'workbook-identity-registration' -and $_.Status -ne 'Not assessed' }).Count -eq 0)
$r=Sample; $r.Evidence[1].PSObject.Properties.Remove('Target')
$o=@(Get-FlapjacksWorkbookIdentityChecks -Result $r)
Check 'Absent exact inventory target cannot establish an identity denominator' (@($o|Where-Object Status -ne 'Not assessed').Count -eq 0)
$tests|Format-Table -AutoSize
Write-Output ("PASS: "+$tests.Count+" offline synthetic identity checks; no requests, sessions, consent, user data or file exports.")
