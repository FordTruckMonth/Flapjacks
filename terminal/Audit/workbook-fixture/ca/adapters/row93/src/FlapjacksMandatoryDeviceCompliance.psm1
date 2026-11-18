#requires -Version 7.4
# Registered invented saved-schema evidence only; no collector or real-input route.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Root=Split-Path $PSScriptRoot -Parent
$script:FixturesPin='e034454e2d61d84fc8d07c33e61089a3bb67193ac47e2affd49bc0ff4510b155'
$script:Workbook='92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
$script:Cache=$null
function Hash-R([string]$s){[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($s))).ToLowerInvariant()}
function Read-R([string]$path,[long]$max){
 $p=[IO.Path]::GetFullPath($path)
 for($q=$p;$q;$q=[IO.Path]::GetDirectoryName($q)){if((Test-Path -LiteralPath $q) -and ([IO.File]::GetAttributes($q) -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked proof path refused.'}}
 $f=[IO.FileInfo]::new($p)
 if(-not $f.Exists -or $f.Length -gt $max){throw 'Private proof file bound.'}
 return [Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($p))
}
$script:PackageRoot=Split-Path (Split-Path $script:Root -Parent) -Parent
. (Join-Path $script:PackageRoot 'support/Integrity.ps1')
Assert-PortablePayload $script:PackageRoot
$script:Dependency=[pscustomobject]@{ExecutionIdentitySha256='a98a69c7913a482a9d9503be0de34a8187cac19da8a7ccb1c5f742d906905078'}
$script:Parent=Import-Module (Join-Path $script:PackageRoot 'support/FlapjacksRowHelpers.psm1') -PassThru -DisableNameChecking
$script:Audit=& $script:Parent {$script:Audit}
function Parse-R([string]$s,[long]$max){& $script:Parent {param($x,$n)Parse-R $x $n} $s $max}
function V($o,[string]$k,$fallback=$null){if($o -is [Collections.IDictionary] -and $o.Contains($k)){return ,$o[$k]};return ,$fallback}
function Shape($o,[string[]]$allowed,[string[]]$required=@()){
 return ($o -is [Collections.IDictionary] -and @($o.Keys|Where-Object {$_ -cnotin $allowed}).Count -eq 0 -and @($required|Where-Object {$_ -cnotin $o.Keys}).Count -eq 0)
}
function Native-Int($v){return ($v -is [long] -or $v -is [int])}
function Utc-R($v){& $script:Parent {param($x)Utc-R $x} $v}
function Fixture-R([string]$id){
 $raw=Read-R (Join-Path $script:Root 'fixtures/registered.json') 1048576
 if((Hash-R $raw) -cne $script:FixturesPin){throw 'Registered fixture bytes changed.'}
 if($null -eq $script:Cache){$script:Cache=Parse-R $raw 1048576}
 $pack=$script:Cache
 if($pack.Kind -cne 'HandcraftedSyntheticFixturesOnly' -or $pack.RealInputsEnabled -isnot [bool] -or $pack.RealInputsEnabled){throw 'Real input disabled.'}
 $entries=@($pack.Cases|Where-Object Id -ceq $id)
 if($entries.Count -ne 1){throw 'Unregistered fixture refused.'}
 $e=$entries[0]
 if((Hash-R $e.AuditJson) -cne $e.AuditSha256 -or (Hash-R $e.IntentJson) -cne $e.IntentSha256){throw 'Fixture content mismatch.'}
 return $e
}
function Array-S($v){return ($v -is [array] -and @($v|Where-Object {$_ -isnot [string]}).Count -eq 0)}
function Empty-S($v){return ($v -is [array] -and $v.Count -eq 0)}
function IdList-S($values,[switch]$All){
 if(-not (Array-S $values) -or $values.Count -gt 64){return $false}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($v in $values){
  if(-not $seen.Add($v)){return $false}
  if($All -and $v -ceq 'All'){if($values.Count -ne 1){return $false};continue}
  if($v -cnotmatch '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$' -or $v -ceq '00000000-0000-0000-0000-000000000000'){return $false}
 }
 return $true
}
function Policy-S($p){
 $r=@{Comparison='Unknown';Reason='UnsupportedOrIncompletePolicy'}
 if(-not (Shape $p @('@odata.type','id','displayName','createdDateTime','modifiedDateTime','templateId','state','conditions','grantControls','sessionControls') @('id','state','conditions','grantControls'))){return $r}
 if(-not (IdList-S @($p.id))){return $r}
 if($p.Contains('@odata.type') -and $p['@odata.type'] -cnotin @('#microsoft.graph.conditionalAccessPolicy','microsoft.graph.conditionalAccessPolicy')){return $r}
 if($p.state -isnot [string] -or $p.state -cnotin @('enabled','disabled','enabledForReportingButNotEnforced')){return $r}
 $c=$p.conditions
 if(-not (Shape $c @('applications','users','clientAppTypes','signInRiskLevels','userRiskLevels','servicePrincipalRiskLevels','devices','locations','platforms','authenticationFlows','clientApplications','insiderRiskLevels') @('applications','users','clientAppTypes','signInRiskLevels','userRiskLevels'))){return $r}
 foreach($k in @('devices','locations','platforms','authenticationFlows','clientApplications','insiderRiskLevels')){if($c.Contains($k) -and $null -ne $c[$k]){$r.Reason='ConditionalScopeUnsupported';return $r}}
 foreach($k in @('signInRiskLevels','userRiskLevels')){if(-not (Empty-S $c[$k])){$r.Reason='ConditionalScopeUnsupported';return $r}}
 if($c.Contains('servicePrincipalRiskLevels') -and -not (Empty-S $c.servicePrincipalRiskLevels)){return $r}
 if(-not (Array-S $c.clientAppTypes) -or $c.clientAppTypes.Count -ne 1 -or $c.clientAppTypes[0] -cne 'all'){$r.Reason='ClientScopeUnsupported';return $r}
 $u=$c.users;$uf=@('includeUsers','excludeUsers','includeGroups','excludeGroups','includeRoles','excludeRoles')
 if(-not (Shape $u ($uf+@('includeGuestsOrExternalUsers','excludeGuestsOrExternalUsers')) $uf)){return $r}
 if(-not (Array-S $u.includeUsers) -or $u.includeUsers.Count -ne 1 -or $u.includeUsers[0] -cne 'All'){$r.Reason='PopulationUnresolved';return $r}
 if(-not (IdList-S $u.excludeUsers)){$r.Reason='UserExclusionShapeUnknown';return $r}
 foreach($k in @('includeGroups','excludeGroups','includeRoles','excludeRoles')){if(-not (Empty-S $u[$k])){$r.Reason='GroupOrRolePopulationUnresolved';return $r}}
 foreach($k in @('includeGuestsOrExternalUsers','excludeGuestsOrExternalUsers')){if($u.Contains($k) -and $null -ne $u[$k]){$r.Reason='ExternalPopulationUnresolved';return $r}}
 $a=$c.applications
 if(-not (Shape $a @('includeApplications','excludeApplications','includeUserActions','includeAuthenticationContextClassReferences','applicationFilter') @('includeApplications','excludeApplications','includeUserActions'))){return $r}
 if(-not (IdList-S $a.includeApplications -All) -or $a.includeApplications.Count -eq 0 -or -not (IdList-S $a.excludeApplications) -or -not (Empty-S $a.includeUserActions)){return $r}
 if($a.Contains('applicationFilter') -and $null -ne $a.applicationFilter){return $r}
 if($a.Contains('includeAuthenticationContextClassReferences') -and -not (Empty-S $a.includeAuthenticationContextClassReferences)){return $r}
 if(@($a.includeApplications|Where-Object {$_ -in $a.excludeApplications}).Count){$r.Reason='ApplicationScopeContradiction';return $r}
 # Microsoft documents an enrollment exemption. Do not credit this target alone.
 if($a.includeApplications.Count -eq 1 -and $a.includeApplications[0] -ieq 'd4ebce55-015a-49b5-a083-c84d1797ae8c'){$r.Reason='EnrollmentExemptionPreventsInference';return $r}
 $g=$p.grantControls
 if(-not (Shape $g @('@odata.type','operator','builtInControls','customAuthenticationFactors','termsOfUse','authenticationStrength') @('operator','builtInControls','customAuthenticationFactors','termsOfUse'))){$r.Reason='GrantEvidenceMissing';return $r}
 if($g.Contains('@odata.type') -and $g['@odata.type'] -cnotin @('#microsoft.graph.conditionalAccessGrantControls','microsoft.graph.conditionalAccessGrantControls')){return $r}
 if($g.operator -isnot [string] -or $g.operator -cnotin @('AND','OR') -or -not (Array-S $g.builtInControls)){$r.Reason='GrantShapeUnknown';return $r}
 if(-not (Empty-S $g.customAuthenticationFactors) -or -not (Empty-S $g.termsOfUse) -or ($g.Contains('authenticationStrength') -and $null -ne $g.authenticationStrength)){$r.Reason='AdditionalGrantSemanticsUnsupported';return $r}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($control in $g.builtInControls){if($control -cnotin @('compliantDevice','mfa','domainJoinedDevice','approvedApplication','compliantApplication','block') -or -not $seen.Add($control)){$r.Reason='GrantControlAmbiguousOrUnsupported';return $r}}
 if($seen.Contains('block') -and $seen.Count -ne 1){$r.Reason='MixedBlockGrantUnsupported';return $r}
 if($p.state -cne 'enabled'){$r.Comparison='DoesNotMatchStoredConfiguration';$r.Reason='StoredPolicyNotEnforced';return $r}
 # An omitted relationship leaves an OR alternative unresolved in a saved projection.
 if($g.operator -ceq 'OR' -and $seen.Count -eq 1 -and $seen.Contains('compliantDevice') -and -not $g.Contains('authenticationStrength')){
  $r.Reason='AuthenticationStrengthProjectionUnknown';return $r
 }
 if($seen.Contains('compliantDevice') -and ($g.operator -ceq 'AND' -or ($g.operator -ceq 'OR' -and $seen.Count -eq 1))){
  $r.Comparison='MatchesStoredConfiguration';$r.Reason='CompliantDeviceIsMandatoryStoredGrant'
 }else{$r.Comparison='DoesNotMatchStoredConfiguration';$r.Reason='ComplianceAbsentOrAlternativeStoredGrant'}
 return $r
}
function Source-S($o,$meta,$start,$finish,$at){
 $r=@{Ready=$false;Comparison='Unknown';Reason='MissingSource';Count=$null}
 if($o.Coverage.Count -eq 0){return $r}
 if($o.Coverage.Count -ne 1){throw 'Multiple or conflicting sources refused.'}
 $s=$o.Coverage[0]
 if(-not (Shape $s @('SourceId','Group','Provider','Target','Status','Reason','CollectedAtUtc','PageCount','RequestCount','Count','Items','MissingFields','Notes') @('SourceId','Group','Provider','Target','Status'))){throw 'Unsupported source envelope.'}
 foreach($pair in @(@('SourceId','conditional-access'),@('Group','Core'),@('Provider','Graph'),@('Target','/identity/conditionalAccess/policies'))){if($s[$pair[0]] -isnot [string] -or $s[$pair[0]] -cne $pair[1]){throw 'Exact source binding refused.'}}
 $r.Reason='SourceIncompleteOrUnselected'
 if($s.Status -isnot [string] -or $s.Status -cne 'Collected' -or 'Core' -cnotin $meta.SelectedGroups){return $r}
 $items=V $s 'Items';$count=V $s 'Count';$missing=V $s 'MissingFields';$pages=V $s 'PageCount';$requests=V $s 'RequestCount'
 if($items -isnot [array] -or $items.Count -eq 0 -or $items.Count -gt 32 -or -not (Native-Int $count) -or $count -ne $items.Count -or $missing -isnot [array] -or $missing.Count){return $r}
 if(-not (Native-Int $pages) -or $pages -ne 1 -or -not (Native-Int $requests) -or $requests -ne 1){return $r}
 $stamp=Utc-R (V $s 'CollectedAtUtc')
 if($null -eq $stamp -or $stamp -lt $start -or $stamp -gt $finish){$r.Reason='SourceTimeUnknown';return $r}
 if(($at-$stamp).TotalHours -gt 24){$r.Reason='StaleSavedEvidence';return $r}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $results=[Collections.Generic.List[object]]::new()
 foreach($p in $items){
  $id=V $p 'id'
  if($id -isnot [string] -or -not $seen.Add($id)){$r.Reason='PolicyIdentityMissingDuplicateOrConflicting';return $r}
  $results.Add((Policy-S $p))
 }
 $r.Ready=$true;$r.Count=$items.Count
 if(@($results|Where-Object Comparison -ceq 'MatchesStoredConfiguration').Count){$r.Comparison='MatchesStoredConfiguration';$r.Reason='AtLeastOneMandatoryStoredGrantInSuppliedSet'}
 elseif(@($results|Where-Object Comparison -ceq 'Unknown').Count){$r.Reason='PolicyScopeOrGrantUnresolved'}
 else{$r.Comparison='DoesNotMatchStoredConfiguration';$r.Reason='NoMandatoryStoredGrantInSuppliedSetOnly'}
 return $r
}
function Get-FlapjacksMandatoryDeviceCompliance {
 [CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{1,80}$')][string]$FixtureId,[switch]$EnableFixtureReview)
 if(-not $EnableFixtureReview){throw 'Explicit fixture review opt-in required; real input disabled.'}
 $e=Fixture-R $FixtureId;$o=Parse-R $e.AuditJson 131072;$i=Parse-R $e.IntentJson 8192
 if(-not (Shape $i @('SchemaVersion','FixtureId','InputSha256','ExpectedTenantId','ExpectedMode','ReviewAsOfUtc','WorkbookSha256','PhysicalRow','SourceId','AuthorizationKind','PermissionToOpenRealInput') @('SchemaVersion','FixtureId','InputSha256','ExpectedTenantId','ExpectedMode','ReviewAsOfUtc','WorkbookSha256','PhysicalRow','SourceId','AuthorizationKind','PermissionToOpenRealInput'))){throw 'Review intent shape refused.'}
 if($i.SchemaVersion -cne 'FlapjacksRow93FixtureIntent/1' -or $i.FixtureId -cne $FixtureId -or $i.InputSha256 -cne $e.AuditSha256 -or $i.WorkbookSha256 -cne $script:Workbook -or -not (Native-Int $i.PhysicalRow) -or $i.PhysicalRow -ne 93 -or $i.SourceId -cne 'conditional-access' -or $i.AuthorizationKind -cne 'RegisteredSyntheticDevelopmentOnly' -or $i.PermissionToOpenRealInput -isnot [bool] -or $i.PermissionToOpenRealInput){throw 'Review intent binding refused.'}
 if(-not (Shape $o @('Metadata','Coverage','Observations') @('Metadata','Coverage','Observations'))){throw 'Saved evidence shape refused.'}
 $meta=$o.Metadata
 if(-not (Shape $meta @('SchemaVersion','ToolVersion','Mode','TenantId','StartedAtUtc','FinishedAtUtc','PowerShellVersion','SelectedGroups','MaxPages','MaxRecords','OrganizationWideConfirmed','AccountVerification','Scope','Privacy','WorkbookAntiPhishBaseline') @('SchemaVersion','Mode','TenantId','StartedAtUtc','FinishedAtUtc','SelectedGroups'))){throw 'Saved metadata shape refused.'}
 if($meta.SchemaVersion -cne '1.1' -or $meta.Mode -isnot [string] -or $meta.Mode -cnotin @('Live','Synthetic') -or $meta.Mode -cne $i.ExpectedMode -or $meta.TenantId -isnot [string] -or $meta.TenantId -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or $meta.TenantId -cne $i.ExpectedTenantId){throw 'Declared tenant or mode binding refused.'}
 $start=Utc-R $meta.StartedAtUtc;$finish=Utc-R $meta.FinishedAtUtc;$at=Utc-R $i.ReviewAsOfUtc
 if($null -eq $start -or $null -eq $finish -or $null -eq $at -or $start -gt $finish -or $finish -gt $at){throw 'Declared time binding refused.'}
 if($meta.SelectedGroups -isnot [array] -or @($meta.SelectedGroups|Where-Object {$_ -isnot [string] -or $_ -cnotin @('Core','Authentication','Consent','Administration','TenantInventory','Intune','Exchange','Purview','WorkbookIdentity','WorkbookExchange','WorkbookCollaboration')}).Count){throw 'Source selection refused.'}
 if($o.Coverage -isnot [array] -or $o.Coverage.Count -gt 2 -or $o.Observations -isnot [array] -or $o.Observations.Count){throw 'Only bounded configuration evidence is supported.'}
 & $script:Parent {param($c)& $script:Parent {param($v)$script:Nodes=0;Walk-Passive $v 0} $c} $o.Coverage
 $source=Source-S $o $meta $start $finish $at
 $row=[pscustomobject][ordered]@{ControlId='WB-REF-92B9-ROW-93';PhysicalRow=93;Title='Require device compliance';Status='Not assessed';StoredComparison=$source.Comparison;WorkbookCriterion='Unknown';ReasonCode=$source.Reason;SourceId='conditional-access';EffectiveOutcomeVerified=$false;DeviceComplianceVerified=$false;PopulationResolved=$false;SourceAuthenticityVerified=$false;FullRowMappingCredit=0}
 $display=[pscustomobject][ordered]@{
  Control='WB-REF-92B9-ROW-93 | Require device compliance';Status='Not assessed'
  'Status details'='Saved-evidence review (fixture only). Stored configuration: '+$source.Comparison+'. Full workbook criterion: Unknown.'
  Rationale='Looks for at least one enabled policy whose supported grant requires compliantDevice. AND requires every listed control; OR with another control permits an alternative. Stored declarations do not prove actual device compliance, policy assignment or effective access.'
  'M365 access/licensing/prerequisites'='Existing conditional-access source and Policy.Read.All catalog scope only. Intune compliance policy, device status, licensing, roles and actual enforcement are unverified. Unsigned saved claims; real input disabled.'
 }
 return [pscustomobject][ordered]@{
  SchemaVersion='FlapjacksMandatoryDeviceComplianceReview/1'
  Metadata=[pscustomobject][ordered]@{EvaluationMode='SavedEvidenceReview';InputDeclaredMode=$meta.Mode;InputModeRelabeled=$false;DevelopmentFixturesOnly=$true;RealInputEnabled=$false;InputSha256=$e.AuditSha256;IntentSha256=$e.IntentSha256;ReferenceWorkbookSha256=$script:Workbook;ParentIdentitySha256=$script:Dependency.ExecutionIdentitySha256;EvidenceTrust='OperatorSuppliedUnsignedUnverified';SourceAuthenticated=$false;LiveRecheck=$false;CompleteTenantCoverageVerified=$false;CurrentTenantPostureAssessed=$false;ReviewAsOfUtc=$i.ReviewAsOfUtc;MaximumSavedAgeHours=24;FreshnessAuthority='Local conservative review policy, not a service SLA';NewStoredPredicates=1;NewFullRowMappings=0;NewLiveCoverage=0;OverallVerifiedNumerator=$null}
  Rows=@($row);DisplayRows=@($display)
  SourceRows=@([pscustomobject][ordered]@{Source='conditional-access';'Collection state'=if($source.Ready){'Supplied / unverified'}else{'Missing or incomplete'};'Returned records'=if($source.Ready){[string]$source.Count}else{'Unknown'}})
  Notes=@('DEVELOPMENT FIXTURES ONLY. Registered invented bytes; declared mode is preserved. No actual saved tenant file was opened.','LOCAL SAVED-EVIDENCE REVIEW. All posture statuses remain Not assessed. A configured mandatory grant is not evidence of actual Intune device compliance, assignment or effective access.','The exact original workbook row is physical Excel row 93. One new stored predicate is implemented for the supported scope; zero full-row or live coverage credits are added. The inherited 134 controls are not recounted.','Supported scope is declared All users with optional literal-user exclusions, All resources or explicit application identifiers, all clients, and no additional conditional restrictions. This does not resolve the actual population. Group or role scope stays Unknown.','A compliantDevice AND grant is mandatory. A single-control compliantDevice OR grant is mandatory only when the other grant fields are explicitly empty and authenticationStrength is explicitly null. Other OR alternatives do not require compliance. Missing, ambiguous or additional unsupported grants remain Unknown.','A known matching stored policy establishes only existence within the supplied set. Empty or partial evidence never establishes policy absence. Duplicate policy identities invalidate the supplied set; an unknown policy cannot erase a separate known stored match.','Microsoft documents that this grant does not block Intune enrollment. An enrollment-only target is not credited here. Actual enforcement also needs an Intune compliance policy and suitable device evidence, neither supplied by this source.','Identifiers and original provenance remain in private local synthetic evidence. The one-page, 32-policy and 24-hour bounds are local prototype rules. Frozen defaults, source catalog, Standard/Strict and real-input gates remain unchanged.')
 }
}
function Export-FlapjacksMandatoryDeviceCompliance {
 [CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{1,80}$')][string]$FixtureId,[Parameter(Mandatory)][string]$OutputDirectory,[switch]$EnableFixtureReview)
 $review=Get-FlapjacksMandatoryDeviceCompliance -FixtureId $FixtureId -EnableFixtureReview:$EnableFixtureReview
 $out=[IO.Path]::GetFullPath($OutputDirectory);$allowed=Join-Path $script:Root 'verification'
 if(-not $out.StartsWith($allowed+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal) -or (Test-Path -LiteralPath $out) -or -not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($out)) -PathType Container)){throw 'Fresh private proof output required.'}
 for($p=[IO.Path]::GetDirectoryName($out);$p;$p=[IO.Path]::GetDirectoryName($p)){if([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint){throw 'Linked output refused.'}}
 [void][IO.Directory]::CreateDirectory($out);$private=Join-Path $out 'private';[void][IO.Directory]::CreateDirectory($private);$e=Fixture-R $FixtureId
 [IO.File]::WriteAllText((Join-Path $private 'original.audit.json'),$e.AuditJson)
 [IO.File]::WriteAllText((Join-Path $private 'review-intent.json'),$e.IntentJson)
 [IO.File]::WriteAllText((Join-Path $private 'review.json'),($review|ConvertTo-Json -Depth 40))
 $pages=& $script:Audit {param($o,$r)
  Write-AuditCsv (Join-Path $o 'Saved-Evidence.csv') $r.DisplayRows @('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
  Write-FlapjacksPostureWorkbook -Path (Join-Path $o 'Saved-Evidence.xlsx') -Controls $r.DisplayRows -Coverage $r.SourceRows -Notes $r.Notes
  Write-FlapjacksPosturePdf -Path (Join-Path $o 'Saved-Evidence.pdf') -Controls $r.DisplayRows -Coverage $r.SourceRows -Notes $r.Notes -Summary 'FIXTURE ONLY | Row 93 mandatory device grant | 1 Not assessed' -CoverageSummary '1 selected source | Effective access unknown' -Synthetic:$false
 } $out $review
 $zip=[IO.Compression.ZipFile]::Open((Join-Path $out 'Saved-Evidence.xlsx'),[IO.Compression.ZipArchiveMode]::Update)
 try{foreach($entry in $zip.Entries){$entry.LastWriteTime=[datetimeoffset]::new(2000,1,1,0,0,0,[timespan]::Zero)}}finally{$zip.Dispose()}
 [pscustomobject]@{Rows=1;PdfPages=$pages;OutputDirectory=$out;RealInputEnabled=$false}
}
Export-ModuleMember -Function Get-FlapjacksMandatoryDeviceCompliance,Export-FlapjacksMandatoryDeviceCompliance
