#requires -Version 7.4
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../src/Posture.ps1')
$evaluate='Get-FlapjacksPostureChecks'
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$name,[bool]$ok){$tests.Add([pscustomobject]@{Test=$name;Passed=$ok});if(-not $ok){throw "FAILED: $name"}}
function Evidence([string]$id,$items){[pscustomobject]@{SourceId=$id;Status='Collected';Count=@($items).Count;Items=@($items);MissingFields=@();CollectedAtUtc='2026-01-01T00:00:00Z'}}
function Sample {
 [pscustomobject]@{Metadata=[pscustomobject]@{Mode='Synthetic';RunId='synthetic-posture-first-slice'};Evidence=@(
  (Evidence 'exchange-organization' @([pscustomobject]@{Identity='synthetic-org';AuditDisabled=$false;RejectDirectSend=$false})),
  (Evidence 'exchange-transport' @([pscustomobject]@{Identity='synthetic-org';SmtpClientAuthenticationDisabled=$true})),
  (Evidence 'authorization-policy' @([pscustomobject]@{id='synthetic-policy';defaultUserRolePermissions=[pscustomobject]@{allowedToCreateApps=$true}})),
  (Evidence 'exchange-malware-policies' @([pscustomobject]@{Identity='synthetic-default';EnableFileFilter=$true},[pscustomobject]@{Identity='synthetic-custom';EnableFileFilter=$false}))
 )}
}
function By($rows,$id){@($rows | Where-Object ControlId -eq $id)[0]}
$r=Sample;$o=@(& $evaluate -Result $r)
Check 'Five stable controls' ($o.Count -eq 5)
Check 'Explicit false auditing flag meets selected switch' ((By $o 'EXO-AUDIT').Status -eq 'Meets selected setting')
Check 'False DirectSend switch needs review/action' ((By $o 'EXO-DIRECT-SEND').Status -eq 'Needs action')
Check 'True SMTP disabled switch meets selected switch' ((By $o 'EXO-SMTP-AUTH').Status -eq 'Meets selected setting')
Check 'Nested true app registration needs review/action' ((By $o 'ENTRA-APP-REG').Status -eq 'Needs action')
Check 'Mixed policy Boolean collection is not a pass' ((By $o 'EOP-FILE-FILTER').Status -eq 'Needs action')
Check 'Counts describe policies not users' ((By $o 'EOP-FILE-FILTER').Observed -eq '1 of 2 returned policies have EnableFileFilter = true.')
Check 'Source timestamp and ID retained' ((By $o 'EXO-AUDIT').EvidenceTime -eq '2026-01-01T00:00:00Z' -and (By $o 'EXO-AUDIT').EvidenceIds[0] -eq 'synthetic-org')
foreach($s in @('Partial','AccessDenied','NotConnected','Error','Unlicensed','NotSelected')){
 $r=Sample;$r.Evidence[0].Status=$s;$o=@(& $evaluate -Result $r)
 Check "$s remains Not assessed" ((By $o 'EXO-AUDIT').Status -eq 'Not assessed')
}
$r=Sample;$r.Evidence[0].Items=@();$r.Evidence[0].Count=0
Check 'Successful empty is unknown not pass/N/A' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].PSObject.Properties.Remove('AuditDisabled')
Check 'Absent Boolean is unknown' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].AuditDisabled='false'
Check 'String false is not Boolean false' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Items[0].AuditDisabled=$null
Check 'Null is not Boolean false' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].MissingFields=@('RejectDirectSend')
Check 'Reported missing fields prevents any source pass' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Count=2
Check 'Count mismatch prevents pass' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence=@($r.Evidence | Where-Object SourceId -ne 'exchange-organization')
Check 'Absent source unknown' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Items+=$r.Evidence[0].Items[0];$r.Evidence[0].Count=2
Check 'Multiple singleton results ambiguous' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[3].Items[1].EnableFileFilter=$null
Check 'One missing policy value blocks aggregate assessment' ((By @(& $evaluate -Result $r) 'EOP-FILE-FILTER').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[3].Items[1].EnableFileFilter=$true
Check 'All returned policies explicit true meets selected setting only' ((By @(& $evaluate -Result $r) 'EOP-FILE-FILTER').Status -eq 'Meets selected setting')
$r=Sample;$saved=[pscustomobject]@{Metadata=$r.Metadata;Coverage=$r.Evidence}
Check 'Standalone full Coverage supported' (@(& $evaluate -Result $saved).Count -eq 5)
$r=Sample;$r.Evidence[0].PSObject.Properties.Remove('Items')
Check 'Summary-only coverage not assessed' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$o=@(& $evaluate -Result $r -NotApplicable @{'EXO-DIRECT-SEND'='Synthetic explicit policy exception for demonstration only.'})
Check 'Only explicit applicability decision yields N/A' ((By $o 'EXO-DIRECT-SEND').Status -eq 'N/A')
$threw=$false;try{$null=& $evaluate -Result (Sample) -NotApplicable @{'EXO-DIRECT-SEND'=''}}catch{$threw=$true}
Check 'Blank applicability decision rejected' $threw
$r=Sample;$r.Evidence+=$r.Evidence[0];$threw=$false;try{$null=& $evaluate -Result $r}catch{$threw=$true}
Check 'Duplicate sources / naive merged runs rejected' $threw
$r=Sample;$before=$r|ConvertTo-Json -Depth 50;$null=& $evaluate -Result $r
Check 'Input evidence not mutated' (($r|ConvertTo-Json -Depth 50) -ceq $before)
$r=Sample;$roundTrip=$r|ConvertTo-Json -Depth 50|ConvertFrom-Json -Depth 50
$o=@(& $evaluate -Result $roundTrip)
Check 'Deserialized JSON evidence supported' ($o.Count -eq 5 -and (By $o 'EXO-AUDIT').Status -eq 'Meets selected setting')
$r=Sample;$r.Evidence[0].PSObject.Properties.Remove('Count')
Check 'Missing count remains unknown' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
foreach($invalidCount in @($true,1.0,'1',-1)){
 $r=Sample;$r.Evidence[0].Count=$invalidCount
 Check ('Noninteger or negative count rejected: '+$invalidCount.GetType().Name+' '+$invalidCount) ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
}
$r=Sample;$r.Evidence[0].Status=123
Check 'Nonstring source status unknown' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].Status='collected'
Check 'Status case is exact' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').Status -eq 'Not assessed')
$r=Sample;$r.Evidence[0].CollectedAtUtc=[datetime]'2026-01-01T00:00:00Z'
Check 'Deserialized timestamp remains ISO UTC' ((By @(& $evaluate -Result $r) 'EXO-AUDIT').EvidenceTime.StartsWith('2026-01-01T00:00:00'))
$r=Sample;$dict=$r|ConvertTo-Json -Depth 50|ConvertFrom-Json -Depth 50 -AsHashtable
Check 'Dictionary evidence supported' ((By @(& $evaluate -Result $dict) 'EXO-AUDIT').Status -eq 'Meets selected setting')
$o=@(& $evaluate -Result (Sample))
Check 'Stable profile version for all five checks' (@($o|Where-Object ProfileVersion -ne 'Flapjacks pilot 0.1').Count -eq 0)
$expected=@{'EXO-AUDIT'='PR.PS-04';'EXO-DIRECT-SEND'='PR.PS-01';'EXO-SMTP-AUTH'='PR.AA-03';'ENTRA-APP-REG'='PR.AA-05';'EOP-FILE-FILTER'='PR.PS-01'}
foreach($c in $o){Check ('Pilot mapping '+$c.ControlId) ($c.NistCsf20EvidenceMapping -eq $expected[$c.ControlId] -and $c.NistFramework -eq 'NIST CSF 2.0' -and $c.NistMappingNote -match 'not proof')}
Check 'Every check has official Microsoft and NIST references' (@($o|Where-Object {$_.Reference -notlike 'https://learn.microsoft.com/*' -or $_.NistReference -notlike 'https://csrc.nist.gov/*'}).Count -eq 0)
Check 'SMTP limit does not claim all mailbox coverage' ((By $o 'EXO-SMTP-AUTH').Limitation -match 'Mailbox overrides')
Check 'Policy aggregate limit retains rule/targeting gap' ((By $o 'EOP-FILE-FILTER').Limitation -match 'recipient targeting')
Check 'N/A source gap is not converted into a technical pass' ((By @(& $evaluate -Result (Sample) -NotApplicable @{'EXO-AUDIT'='Synthetic explicit exclusion'}) 'EXO-AUDIT').Status -eq 'N/A')
$threw=$false;try{$null=& $evaluate -Result (Sample) -NotApplicable @{'NOT-A-CONTROL'='reason'}}catch{$threw=$true}
Check 'Unknown applicability ID rejected' $threw
$tests|Format-Table -AutoSize
Write-Output ("PASS: "+$tests.Count+" offline synthetic posture checks; no tenant access or file exports.")
