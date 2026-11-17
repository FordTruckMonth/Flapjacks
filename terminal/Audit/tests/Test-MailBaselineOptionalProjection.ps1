#requires -Version 7.4
# Local mock provider only; validates one call and snapshot compatibility.
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../M365SecurityAudit.psm1') -Force -DisableNameChecking
$m=Get-Module M365SecurityAudit
$fixed=@(Get-AuditSourceCatalog | Where-Object Id -in @('exchange-antiphish-policies','exchange-antispam-policies'))
$mock=New-Module -Name 'SyntheticMailProjection' -ScriptBlock {
    $script:Rows=@{};$script:Calls=0
    function Get-AntiPhishPolicy {[CmdletBinding()]param();$script:Calls++;$script:Rows['phish']}
    function Get-HostedContentFilterPolicy {[CmdletBinding()]param();$script:Calls++;$script:Rows['spam']}
    Export-ModuleMember -Function Get-AntiPhishPolicy,Get-HostedContentFilterPolicy
}
Import-Module $mock -Force
$checks=0
function Check($name,$ok){if(-not $ok){throw "Failed: $name"};$script:checks++}
$kr=@{phish='exchange-antiphish-policies';spam='exchange-antispam-policies'}
try{
 foreach($k in @('phish','spam')){
    $source=@($fixed|Where-Object Id -ceq $kr[$k])[0]
    Check 'Three optional fields in static approved contract' ($source.OptionalFields.Count -eq 3)
    Check 'Optional fields do not replace any prior required field' (-not @($source.OptionalFields | Where-Object {$_ -in $source.Fields}).Count)
    $data=[ordered]@{};foreach($p in $source.Fields){$data[$p]=$false};$data.Identity='synthetic policy'
    foreach($p in $source.OptionalFields){$data[$p]=if($p -like '*Action'){'Quarantine'}elseif($p -eq 'QuarantineRetentionPeriod'){30}else{$true}}
    & $mock {param($key,$row)$script:Rows[$key]=$row;$script:Calls=0} $k ([pscustomobject]$data)
    $ready=@{Connection=@{ModuleName='SyntheticMailProjection'}}
    $normal=& $m {param($src,$session) Read-AuditCommandSource -Source $src -Session $session} $source $ready
    Check 'Standard audit omits optional fields and calls exact getter once' ($normal.Status -eq 'Collected' -and $normal.RequestCount -eq 1 -and -not @(($normal.Items[0].PSObject.Properties.Name)|Where-Object {$_ -in $source.OptionalFields}).Count)
    $extended=& $m {param($src,$session) Read-AuditCommandSource -Source $src -Session $session -IncludeWorkbookMailFields} $source $ready
    Check 'Workbook projects all available optional fields without an extra GET' ($extended.Status -eq 'Collected' -and $extended.RequestCount -eq 1 -and @(($extended.Items[0].PSObject.Properties.Name)|Where-Object {$_ -in $source.OptionalFields}).Count -eq 3)
    Check 'Two explicit runs cause one invocation each' ((& $mock {$script:Calls}) -eq 2)
    foreach($p in $source.OptionalFields){[void]$data.Remove($p)}
    & $mock {param($key,$row)$script:Rows[$key]=$row;$script:Calls=0} $k ([pscustomobject]$data)
    $old=& $m {param($src,$session) Read-AuditCommandSource -Source $src -Session $session -IncludeWorkbookMailFields} $source $ready
    Check 'Unavailable optional fields do not corrupt earlier complete fields' ($old.Status -eq 'Collected' -and $old.RequestCount -eq 1 -and $old.MissingFields.Count -eq 0)
    $rows=@(& $m {param($r) Get-FlapjacksMailBaselineChecks -Baseline Standard -Result @{Evidence=@($r)}} $old)
    $affected=@($rows|Where-Object {$_.SourceId -eq $source.Id -and $_.Field -in $source.OptionalFields})
    Check 'Only available typed optional fields can support an assessment' ($affected.Count -eq 3 -and @($affected|Where-Object Status -ne 'Not assessed').Count -eq 0)
 }
}finally{Remove-Module $mock -Force}
Write-Output "PASS: $checks mock-only optional-projection assertions; no new provider calls or scopes."
