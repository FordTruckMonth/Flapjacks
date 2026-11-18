# Fixed, read-only comparisons of saved settings; no collection or authentication.
function Get-FlapjacksMailBaselineDefinitions {
    Get-FlapjacksMailBaselineAntiphishDefinitions
    Get-FlapjacksMailBaselineSpamDefinitions
    Get-FlapjacksMailBaselineProtectionDefinitions
    Get-FlapjacksMailBaselineFileTypesDefinitions
}

function Get-FlapjacksMailBaselineChecks {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result,[ValidateSet('None','Standard','Strict')][string]$Baseline='None')
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    function IsList($x) {
        $null -ne $x -and $x -is [Collections.IEnumerable] -and
            $x -isnot [string] -and $x -isnot [Collections.IDictionary]
    }
    function IsInteger($x) {
        $x -is [byte] -or $x -is [sbyte] -or $x -is [int16] -or $x -is [uint16] -or
         $x -is [int32] -or $x -is [uint32] -or $x -is [int64]
    }
    $Baseline=switch($Baseline){'Standard'{'Standard'} 'Strict'{'Strict'} default{'None'}}
    $rows=Get-AuditProperty $Result 'Evidence'
    if($null -eq $rows -or ((IsList $rows) -and @($rows).Count -eq 0)){$rows=Get-AuditProperty $Result 'Coverage'}
    if(-not (IsList $rows) -or -not @($rows).Count){throw 'Full saved Evidence or Coverage source records are required; no tenant reads will be performed.'}
    $byId=@{}
    foreach($row in $rows) {
        $id=Get-AuditProperty $row 'SourceId'
        if($id -isnot [string] -or $id -cnotmatch '^[a-z][a-z0-9-]{0,99}$' -or $byId.ContainsKey($id)){
            throw 'Invalid or duplicate source ID; combining runs requires provenance-aware reconciliation.'
        }
        $byId[$id]=$row
    }
    $catalog=@{}; foreach($source in Get-AuditSourceCatalog){$catalog[$source.Id]=$source}
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($def in Get-FlapjacksMailBaselineDefinitions) {
        $contract=$catalog[$def.SourceId]
        if($null -eq $contract -or $contract.Provider -cne 'Exchange' -or $def.Target -cne $contract.Target -or
            $def.Field -cnotin (@($contract.Fields)+@((Get-AuditProperty $contract 'OptionalFields' @()))) -or -not $ids.Add($def.Id) -or
            ($def.Reference -cnotmatch '^https://learn\.microsoft\.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#[a-z0-9-]+$' -and
             $def.Reference -cne 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies')){
            throw 'Invalid or duplicate Microsoft mail-control definition.'
        }
        $global=Get-AuditProperty $def 'Global'
        $hasGlobal=$global -is [bool]
        $referenceProfile=if($hasGlobal){'Microsoft global'}else{$Baseline}
        $expected=if($hasGlobal){$global}elseif($Baseline -ne 'None'){Get-AuditProperty $def $Baseline}else{$null}
        if($def.Kind -ceq 'ContainsAllFileTypes' -and $null -ne $expected){
            if(-not (IsList $expected) -or @($expected).Count -ne 53 -or @($expected|Sort-Object -Unique).Count -ne 53){throw 'Invalid documented extension definition.'}
        }
        $source=$byId[$def.SourceId]; $validatedValueCount=0;$matching=0
        $idsForLocal=[Collections.Generic.List[string]]::new();$observedValues=[Collections.Generic.List[object]]::new()
        $status='Not assessed'
        $reason='No matching saved Exchange configuration evidence was supplied.'
        $items=Get-AuditProperty $source 'Items'
        $count=Get-AuditProperty $source 'Count'
        $missing=Get-AuditProperty $source 'MissingFields'
        $state=Get-AuditProperty $source 'Status' 'Missing'
        $builtInSkipped=0
        if($Baseline -eq 'None' -and -not $hasGlobal) {
            $reason='No Microsoft Standard or Strict comparison profile was selected.'
        }elseif($null -eq $expected){
            $reason='Microsoft does not define this setting for the selected Standard/Strict policy profile.'
        }elseif($null -ne $source) {
            $provider=Get-AuditProperty $source 'Provider';$target=Get-AuditProperty $source 'Target'
            if($provider -isnot [string] -or $provider -cne 'Exchange' -or $target -isnot [string] -or $target -cne $def.Target) {
                $reason='Saved evidence does not carry the expected Exchange Online command provenance.'
            }elseif($state -isnot [string] -or $state -cne 'Collected'){
                $reason='A complete successful source read is required; the saved source is incomplete or unavailable.'
            }elseif(-not (IsList $items) -or -not (IsInteger $count) -or $count -ne @($items).Count -or
                -not (IsList $missing) -or @($missing).Count){
                $reason='Required saved fields or count are incomplete or malformed.'
            }elseif($count -eq 0) {
                $reason='The successful source read returned no records; the setting cannot be assessed.'
            }else{
                $reason=''
                foreach($item in $items){
                    if((Get-AuditProperty $def 'ExcludeBuiltIn' $false) -ceq $true){
                        $builtIn=Get-AuditProperty $item 'IsBuiltInProtection'
                        if($builtIn -isnot [bool]){$reason='The saved result cannot distinguish built-in protection from other policies.';break}
                        if($builtIn){$builtInSkipped++;continue}
                    }
                    $value=Get-AuditProperty $item $def.Field
                    $valid=$false;$meets=$false
                    switch($def.Kind){
                        'Boolean' {if($value -is [bool]){$valid=$true;$meets=$value -ceq $expected}}
                        'Enumeration' {
                            $known=@((Get-AuditProperty $def 'ValidValues' @()))
                            if($value -is [string] -and $value -in $known) {$valid=$true;$meets=$value -eq $expected}
                        }
                        {$_ -in @('IntegerExact','IntegerMin','IntegerMax')} {
                            $min=Get-AuditProperty $def 'Minimum' 0
                            $max=Get-AuditProperty $def 'Maximum' ([int]::MaxValue)
                            if((IsInteger $value) -and $value -ge $min -and $value -le $max){
                                if($value -eq 0 -and (Get-AuditProperty $def 'ZeroMeansUnknown' $false) -ceq $true){
                                    $reason='The saved limit uses the service default; its effective numeric limit was not collected.'
                                }else{
                                    $valid=$true
                                    $meets=switch($def.Kind){'IntegerExact'{$value -eq $expected} 'IntegerMin'{$value -ge $expected} 'IntegerMax'{$value -le $expected}}
                                }
                            }
                        }
                        'ContainsAllFileTypes' {
                            if((IsList $value) -and -not @($value|Where-Object {$_ -isnot [string] -or $_ -notmatch '\A\.?[A-Za-z0-9]{1,16}\z'}).Count){
                                $seenTypes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                                foreach($extension in $value){[void]$seenTypes.Add($extension.TrimStart('.'))}
                                $hasCount=@($expected|Where-Object {$seenTypes.Contains($_)}).Count
                                $valid=$true;$meets=$hasCount -eq @($expected).Count
                            }
                        }
                        'EmptyList' {
                            if((IsList $value) -and -not @($value | Where-Object {$null -eq $_ -or $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)}).Count) {
                                $valid=$true; $meets=@($value).Count -eq 0
                            }
                        }
                    }
                    if(-not $valid){if(-not $reason){$reason='A required value is missing, unrecognized, out of range or the wrong type.'};break}
                    if($def.Kind -eq 'EmptyList'){$observedValues.Add(@($value).Count)}elseif($def.Kind -ceq 'ContainsAllFileTypes'){$observedValues.Add($hasCount)}else{$observedValues.Add($value)}
                    $validatedValueCount++
                    if($meets){$matching++}
                    $object=Get-AuditProperty $item 'Identity'
                    if($object -is [string] -and -not [string]::IsNullOrWhiteSpace($object)){$idsForLocal.Add($object)}
                }
                if(-not $reason -and $validatedValueCount -eq 0){$reason='Only built-in protection records were returned; their settings are separate from Standard and Strict.'}
                if(-not $reason){
                    $status=if($matching -eq $validatedValueCount){'Meets selected setting'}else{'Needs action'}
                    $reason="$matching of $validatedValueCount applicable saved records match the $referenceProfile recommendation."
                    if($def.Kind -in @('EmptyList','ContainsAllFileTypes') -or $def.Kind -like 'Integer*'){
                        $range=$observedValues | Measure-Object -Minimum -Maximum
                        $observedText=if($range.Minimum -eq $range.Maximum){[string]$range.Minimum}else{[string]$range.Minimum+' to '+[string]$range.Maximum}
                        if($def.Kind -eq 'EmptyList'){$reason+=" Observed $($def.Field) entries per record: $observedText."}
                        elseif($def.Kind -ceq 'ContainsAllFileTypes'){$reason+=" Documented default types present per record: $observedText of $(@($expected).Count)."}
                        else{$reason+=" Observed $($def.Field): $observedText."}
                    }else{
                        $displayValues=if($def.Kind -eq 'Boolean'){@($observedValues | ForEach-Object {$_.ToString().ToLowerInvariant()} | Sort-Object -Unique)}
                                       else{@($observedValues | Sort-Object -Unique)}
                        $reason+=" Observed $($def.Field): "+($displayValues -join ', ')+'.'
                    }
                }
                if($builtInSkipped){$reason+=" Built-in protection records excluded: $builtInSkipped."}
            }
        }
        $desired=if($null -eq $expected){
            if($Baseline -eq 'None'){'Select Standard or Strict to compare Microsoft recommendations.'}else{'No Standard/Strict recommendation for this setting.'}
        }else{
            $predicate=switch($def.Kind){
                'EmptyList'{$def.Field+' has no entries'}
                'ContainsAllFileTypes'{$def.Field+' contains all '+@($expected).Count+' documented default types'}
                'IntegerMin'{$def.Field+' >= '+$expected}
                'IntegerMax'{$def.Field+' <= '+$expected}
                'Boolean'{$def.Field+' = '+$expected.ToString().ToLowerInvariant()}
                default{$def.Field+' = '+$expected}
            }
            "$referenceProfile recommendation: $predicate."
        }
        $timestamp=Get-AuditProperty $source 'CollectedAtUtc' ''
        if($timestamp -is [datetime] -or $timestamp -is [datetimeoffset]){$timestamp=$timestamp.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
        if($timestamp -isnot [string]){$timestamp=''}
        [pscustomobject][ordered]@{
            ControlId=$def.Id;Control=$def.Name;Status=$status;SourceId=$def.SourceId;Field=$def.Field;SourceStatus=$state
            EvidenceIds=$idsForLocal.ToArray();EvidenceTime=$timestamp;Observed=$reason;Expected=$desired;Rationale=$def.Rationale
            Limitation=$def.Limitation;Reference=$def.Reference;ProfileVersion=$(if($hasGlobal){'Flapjacks Microsoft global mail policy 0.1'}else{'Flapjacks Microsoft mail policy 0.1 / '+$Baseline})
            NistCsf20EvidenceMapping='PR.PS-01';NistFramework='NIST CSF 2.0'
            NistReference='https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final'
            NistMappingNote='Analyst-selected supporting evidence only; not NIST outcome attainment.'
            AccessPrerequisites=$def.Access;Section=$def.Section;RecommendationAuthority='Microsoft';StatusDetailsSafe=$reason
        }
    }
}
