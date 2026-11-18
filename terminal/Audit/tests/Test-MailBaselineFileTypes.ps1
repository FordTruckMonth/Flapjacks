#requires -Version 7.4
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$tests=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[bool]$Ok) {
    $tests.Add([pscustomobject]@{Test=$Name;Passed=$Ok})
    if (-not $Ok) { throw "FAILED: $Name" }
}

# Trap all related provider operations before loading the fixed registry.
$script:liveCalls=0
function Get-MalwareFilterPolicy { $script:liveCalls++; throw 'Unexpected tenant policy read' }
function Get-MalwareFilterRule { $script:liveCalls++; throw 'Unexpected tenant rule read' }
function Set-MalwareFilterPolicy { $script:liveCalls++; throw 'Unexpected tenant write' }
function Set-MalwareFilterRule { $script:liveCalls++; throw 'Unexpected tenant write' }
function Connect-ExchangeOnline { $script:liveCalls++; throw 'Unexpected authentication' }
function Invoke-RestMethod { $script:liveCalls++; throw 'Unexpected network request' }
function Invoke-WebRequest { $script:liveCalls++; throw 'Unexpected network request' }
. (Join-Path $PSScriptRoot '../src/MailBaselineFileTypes.ps1')
. (Join-Path $PSScriptRoot '../src/Catalog.ps1')

$definitions=@(Get-FlapjacksMailBaselineFileTypesDefinitions)
Check 'Exactly one fixed FileTypes coverage definition' ($definitions.Count -eq 1)
$definition=$definitions[0]
$required=@('Id','Name','SourceId','Target','Field','Kind','ValidValues','Standard','Strict','Rationale','Limitation','Reference','Access','Section')
Check 'Definition is a PSCustomObject with the existing public schema' ($definition -is [pscustomobject] -and ($definition.PSObject.Properties.Name -join ',') -ceq ($required -join ','))
Check 'Stable file-types control ID and collection predicate' ($definition.Id -ceq 'EOP-MALWARE-FILE-TYPES' -and $definition.Field -ceq 'FileTypes' -and $definition.Kind -ceq 'ContainsAllFileTypes')
Check 'File types are not reduced to an enum domain' ($definition.ValidValues -is [array] -and $definition.ValidValues.Count -eq 0)
Check 'Enablement and stored response are not duplicated' ($definition.Id -cnotin @('EOP-FILE-FILTER','EOP-MALWARE-FILE-ACTION') -and $definition.Field -cnotin @('EnableFileFilter','FileTypeAction'))
foreach ($name in @('Name','Rationale','Limitation','Reference','Access','Section')) {
    Check ('Nonempty '+$name) ($definition.$name -is [string] -and -not [string]::IsNullOrWhiteSpace($definition.$name))
}

# Reviewed independently against Microsoft Learn's default list, not the optional
# Defender-portal list, true-type-matching list, or a workbook custom list.
$reviewedDefaults='ace,ani,apk,app,appx,arj,bat,cab,cmd,com,deb,dex,dll,docm,elf,exe,hta,img,iso,jar,jnlp,kext,lha,lib,library,lnk,lzh,macho,msc,msi,msix,msp,mst,pif,ppa,ppam,reg,rev,scf,scr,sct,sys,uif,vb,vbe,vbs,vxd,wsc,wsf,wsh,xll,xz,z'
foreach ($profile in @('Standard','Strict')) {
    $values=$definition.$profile
    Check ($profile+' is an explicit fixed array of 53 file types') ($values -is [array] -and $values.Count -eq 53)
    Check ($profile+' exactly matches all 53 reviewed defaults') (($values -join ',') -ceq $reviewedDefaults)
    Check ($profile+' contains unique canonical strings only') (@($values | Sort-Object -Unique).Count -eq 53 -and @($values | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[a-z0-9]+$' }).Count -eq 0)
    Check ($profile+' does not mix optional extensions into Microsoft defaults') (@($values | Where-Object { $_ -cin @('7z','js','ps1','html','zip') }).Count -eq 0)
}
Check 'Profiles have independent arrays' (-not [object]::ReferenceEquals($definition.Standard,$definition.Strict))

$catalog=@(Get-AuditSourceCatalog)
$sources=@($catalog | Where-Object Id -CEQ $definition.SourceId)
Check 'Existing exact malware source selected' ($definition.SourceId -ceq 'exchange-malware-policies' -and $sources.Count -eq 1)
$source=$sources[0]
Check 'Exact existing Exchange cmdlet and projected field' ($source.Provider -ceq 'Exchange' -and $source.Target -ceq 'Get-MalwareFilterPolicy' -and $definition.Target -ceq $source.Target -and $source.Fields -ccontains 'FileTypes')
Check 'No new source scopes or read access requested' ($source.Scopes.Count -eq 0 -and $definition.Access -match '^Existing Exchange read access to Get-MalwareFilterPolicy' -and $definition.Access -match 'No new access is requested')
Check 'Precise official common-attachments reference and section' ($definition.Reference -ceq 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies' -and $definition.Section -ceq 'Anti-malware')
Check 'Rationale explicitly allows supersets of the documented defaults' ($definition.Rationale -match '53 default file types' -and $definition.Rationale -match 'both Standard and Strict' -and $definition.Rationale -match 'every documented default' -and $definition.Rationale -match 'permitting additional')
Check 'Coverage cannot imply enabled filtering or a response action' ($definition.Limitation -match 'EnableFileFilter is assessed separately by EOP-FILE-FILTER' -and $definition.Limitation -match 'FileTypeAction is assessed separately by EOP-MALWARE-FILE-ACTION')
Check 'Stored-policy, rule and effective-recipient limitations retained' ($definition.Limitation -match 'disabled or unassigned' -and $definition.Limitation -match 'Rule enablement' -and $definition.Limitation -match 'priority' -and $definition.Limitation -match 'preset precedence' -and $definition.Limitation -match 'recipient targeting' -and $definition.Limitation -match 'exclusions' -and $definition.Limitation -match 'does not establish effective recipient protection')
Check 'Workbook custom dangerous-extension and enabled-rule scope remains partial' ($definition.Limitation -match 'Workbook row 168 remains partial' -and $definition.Limitation -match 'not a comprehensive dangerous-extension list' -and $definition.Limitation -match 'custom extension list or enabled-rule requirement')
Check 'No message-handling or true-type validation claimed' ($definition.Limitation -match 'Actual attachment detection, true-type matching and message handling are not tested')

$before=Get-FlapjacksMailBaselineFileTypesDefinitions | ConvertTo-Json -Depth 10 -Compress
$definition.Standard[0]='synthetic-modified'
Check 'Mutating one profile cannot change the other' ($definition.Strict[0] -ceq 'ace')
$definition.Strict[1]='synthetic-modified'
$definition.Id='SYNTHETIC-MODIFIED'
$after=Get-FlapjacksMailBaselineFileTypesDefinitions | ConvertTo-Json -Depth 10 -Compress
Check 'Every call returns fresh fixed registry data' ($before -ceq $after)
Check 'No tenant reads, writes, authentication or network access' ($script:liveCalls -eq 0)
$tests | Format-Table -AutoSize
Write-Output ('PASS: '+$tests.Count+' offline MailBaselineFileTypes registry checks; no tenant access or file exports.')
