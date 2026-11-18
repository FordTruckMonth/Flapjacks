#requires -Version 7.4
# Fixed offline conjunction of the existing two empty-list evaluators. No acquisition.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Fw74Workbook='92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'

# Resolve the same two native empty-list comparators in this candidate checkout.
# The focused fixtures exercise the reviewed primitive IDs and status mapping.
. (Join-Path $PSScriptRoot 'PassiveJson.ps1')
$script:Fw74Audit = Import-Module (Join-Path $PSScriptRoot '../M365SecurityAudit.psm1') -PassThru -DisableNameChecking -Scope Local

function Get-Fw74Value($Object,[string]$Key){
    if($Object -is [Collections.IDictionary] -and $Key -cin @($Object.Keys)){return ,$Object[$Key]}
    return $null
}
function Assert-Fw74Keys($Object,[string[]]$Allowed,[string[]]$Required){
    if($Object -isnot [Collections.IDictionary]){throw 'Expected a passive object.'}
    foreach($key in $Object.Keys){if($key -cnotin $Allowed){throw 'Unsupported contract field.'}}
    foreach($key in $Required){if($key -cnotin @($Object.Keys)){throw 'Missing contract field.'}}
}
function Test-Fw74Text($Value,[string]$Expected){return ($Value -is [string] -and $Value -ceq $Expected)}
function Get-FlapjacksWorkbookAllowlistComparison {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$EvidenceJson,
        [Parameter(Mandatory)][string]$ExpectedWorkbookSha256,
        [switch]$EnableExactWorkbookAllowlist
    )
    if(-not $EnableExactWorkbookAllowlist -or $ExpectedWorkbookSha256 -cne $script:Fw74Workbook){throw 'Exact workbook pin and explicit row74 selection required.'}
    try{
        if([string]::IsNullOrWhiteSpace($EvidenceJson) -or [Text.Encoding]::UTF8.GetByteCount($EvidenceJson) -gt 1048576){throw 'Input exceeds bound.'}
        $snapshot=ConvertFrom-FjcJson $EvidenceJson
        Assert-Fw74Keys $snapshot @('SchemaVersion','Metadata','Evidence') @('SchemaVersion','Metadata','Evidence')
        if(-not (Test-Fw74Text (Get-Fw74Value $snapshot 'SchemaVersion') 'FlapjacksWorkbookAllowlistEvidence/1')){throw 'Unsupported schema.'}
        $meta=Get-Fw74Value $snapshot 'Metadata'
        Assert-Fw74Keys $meta @('Mode','TenantId','RunId','ReferenceWorkbookSha256') @('Mode','TenantId','RunId','ReferenceWorkbookSha256')
        if(-not (Test-Fw74Text (Get-Fw74Value $meta 'Mode') 'Synthetic') -or -not (Test-Fw74Text (Get-Fw74Value $meta 'ReferenceWorkbookSha256') $script:Fw74Workbook)){throw 'Unsupported mode or workbook.'}
        $tenant=Get-Fw74Value $meta 'TenantId';$run=Get-Fw74Value $meta 'RunId';$guid=[guid]::Empty
        if($tenant -isnot [string] -or -not [guid]::TryParseExact($tenant,'D',[ref]$guid) -or $guid -eq [guid]::Empty -or $run -isnot [string] -or $run -cnotmatch '^synthetic-[a-z0-9-]{1,64}$'){throw 'Invalid supplied binding.'}
        $sources=Get-Fw74Value $snapshot 'Evidence'
        if($sources -isnot [array] -or $sources.Count -gt 1){throw 'Supply at most one dedicated source.'}
        $source=$null
        if($sources.Count){
            $source=$sources[0]
            Assert-Fw74Keys $source @('SourceId','Provider','Target','TenantId','RunId','Status','CompletenessClaim','CollectionScope','Count','MissingFields','Items') @('SourceId')
            if(-not (Test-Fw74Text (Get-Fw74Value $source 'SourceId') 'exchange-antispam-policies')){throw 'Unsupported source.'}
        }
    }catch{throw 'Workbook row74 evidence contract refused; no source interaction occurred.'}
    $comparison='Unknown';$reason='SourceMissing';$supplied=$null;$compared=$null
    $senderComparison='Unknown';$domainComparison='Unknown'
    if($null -ne $source){
        $items=Get-Fw74Value $source 'Items';$count=Get-Fw74Value $source 'Count';$missing=Get-Fw74Value $source 'MissingFields'
        if($items -is [array] -and $items.Count -le 512){$supplied=$items.Count}
        if(-not (Test-Fw74Text (Get-Fw74Value $source 'Provider') 'Exchange') -or -not (Test-Fw74Text (Get-Fw74Value $source 'Target') 'Get-HostedContentFilterPolicy')){$reason='SourceContractMismatch'}
        elseif(-not (Test-Fw74Text (Get-Fw74Value $source 'TenantId') $tenant) -or -not (Test-Fw74Text (Get-Fw74Value $source 'RunId') $run)){$reason='RunOrTenantMismatch'}
        elseif(-not (Test-Fw74Text (Get-Fw74Value $source 'Status') 'Collected') -or -not (Test-Fw74Text (Get-Fw74Value $source 'CompletenessClaim') 'Complete') -or -not (Test-Fw74Text (Get-Fw74Value $source 'CollectionScope') 'AllHostedContentFilterPolicies')){$reason='IncompleteOrUnestablishedScope'}
        elseif($items -isnot [array] -or $items.Count -gt 512 -or $count -isnot [long] -or $count -lt 0 -or $count -ne $items.Count){$reason='InvalidCountOrItems'}
        elseif($missing -isnot [array] -or $missing.Count -ne 0){$reason='MissingFields'}
        elseif($items.Count -eq 0){$reason='EmptySource'}
        else{
            $valid=$true;$identities=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach($item in $items){
                if($item -isnot [Collections.IDictionary] -or @($item.Keys | Where-Object {$_ -cnotin @('Identity','AllowedSenders','AllowedSenderDomains')}).Count){$valid=$false;$reason='UnsupportedPolicyRecord';break}
                $identity=Get-Fw74Value $item 'Identity'
                if($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or $identity.Length -gt 256 -or $identity.Trim() -cne $identity -or -not $identities.Add($identity)){$valid=$false;$reason='MissingOrDuplicatePolicyIdentity';break}
                foreach($field in @('AllowedSenders','AllowedSenderDomains')){
                    $value=Get-Fw74Value $item $field
                    # Bound strings and arrays before reusing the evaluator. Missing/null/scalar
                    # values are deliberately left for its established Unknown handling.
                    if($value -is [array]){
                        if($value.Count -gt 1000){$valid=$false;$reason='ListExceedsBound';break}
                        foreach($entry in $value){if($entry -is [string] -and $entry.Length -gt 320){$valid=$false;$reason='ListEntryExceedsBound';break}}
                    }elseif($value -is [string] -and $value.Length -gt 320){$valid=$false;$reason='ListEntryExceedsBound'}
                }
                if(-not $valid){break}
            }
            if($valid){
                # Same source and policy set for both primitives. No per-mailbox evidence,
                # existing checks, supplied verdicts, or reporting strings are trusted.
                $primitive=@(& $script:Fw74Audit {
                    param($s)
                    Get-FlapjacksMailBaselineChecks -Result @{Evidence=@($s)} -Baseline Standard |
                        Where-Object {$_.ControlId -cin @('EOP-SPAM-ALLOWED-SENDERS','EOP-SPAM-ALLOWED-DOMAINS')}
                } $source)
                if($primitive.Count -ne 2 -or ($primitive.ControlId -join '|') -cne 'EOP-SPAM-ALLOWED-SENDERS|EOP-SPAM-ALLOWED-DOMAINS'){throw 'Reviewed empty-list primitive contract changed.'}
                $map=@{'Meets selected setting'='Matches';'Needs action'='Differs';'Not assessed'='Unknown'}
                if($primitive[0].Status -cnotin @($map.Keys) -or $primitive[1].Status -cnotin @($map.Keys)){throw 'Unsupported primitive comparison.'}
                $senderComparison=$map[$primitive[0].Status];$domainComparison=$map[$primitive[1].Status]
                if($senderComparison -ceq 'Unknown' -or $domainComparison -ceq 'Unknown'){$reason='MissingOrMalformedListValues'}
                else{
                    $compared=$items.Count;$reason='CompleteSuppliedSyntheticListsCompared'
                    $comparison=if($senderComparison -ceq 'Matches' -and $domainComparison -ceq 'Matches'){'MatchesWorkbookPredicate'}else{'DiffersFromWorkbookPredicate'}
                }
            }
        }
    }
    $limit='Stored anti-spam policy lists only. Supplier scope, completeness, tenant/run labels and source authenticity remain unverified. Includes every supplied policy without inferring enabled rules, recipient coverage or effective bypasses. No Tenant Allow/Block List, transport exceptions, mailbox history, live protection or licensing assessment.'
    $predicate='For every supplied anti-spam policy, AllowedSenders and AllowedSenderDomains are both native empty arrays.'
    $row=[pscustomobject][ordered]@{ControlId='WB-REF-92B9-ROW-074';Control='Workbook row 74: no allowed senders or sender domains';Status='Not assessed';SourceStatus=if($null -eq $source){'Missing'}else{'OfflineSnapshot'};Comparison=$comparison;ReasonCode=$reason;ReferenceWorkbookSha256=$script:Fw74Workbook;Worksheet='Sheet1';PhysicalRow=74;ReferenceCells=@('A74','D74');SourceId='exchange-antispam-policies';ReadContract='Get-HostedContentFilterPolicy';Fields=@('AllowedSenders','AllowedSenderDomains');Predicate=$predicate;SuppliedPolicies=$supplied;ComparedPolicies=$compared;AllowedSendersComparison=$senderComparison;AllowedSenderDomainsComparison=$domainComparison;ReusedPrimitiveControlIds=@('EOP-SPAM-ALLOWED-SENDERS','EOP-SPAM-ALLOWED-DOMAINS');ComparisonAuthority='Owner-supplied workbook reference';Limitation=$limit}
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($EvidenceJson))).ToLowerInvariant()
    [pscustomobject][ordered]@{
        SchemaVersion='FlapjacksWorkbookAllowlistComparison/1'
        Metadata=[pscustomobject][ordered]@{Mode='Synthetic';Status='Not assessed';EvidenceSha256=$hash;ReferenceWorkbookSha256=$script:Fw74Workbook;LocalCombinedPredicateImplementationMatches=1;SourceAuthenticityVerified=$false;CompleteTenantCoverageVerified=$false;OverallWorkbookNumerator=$null;ProductionMappingsAdded=0;LiveValidations=0;NewSources=0;DefaultAWChanged=$false;MicrosoftBaselinesChanged=$false}
        ComparisonRows=@($row)
        DisplayRows=@([pscustomobject][ordered]@{Control='WB-REF-92B9-ROW-074 | Workbook anti-spam allowlists';Status='Not assessed';'Status details'=('Synthetic stored-list comparison: '+$comparison+'. Allowed senders: '+$senderComparison+'. Allowed sender domains: '+$domainComparison+'. Evidence condition: '+$reason+'.');Rationale=$predicate+' '+$limit;'M365 access/licensing/prerequisites'='Existing Exchange configuration fields only. Actual read access, licensing and complete tenant coverage are unverified. No new source, session or permission.'})
        SourceRows=@([pscustomobject][ordered]@{Source='supp-workbook-antispam-allowlists';SourceStatus=$row.SourceStatus;SuppliedRecords=$supplied})
        Notes=@('The two existing empty-list primitives are reused as one conjunction, not counted as two workbook rows. A known difference with a missing list still leaves the combined comparison Unknown.', 'Raw policy identities, addresses and domains remain with the caller. Only aggregate comparisons and an exact input-text hash are returned. No input values are logged or followed.', 'No overall workbook numerator is established and the historical 43 claim is not reverified. All assessments remain Not assessed.')
    }
}
Export-ModuleMember -Function Get-FlapjacksWorkbookAllowlistComparison
