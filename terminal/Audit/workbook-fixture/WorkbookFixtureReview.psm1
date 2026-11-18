#requires -Version 7.4
function Get-WorkbookFixtureComparison {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FixtureJson,
        [switch]$EnableFixtureReview,
        [string]$RiskFixture,
        [string]$OutputDirectory
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    if (-not $EnableFixtureReview) { throw 'Explicit fixture review opt-in is required.' }
    if ([Text.Encoding]::UTF8.GetByteCount($FixtureJson) -gt 2097152) { throw 'Fixture pack exceeds the size limit.' }

    $lib = $PSScriptRoot
    . (Join-Path $lib 'PassiveJson.ps1')
    $reference = '92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
    $newSettings = @('MailOrganizationSettings','LockboxOrganizationSettings')
    $allowed = @('SchemaVersion','Mode','ReferenceWorkbookSha256','Thresholds','Allowlists','Row93Fixture','Row167Fixture','ProjectedCollaboration','ConnectionFilter','ConditionalAccessRiskFixture','AuthorizationPolicy','OutboundForwarding','AuthenticationMigrationFixture') + $newSettings
    $pack = [ordered]@{}
    $document = [Text.Json.JsonDocument]::Parse($FixtureJson)
    try {
        if ($document.RootElement.ValueKind -ne 'Object') { throw 'Fixture pack must be an object.' }
        foreach ($property in $document.RootElement.EnumerateObject()) {
            $name = $property.Name
            if ($name -cnotin $allowed -or $pack.Contains($name)) { throw 'Unknown or duplicate fixture pack field.' }
            if ($name -cin $newSettings -or $name -cin @('Thresholds','Allowlists','ProjectedCollaboration','ConnectionFilter','AuthorizationPolicy','OutboundForwarding')) {
                # Preserve original numeric tokens and duplicate properties for each
                # evaluator. A refused envelope cannot change a sibling's evidence.
                if ($name -ceq 'ProjectedCollaboration') { $pack[$name] = $property.Value.Clone() }
                else { $pack[$name] = $property.Value.GetRawText() }
            } elseif ($property.Value.ValueKind -eq 'String') {
                $pack[$name] = $property.Value.GetString()
            } else {
                $pack[$name] = $null
            }
        }
    } finally { $document.Dispose() }
    $version = 0
    if ($pack['SchemaVersion'] -cmatch '\AFlapjacksWorkbookFixturePack/([1-5])\z') {
        $version = [int]$Matches[1]
    }
    if ($version -eq 0 -or
        ($version -lt 2 -and $pack.Contains('ConnectionFilter')) -or
        ($version -lt 3 -and ($pack.Contains('MailOrganizationSettings') -or $pack.Contains('LockboxOrganizationSettings'))) -or
        ($version -lt 4 -and ($pack.Contains('ConditionalAccessRiskFixture') -or $pack.Contains('AuthorizationPolicy'))) -or
        ($version -lt 5 -and ($pack.Contains('OutboundForwarding') -or $pack.Contains('AuthenticationMigrationFixture'))) -or
        $pack['Mode'] -cne 'Synthetic' -or $pack['ReferenceWorkbookSha256'] -cne $reference) {
        throw 'Expected a synthetic fixture pack for the reviewed workbook.'
    }

    . (Join-Path $lib 'Compare-ProjectedTeamsAndSharePoint.ps1')
    $definitions = [ordered]@{
        '31'  = @('exchange-antiphish-policies','PhishThresholdLevel','Every supplied policy has an integer from 2 through 4.')
        '69'  = @('exchange-antispam-policies','BulkThreshold','Every supplied policy has an integer from 1 through 6.')
        '74'  = @('exchange-antispam-policies','AllowedSenders + AllowedSenderDomains','Both lists are present and empty on every supplied policy.')
        '93'  = @('conditional-access','grantControls','A supported enabled policy declares a mandatory compliant-device grant.')
        '132' = @('workbook-teams-client','AllowEmailIntoChannel','One complete projected Global client configuration explicitly sets this field to false.')
        '144' = @('workbook-spo-tenant','DisallowInfectedFileDownload','One complete projected tenant configuration explicitly sets this field to true.')
        '167' = @('conditional-access','sessionControls.signInFrequency + grantControls','One supported enabled enrollment policy requires every-time sign-in frequency and mandatory built-in MFA.')
    }
    $rows = [ordered]@{}
    if ($version -ge 2) {
        $definitions['140'] = @('workbook-spo-tenant','ExternalUserExpirationRequired + ExternalUserExpireInDays',
            'Checks whether the tenant default enables guest expiry with an integer duration of 30 through 730 days. Site overrides and individual guest expiration remain unverified.')
        $definitions['165'] = @('exchange-connection-filter-policies','EnableSafeList',
            'Checks whether the uniquely named Default connection-filter policy stores EnableSafeList=false. Effective filtering and recipient coverage remain unverified.')
        $definitions['169'] = @('exchange-connection-filter-policies','IPAllowList',
            'Checks whether the uniquely named Default connection-filter policy stores an empty IPAllowList. Effective filtering and recipient coverage remain unverified.')
        $definitions['176'] = @('workbook-teams-protection','ZapEnabled',
            'Checks whether the single named Teams protection policy stores ZapEnabled=true. Rule exceptions, recipient coverage, eligibility and actual message removals remain unverified.')
    }
    if ($version -ge 3) {
        $definitions['83'] = @('exchange-atp-organization','EnableATPForSPOTeamsODB',
            'Checks whether the single organization configuration enables Defender protection for SharePoint, OneDrive and Teams. Entitlement, file scanning and effective coverage remain unverified.')
        $definitions['84'] = @('exchange-atp-organization','EnableSafeDocs',
            'Checks whether the single organization configuration enables Safe Documents. Client eligibility, user bypass and actual file handling remain unverified.')
        $definitions['157'] = @('exchange-organization','CustomerLockboxEnabled',
            'Checks whether the single Exchange organization configuration enables Customer Lockbox. Licensing, support request approvals and actual access remain unverified.')
    }
    if ($version -ge 4) {
        $definitions['117'] = @('conditional-access','conditions.signInRiskLevels',
            'Checks for an enabled block policy covering all users, resources and client types at high sign-in risk. The user-risk selector must be explicitly empty and there must be no exclusions. Tenant enforcement remains unverified.')
        $definitions['118'] = @('conditional-access','conditions.userRiskLevels',
            'Checks for an enabled block policy covering all users, resources and client types at high user risk. The sign-in-risk selector must be explicitly empty and there must be no exclusions. Tenant enforcement remains unverified.')
        $definitions['155'] = @('authorization-policy','defaultUserRolePermissions.allowedToCreateSecurityGroups',
            'Checks whether the default user role stores false for security group creation. Other permissions, Microsoft 365 group creation and actual creation outcomes remain unverified.')
    }
    if ($version -ge 5) {
        $definitions['76'] = @('exchange-outbound-spam-policies','AutoForwardingMode',
            'Checks whether every identified outbound spam policy in the supplied source stores Automatic. Microsoft Standard and Strict use Off. Assignments, actual forwarding and delivery remain unverified.')
        $definitions['141'] = @('workbook-spo-tenant','EmailAttestationRequired + EmailAttestationReAuthDays',
            'Checks whether SharePoint requires verification-code reauthentication within 1 to 15 days for ad-hoc external recipients who stay signed in. Guest authentication flow and actual sessions remain unverified.')
        $definitions['151'] = @('authentication-methods-policy','policyMigrationState + authenticationMethodConfigurations[].state',
            'Checks for completed migration and explicitly disabled SMS and Voice methods in the same captured policy. Effective authentication and actual user challenges remain unverified.')
    }
    foreach ($id in ($definitions.Keys | Sort-Object { [int]$_ })) {
        $d = $definitions[$id]
        $rows[$id] = [pscustomobject][ordered]@{
            Row=[int]$id; SourceId=$d[0]; Field=$d[1]; Predicate=$d[2]; StoredComparison='Unknown'
            Reason='FixtureNotSelected'; Status='Not assessed'; FullRowMappingCredit=0; LiveVerified=$false
        }
        if ($id -eq '151') {
            $rows[$id] | Add-Member -NotePropertyName Binding -NotePropertyValue $null
        }
        if ($id -in '117','118') {
            $rows[$id] | Add-Member -NotePropertyName WitnessOrdinals -NotePropertyValue @()
        }
    }
    function Set-Comparison([string]$Row, [string]$Value, [string]$Reason) {
        $normalized = switch -CaseSensitive ($Value) {
            { $_ -cin @('Matches','MatchesWorkbookPredicate','MatchesStoredConfiguration') } { 'Matches' }
            { $_ -cin @('Differs','DiffersFromWorkbookPredicate','DoesNotMatchStoredConfiguration') } { 'Differs' }
            'Unknown' { 'Unknown' }
            default { throw 'Unexpected comparison result from workbook evaluator.' }
        }
        $rows[$Row].StoredComparison = $normalized
        $rows[$Row].Reason = $Reason
    }

    if ($pack.Contains('Thresholds')) {
        Import-Module (Join-Path $lib 'FlapjacksWorkbookThresholds.psm1') -Scope Local
        try {
            $result = Get-FlapjacksWorkbookThresholdComparison -EnableExactWorkbookComparison -ExpectedWorkbookSha256 $reference -EvidenceJson $pack.Thresholds
            foreach ($r in $result.ComparisonRows) { Set-Comparison $r.PhysicalRow $r.Comparison $r.ReasonCode }
        } catch {
            if ($_.Exception.Message -cne 'Workbook evidence contract refused; no source interaction occurred.') { throw }
            foreach ($id in '31','69') { $rows[$id].Reason = 'FixtureContractRefused' }
        }
    }
    if ($pack.Contains('Allowlists')) {
        Import-Module (Join-Path $lib 'FlapjacksWorkbookAllowlist.psm1') -Scope Local
        try {
            $result = Get-FlapjacksWorkbookAllowlistComparison -EnableExactWorkbookAllowlist -ExpectedWorkbookSha256 $reference -EvidenceJson $pack.Allowlists
            $r = $result.ComparisonRows[0]
            Set-Comparison 74 $r.Comparison $r.ReasonCode
        } catch {
            if ($_.Exception.Message -cne 'Workbook row74 evidence contract refused; no source interaction occurred.') { throw }
            $rows['74'].Reason = 'FixtureContractRefused'
        }
    }
    function Read-SavedFixture([string]$Json) {
        try { return ,(ConvertFrom-FjcJson $Json) }
        catch {
            if ($_.Exception.Message -cne 'Invalid JSON: use bounded passive JSON with unique property names and supported numbers.') { throw }
            return $null
        }
    }
    if ($version -ge 2 -and $pack.Contains('ConnectionFilter')) {
        . (Join-Path $lib 'ConnectionFilter.ps1')
        foreach ($r in (Get-FlapjacksSyntheticConnectionFilterComparison -Result (Read-SavedFixture $pack.ConnectionFilter))) {
            Set-Comparison $r.Row $r.Comparison $r.Reason
        }
    }
    if ($version -ge 3 -and $pack.Contains('MailOrganizationSettings')) {
        . (Join-Path $lib 'MailOrganizationSettings.ps1')
        foreach ($r in (Get-FlapjacksSyntheticMailOrganizationComparison -Result (Read-SavedFixture $pack.MailOrganizationSettings))) {
            Set-Comparison $r.Row $r.Comparison $r.Reason
        }
    }
    if ($version -ge 3 -and $pack.Contains('LockboxOrganizationSettings')) {
        . (Join-Path $lib 'Compare-LockboxOrganizationSettings.ps1')
        $r = Get-FlapjacksSyntheticLockboxComparison -Result (Read-SavedFixture $pack.LockboxOrganizationSettings)
        Set-Comparison $r.Row $r.Comparison $r.Reason
    }
    if ($version -ge 4 -and $pack.Contains('AuthorizationPolicy')) {
        . (Join-Path $lib 'Compare-AuthorizationPolicy.ps1')
        $r = Get-FlapjacksSyntheticAuthorizationPolicyComparison -Result (Read-SavedFixture $pack.AuthorizationPolicy)
        Set-Comparison $r.Row $r.Comparison $r.Reason
    }
    if ($version -ge 4 -and $pack.Contains('ConditionalAccessRiskFixture')) {
        . (Join-Path $lib 'Compare-ConditionalAccessRiskFixtures.ps1')
        $selector = if ($RiskFixture) { $RiskFixture } else { $pack.ConditionalAccessRiskFixture }
        foreach ($r in (Get-FlapjacksSyntheticRiskComparison -FixtureId $selector)) {
            $reason = $r.Reason
            if ($r.WitnessOrdinals.Count -gt 0) {
                $label = if ($r.WitnessOrdinals.Count -eq 1) { 'Witness policy' } else { 'Witness policies' }
                $reason += ". $label " + ($r.WitnessOrdinals -join ', ')
            }
            Set-Comparison $r.Row $r.Comparison $reason
            $rows[[string]$r.Row].WitnessOrdinals = $r.WitnessOrdinals
        }
    }
    if ($version -ge 5 -and $pack.Contains('OutboundForwarding')) {
        . (Join-Path $lib 'Compare-OutboundForwarding.ps1')
        $r = Get-FlapjacksSyntheticOutboundForwardingComparison -Result (Read-SavedFixture $pack.OutboundForwarding)
        Set-Comparison $r.Row $r.Comparison $r.Reason
    }
    if ($version -ge 5 -and $pack.Contains('AuthenticationMigrationFixture')) {
        . (Join-Path $lib 'Compare-AuthenticationMigration.ps1')
        $r = Get-FlapjacksSyntheticMigrationComparison -FixtureId $pack.AuthenticationMigrationFixture -ReferenceWorkbookSha256 $reference
        Set-Comparison $r.Row $r.Comparison $r.Reason
        $rows['151'].Binding = $r.Binding
    }
    if ($pack.Contains('ProjectedCollaboration')) {
        $projected = [Collections.Generic.List[object]]::new()
        if ($pack.ProjectedCollaboration.ValueKind -eq 'Array') {
            foreach ($item in $pack.ProjectedCollaboration.EnumerateArray()) {
                if ($item.ValueKind -ne 'Object') { continue }
                try { $projected.Add((ConvertFrom-FjcJson $item.GetRawText())) }
                catch {
                    if ($_.Exception.Message -cne 'Invalid JSON: use bounded passive JSON with unique property names and supported numbers.') { throw }
                    # Retain an unusable record for each named source. Dropping it
                    # could allow a second record for that source to appear unique.
                    foreach ($label in $item.EnumerateObject()) {
                        if ($label.Name -ieq 'SourceId' -and $label.Value.ValueKind -eq 'String') {
                            $projected.Add(@{SourceId=$label.Value.GetString()})
                        }
                    }
                }
            }
        }
        $comparisons = Get-FlapjacksSyntheticCollaborationComparison -Evidence $projected.ToArray()
        foreach ($r in $comparisons) {
            $reason = if ($r.Comparison -ceq 'Unknown') { 'IncompleteProjectedEvidence' } else { 'ComparedProjectedSetting' }
            Set-Comparison $r.Row $r.Comparison $reason
        }
        if ($version -ge 2) {
            . (Join-Path $lib 'Compare-CollaborationSettings.ps1')
            foreach ($r in (Get-FlapjacksAdditionalCollaborationComparison -Evidence $projected.ToArray())) {
                $reason = if ($r.Comparison -ceq 'Unknown') { 'IncompleteProjectedEvidence' } else { 'ComparedProjectedSetting' }
                Set-Comparison $r.Row $r.Comparison $reason
            }
        }
        if ($version -ge 5) {
            . (Join-Path $lib 'Compare-SharePointReauthentication.ps1')
            $r = Get-FlapjacksSyntheticSharePointReauthenticationComparison -ProjectedJson $pack.ProjectedCollaboration
            Set-Comparison $r.Row $r.Comparison $r.Reason
        }
    }

    if ($pack.Contains('Row93Fixture') -or $pack.Contains('Row167Fixture')) {
        $ca = Join-Path $lib 'ca'
        $integrity = Join-Path $ca 'support/Integrity.ps1'
        if ((Get-FileHash $integrity).Hash -ne 'ef973e6a35194b51d2d842fa5277c22588de54a1c740adaa961542717ec38555' -or
            (Get-FileHash (Join-Path $ca 'package-manifest.json')).Hash -ne '5b62299b5a75ca97cf23e073a40ae8a711c229a5b8970f64ff5a12d1639d48d7') {
            throw 'Conditional Access fixture package identity changed.'
        }
        . $integrity
        Assert-PortablePayload $ca
        foreach ($id in '93','167') {
            $key = "Row${id}Fixture"
            if (-not $pack.Contains($key)) { continue }
            $selector = $pack[$key]
            if ($selector -isnot [string] -or $selector -cnotmatch '\A[a-z0-9-]{1,80}\z') {
                $rows[$id].Reason = 'InvalidFixtureIdentifier'
                continue
            }
            try {
                if ($id -eq '93') {
                    Import-Module (Join-Path $ca 'adapters/row93/src/FlapjacksMandatoryDeviceCompliance.psm1') -Scope Local -DisableNameChecking
                    $r = (Get-FlapjacksMandatoryDeviceCompliance -FixtureId $selector -EnableFixtureReview).Rows[0]
                    Set-Comparison $id $r.StoredComparison $r.ReasonCode
                } else {
                    Import-Module (Join-Path $ca 'adapters/row167/EnrollmentMfa.psm1') -Scope Local -DisableNameChecking
                    $r = Get-EnrollmentMfaComparison -FixtureId $selector -EnableFixtureReview
                    Set-Comparison $id $r.SamePolicySessionAndMandatoryBuiltinMfa 'RegisteredSamePolicyComparison'
                }
            } catch {
                # Keep evidence refusals local to their row. Broken modules and
                # altered registries are errors and must fail the review.
                $message = $_.Exception.Message
                if ($message -ceq 'Unregistered fixture refused.') { $rows[$id].Reason = 'UnregisteredFixture' }
                elseif ($message -cin @('Exact source binding refused.', 'Declared tenant or mode binding refused.',
                    'Incident, continuation or conflicting identity refused.', 'Only bounded configuration evidence is supported.',
                    'Invalid JSON: use bounded passive JSON with unique property names and supported numbers.',
                    'Review intent binding refused.')) { $rows[$id].Reason = 'FixtureContractRefused' }
                else { throw }
            }
        }
    }

    $review = [pscustomobject][ordered]@{
        SchemaVersion=$pack.SchemaVersion.Replace('FixturePack/','FixtureReview/')
        Mode='Synthetic'; Rows=@($rows.Values)
        VerifiedCoverageNumerator=$null; NewFullRowMappings=0; LiveValidations=0
    }
    if ($OutputDirectory) {
        $audit = Import-Module (Join-Path $lib '../M365SecurityAudit.psm1') -Scope Local -PassThru -DisableNameChecking
        . (Join-Path $lib 'Write-WorkbookFixtureReview.ps1')
        Write-WorkbookFixtureReview -Review $review -AuditModule $audit -OutputDirectory $OutputDirectory
    }
    $review
}

function Invoke-RegisteredWorkbookFixtureReview {
    [CmdletBinding()]
    param([switch]$EnableFixtureReview, [ValidateSet('1','2','3','4','5')][string]$FixtureVersion='5',
        [ValidatePattern('\A[a-z0-9-]{1,80}\z')][string]$RiskFixture, [string]$OutputDirectory)
    if (-not $EnableFixtureReview) { throw 'Explicit fixture review opt-in is required.' }
    if ($RiskFixture -and $FixtureVersion -notin '4','5') { throw 'Risk fixtures require version 4 or 5.' }
    $packs = @{
        '1' = @('workbook-review.synthetic.json', 'f80cdfbb8a386a4031d6c59e0ce202c07ca38cacf9aa351ca96332f113a3e982')
        '2' = @('workbook-review-v2.synthetic.json', '6780aa20d552b1f1844a19f20e67f73ac82b011fee34700ea964a23cfd3174f6')
        '3' = @('workbook-review-v3.synthetic.json', 'c79f0a473b74a51e74091310f34d179ec4d68bb1042a0658b1ca68c88dc56926')
        '4' = @('workbook-review-v4.synthetic.json', 'b35a1a83c3c95503730539c17a5e4c1733eea58620260240f167c8f7ab8d8e62')
        '5' = @('workbook-review-v5.synthetic.json', 'c3b3c1289aafdbf73c0a183f1fdd10a7f3ccf2b7f5ded1557dddbc2d3bbf4556')
    }
    $name, $expectedHash = $packs[$FixtureVersion]
    $file = Join-Path $PSScriptRoot "../fixtures/$name"
    # Verify exactly the bytes passed to the evaluator.
    $bytes = [IO.File]::ReadAllBytes($file)
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    if ($actual -ine $expectedHash) { throw 'Packaged synthetic fixture integrity check failed.' }
    $fixtureJson = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Get-WorkbookFixtureComparison -FixtureJson $fixtureJson -EnableFixtureReview -RiskFixture $RiskFixture -OutputDirectory $OutputDirectory
}
Export-ModuleMember -Function Invoke-RegisteredWorkbookFixtureReview
