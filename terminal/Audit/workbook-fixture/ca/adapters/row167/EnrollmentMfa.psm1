#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot src/FlapjacksEnrollmentFrequency.psm1
if ((Get-FileHash -Algorithm SHA256 $path).Hash -ne 'c3572fcc3e67d00468a685f78d813f45c24fae04b35d14347570ae07713939a4') {
    throw 'Unexpected fixture module identity'
}
$script:SessionModule = Import-Module $path -PassThru -DisableNameChecking

function Get-EnrollmentMfaComparison {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{1,80}$')][string]$FixtureId,
          [switch]$EnableFixtureReview)

    $session = Get-FlapjacksEnrollmentFrequency -FixtureId $FixtureId -EnableFixtureReview:$EnableFixtureReview
    $row = $session.Rows[0]
    $combined = $row.StoredComparison
    if ($combined -ceq 'MatchesStoredConfiguration') {
        # The public session evaluator verified fixture binding, source completeness and
        # supported policy shapes. Re-evaluate each individual policy before combining.
        $combined = & $script:SessionModule {
            param($id)
            $registered = Fixture-R $id
            $audit = Parse-R $registered.AuditJson 131072
            $match = $false
            $unresolved = $false
            foreach ($policy in $audit.Coverage[0].Items) {
                if ((Policy-S $policy).Comparison -cne 'MatchesStoredConfiguration') { continue }
                $grant = $policy.grantControls
                if ($null -eq $grant) { continue }
                $controls = $grant.builtInControls
                $outOfScope = @($controls | Where-Object { $_ -cnotin @('mfa', 'compliantDevice') })
                if ($outOfScope.Count -gt 0 -or $controls.Count -eq 0 -or @($controls | Select-Object -Unique).Count -ne $controls.Count) {
                    $unresolved = $true
                    continue
                }
                if ($grant.operator -ceq 'OR' -and -not $grant.Contains('authenticationStrength')) {
                    $unresolved = $true
                    continue
                }
                # Policy-S already requires explicit empty terms/custom factors and rejects
                # non-null strength, unsupported controls and unknown operators.
                if ('mfa' -cin $controls -and ($grant.operator -ceq 'AND' -or $controls.Count -eq 1)) {
                    $match = $true
                }
            }
            if ($unresolved) { return 'Unknown' }
            if ($match) { return 'MatchesStoredConfiguration' }
            return 'DoesNotMatchStoredConfiguration'
        } $FixtureId
    }
    [pscustomobject][ordered]@{
        PhysicalRow = $row.PhysicalRow
        SessionOnly = $row.StoredComparison
        SamePolicySessionAndMandatoryBuiltinMfa = $combined
        WorkbookCriterion = $row.WorkbookCriterion
        Status = $row.Status
        EffectiveOutcomeVerified = $row.EffectiveOutcomeVerified
        FullRowMappingCredit = $row.FullRowMappingCredit
        LiveCoverageCredit = $session.Metadata.NewLiveCoverage
    }
}
Export-ModuleMember -Function Get-EnrollmentMfaComparison
