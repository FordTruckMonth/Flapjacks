#requires -Version 7.4
<#
.SYNOPSIS
Runs the standalone release tests for the registered synthetic workbook reviewer.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory, [switch]$RequireRiskRuntime)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new test output directory.' }
$dir = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
$exe = (Get-Process -Id $PID).Path
$tests = @(
    'Test-RegisteredWorkbookFixtures','Test-WorkbookFixtureReview','Test-WorkbookFixtureReviewV2',
    'Test-WorkbookFixtureReviewV3','Test-WorkbookFixtureReviewV4','Test-WorkbookFixtureReviewV5',
    'Test-SyntheticOutboundForwardingComparison','Test-SharePointReauthenticationFixture','Test-SyntheticAuthenticationMigration','Test-ConditionalAccessFixtures',
    'Test-SyntheticConditionalAccessRiskFixtures','Test-SyntheticAuthorizationPolicyComparison',
    'Test-ProjectedCollaborationSettings','Test-SyntheticConnectionFilterComparison','Test-WorkbookRow165',
    'Test-WorkbookRow169','Test-WorkbookGlobalSettings','Test-SyntheticMailOrganizationComparison','Test-SyntheticLockboxComparison'
)
foreach ($test in $tests) {
    $arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot "$test.ps1"))
    if ($test -ceq 'Test-RegisteredWorkbookFixtures' -or $test -clike 'Test-WorkbookFixtureReview*') {
        $arguments += @('-OutputDirectory',(Join-Path $dir $test))
    }
    if ($RequireRiskRuntime -and $test -ceq 'Test-WorkbookFixtureReviewV4') { $arguments += '-RequireRiskRuntime' }
    if ($RequireRiskRuntime -and $test -ceq 'Test-SyntheticAuthenticationMigration') { $arguments += '-RequireRuntime' }
    $stdout = & $exe @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $stdout | Set-Content -LiteralPath (Join-Path $dir "$test.txt")
    if ($exitCode -ne 0) { throw "$test failed. See its test output." }
}
[pscustomobject]@{Passed=$true;Suites=$tests.Count;RiskRuntimeRequired=[bool]$RequireRiskRuntime}
