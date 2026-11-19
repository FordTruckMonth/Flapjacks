#requires -Version 7.4
<#
.SYNOPSIS
Reviews a packaged synthetic workbook fixture and optionally writes a local report.
.EXAMPLE
./terminal/Audit/Invoke-WorkbookFixtureReview.ps1 -EnableFixtureReview -FixtureVersion 5 -OutputDirectory ./fixture-review
.EXAMPLE
./terminal/Audit/Invoke-WorkbookFixtureReview.ps1 -EnableFixtureReview -RiskFixture conjoined
#>
[CmdletBinding()]
param([switch]$EnableFixtureReview, [ValidateSet('1','2','3','4','5')][string]$FixtureVersion='5',
        [ValidatePattern('\A[a-z0-9-]{1,80}\z')][string]$RiskFixture, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (-not $EnableFixtureReview) { throw 'Explicit fixture review opt-in is required.' }
$reviewer = Import-Module (Join-Path $PSScriptRoot 'workbook-fixture/WorkbookFixtureReview.psm1') -Scope Local -PassThru
& $reviewer.ExportedCommands['Invoke-RegisteredWorkbookFixtureReview'] @PSBoundParameters
