#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('Fixture','Live')][string]$Mode='Fixture',
    [string]$TargetUpn,
    [ValidateRange(1,90)][int]$LookbackDays=30,
    [DateTimeOffset]$StartUtc,[DateTimeOffset]$EndUtc,
    [string]$FixturePath="$PSScriptRoot/fixtures/bec-synthetic.json",
    [string]$OutputRoot="$PSScriptRoot/cases",
    [switch]$IncludeDefender,[switch]$IncludeNonInteractivePreview,[switch]$NonInteractive,
    [ValidateRange(1,100)][int]$MaxPages=20,
    [ValidateRange(1,2000)][int]$MaxDetails=200,
    [ValidateRange(1,1000)][int]$MaxFolders=100
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot/M365Bec.psm1" -Force -DisableNameChecking
if(-not $TargetUpn){if($NonInteractive){throw 'Provide -TargetUpn in noninteractive mode'};$TargetUpn=Read-Host 'Target user principal name (no password)'}
if(-not $NonInteractive -and -not $PSBoundParameters.ContainsKey('LookbackDays') -and -not $PSBoundParameters.ContainsKey('StartUtc')){
    $answer=Read-Host 'Lookback days [30]';if($answer){$days=0;if(-not [int]::TryParse($answer,[ref]$days) -or $days -lt 1 -or $days -gt 90){throw 'Lookback must be 1–90 days'};$LookbackDays=$days}
}
if(-not $PSBoundParameters.ContainsKey('EndUtc')){
    $EndUtc=if($Mode -eq 'Fixture'){[DateTimeOffset](Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json).ReferenceUtc}else{[DateTimeOffset]::UtcNow}
}
if(-not $PSBoundParameters.ContainsKey('StartUtc')){$StartUtc=$EndUtc.AddDays(-$LookbackDays)}
$context=if($Mode -eq 'Live'){New-BecContext -MaxPages $MaxPages -MaxDetails $MaxDetails -MaxFolders $MaxFolders}else{$null}
# No authentication, installation or remediation is performed here. Live mode uses preexisting sessions.
Invoke-BecInvestigation -TargetUpn $TargetUpn -Start $StartUtc -End $EndUtc -Mode $Mode -FixturePath $FixturePath -OutputRoot $OutputRoot -ProjectRoot $PSScriptRoot -IncludeDefender:$IncludeDefender -IncludeNonInteractivePreview:$IncludeNonInteractivePreview -Context $context
