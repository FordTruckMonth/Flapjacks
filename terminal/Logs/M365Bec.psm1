#requires -Version 7.4
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Get-UtcQueryWindow.ps1"
foreach($file in @('Core','Paging','Live','Normalize','Report','Investigation')){. "$PSScriptRoot/src/$file.ps1"}
# Acquisition helpers stay private behind the explicit Live investigation entry point.
Export-ModuleMember -Function Invoke-BecInvestigation,New-BecContext,Test-BecManifest,Get-UtcQueryWindow
