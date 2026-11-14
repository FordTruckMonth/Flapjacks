#requires -Version 7.4
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Get-UtcQueryWindow.ps1"
foreach($file in @('Core','Paging','Live','Normalize','Report','Investigation')){. "$PSScriptRoot/src/$file.ps1"}
Export-ModuleMember -Function *-Bec*,Get-UtcQueryWindow
