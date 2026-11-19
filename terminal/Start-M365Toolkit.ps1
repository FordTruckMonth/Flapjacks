#requires -Version 7.4
[CmdletBinding()]
param([ValidateSet('Live')][string]$Mode)
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('Mode')){
    try{$liveChoice=Read-Host 'Type LIVE to enable Microsoft sign-in, session access and live workflows; Enter cancels'}
    catch{Write-Host 'Startup canceled; no Microsoft session was inspected or opened.';return}
    if($liveChoice -ine 'LIVE'){Write-Host 'Startup canceled; no Microsoft session was inspected or opened.';return}
    $Mode='Live'
}
Import-Module "$PSScriptRoot/M365Toolkit.psm1" -DisableNameChecking
try{Invoke-M365Terminal -Mode $Mode | Out-Null}catch{Write-Error ('Stopped safely: '+(ConvertTo-ToolkitText $_.Exception.Message));exit 1}
