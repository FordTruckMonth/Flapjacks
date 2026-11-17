#requires -Version 7.4
[CmdletBinding()]
param([ValidateSet('Live','Synthetic')][string]$Mode='Live')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot/M365Toolkit.psm1" -DisableNameChecking
try{Invoke-M365Terminal -Mode $Mode | Out-Null}catch{Write-Error ('Stopped safely: '+(ConvertTo-ToolkitText $_.Exception.Message));exit 1}
