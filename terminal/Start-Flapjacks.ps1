#requires -Version 7.4
[CmdletBinding()]
param([ValidateSet('Live','Synthetic')][string]$Mode='Live')
& "$PSScriptRoot/Start-M365Toolkit.ps1" -Mode $Mode
