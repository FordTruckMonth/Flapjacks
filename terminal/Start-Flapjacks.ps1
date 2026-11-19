#requires -Version 7.4
[CmdletBinding()]
param([ValidateSet('Live')][string]$Mode)
& "$PSScriptRoot/Start-M365Toolkit.ps1" @PSBoundParameters
