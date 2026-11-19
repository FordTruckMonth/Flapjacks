#requires -Version 7.4
[CmdletBinding()]
param([ValidateSet('Live')][string]$Mode)
& "$PSScriptRoot/terminal/Start-Flapjacks.ps1" @PSBoundParameters
