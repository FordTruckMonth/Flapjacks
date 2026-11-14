#requires -Version 7.4
param([Parameter(Mandatory)][string]$CasePath)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot/M365Bec.psm1" -Force -DisableNameChecking
$r=Test-BecManifest $CasePath;$r
if(-not $r.Passed){exit 1}
