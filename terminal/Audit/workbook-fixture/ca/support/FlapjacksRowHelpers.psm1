#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Parent=Import-Module (Join-Path $PSScriptRoot 'FlapjacksPassiveHelpers.psm1') -PassThru -DisableNameChecking
$script:Audit=Import-Module (Join-Path $PSScriptRoot 'FlapjacksOfflineReport.psm1') -PassThru -DisableNameChecking
function Parse-R([string]$s,[long]$max){& $script:Parent {param($x,$n)Parse-Local $x $n} $s $max}
function Utc-R($v){& $script:Parent {param($x)Utc $x} $v}
