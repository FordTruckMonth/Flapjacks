#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:ToolkitRoot=$PSScriptRoot
foreach($part in @('Terminal','Sessions','Workflow')){. (Join-Path $PSScriptRoot "src/$part.ps1")}
Export-ModuleMember -Function *-Toolkit*,Invoke-M365Terminal
