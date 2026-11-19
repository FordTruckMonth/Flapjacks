#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:ToolkitRoot=$PSScriptRoot
foreach($part in @('Terminal','Sessions','Workflow','MailboxSnapshot')){. (Join-Path $PSScriptRoot "src/$part.ps1")}
# Supported workflows and non-collecting launcher/evidence utilities only.
Export-ModuleMember -Function Invoke-M365Terminal,Invoke-ToolkitAuditWorkflow,Invoke-ToolkitLogsWorkflow,Invoke-ToolkitCurrentMailboxSnapshot,ConvertTo-ToolkitMailboxSnapshot,Export-ToolkitMailboxSnapshot,New-ToolkitRuntime,Resolve-ToolkitGraphContext,Resolve-ToolkitExchangeContext,ConvertTo-ToolkitText,Read-ToolkitInput,Write-ToolkitText,Test-ToolkitAddress
