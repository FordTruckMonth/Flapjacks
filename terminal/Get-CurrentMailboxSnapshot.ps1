#requires -Version 7.4
# No login, installation, Graph, history, write to tenant, or automatic evidence save.
[CmdletBinding()]
param([ValidateSet('Live')][string]$Mode,[Parameter(Mandatory)][string]$MailboxUpn,[string]$OutputPath)
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('Mode')){throw 'Live snapshot requires an explicit -Mode Live. No session was inspected and nothing was collected or written.'}
Import-Module "$PSScriptRoot/M365Toolkit.psm1" -DisableNameChecking
if(-not (Test-ToolkitAddress $MailboxUpn)){throw 'One exact mailbox UPN required.'}
$runtime=New-ToolkitRuntime
$session=Resolve-ToolkitExchangeContext $runtime
Write-ToolkitText $runtime ('Current-only Exchange snapshot. Tenant: '+$session.TenantId+'; operator: '+$session.Account+'; mailbox: '+$MailboxUpn)
Write-ToolkitText $runtime 'Reads: Get-Mailbox, Get-InboxRule (including hidden, cap 1000), Get-MailboxPermission, Get-RecipientPermission. No history, Graph, mail bodies, attachments or tenant-wide reads.'
if($OutputPath){Write-ToolkitText $runtime ('Sensitive local JSON will be written to: '+[IO.Path]::GetFullPath($OutputPath)+'; no encryption or permission hardening is provided.')}
$expected='SNAPSHOT '+$session.TenantId+' '+$MailboxUpn
if((Read-ToolkitInput $runtime ('Type exactly '+$expected+' to authorize this read')) -cne $expected){throw 'Confirmation did not match; no collection performed.'}
$result=Invoke-ToolkitCurrentMailboxSnapshot -Mode $Mode -Runtime $runtime -TenantId $session.TenantId -Account $session.Account -Target $MailboxUpn
if($OutputPath){Export-ToolkitMailboxSnapshot $result $session.TenantId $OutputPath}else{ConvertTo-ToolkitMailboxSnapshot $result $session.TenantId}
