#requires -Version 7.4
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Import-Module "$root/M365Toolkit.psm1" -Force -DisableNameChecking
$module=Get-Module M365Toolkit
# Test-only synthetic messages: no URLs, codes, credentials, provider, or auth calls.
$state=@{Displayed=[Collections.Generic.List[string]]::new();BeforeCompletion=$false;Completed=$false;ErrorCaught=$false;Scopes=@()}
& $module {
 param($state)
 # A module-local host sink models Out-Host's process-stage behavior. It must
 # receive each prompt while the producer is still waiting, not after completion.
 function Out-Host {
  [CmdletBinding()]
  param([Parameter(ValueFromPipeline)]$InputObject)
  process {$state.Displayed.Add([string]$InputObject)}
 }
 $fake={
  [CmdletBinding()]param([string[]]$Scopes,[switch]$UseDeviceCode,[string]$ContextScope)
  $state.Scopes=$Scopes
  Start-Sleep -Milliseconds 30
  Write-Output 'SYNTHETIC device instructions, not a usable code'
  Start-Sleep -Milliseconds 50
  $state.BeforeCompletion=($state.Displayed.Count -eq 1 -and -not $state.Completed)
  $state.Completed=$true
 }.GetNewClosure()
 # Reproduce both assignment and outer Out-Null in the real launcher.
 $captured=@(Invoke-ToolkitAuthenticationCommand $fake @{Scopes=@('User.Read');UseDeviceCode=$true;ContextScope='Process'})
 if($captured.Count -ne 0){throw 'Authentication display leaked into returned session data'}
 Invoke-ToolkitAuthenticationCommand { [CmdletBinding()]param() 'SYNTHETIC second prompt' } @{} | Out-Null
 try{Invoke-ToolkitAuthenticationCommand { [CmdletBinding()]param() throw 'Synthetic provider denial' } @{}}catch{$state.ErrorCaught=$true}
} $state
$checks=@(
 @{Name='delayed prompt displayed before completion';Passed=$state.BeforeCompletion},
 @{Name='producer completed';Passed=$state.Completed},
 @{Name='outer Out-Null cannot swallow host boundary';Passed=($state.Displayed.Count -eq 2)},
 @{Name='provider errors still terminate';Passed=$state.ErrorCaught},
 @{Name='scope remains User.Read';Passed=(($state.Scopes -join ',') -ceq 'User.Read')},
 @{Name='runtime uses streaming helper';Passed=((Get-Content "$root/src/Sessions.ps1" -Raw).Contains('Invoke-ToolkitAuthenticationCommand -Command $command -Parameters $connectParameters'))}
)
foreach($check in $checks){if(-not $check.Passed){throw ('FAIL '+$check.Name)}}
# Real console sink smoke, without mocks or Microsoft modules.
$captured=@(Invoke-ToolkitAuthenticationCommand { [CmdletBinding()]param() 'SYNTHETIC host-display smoke (no authentication)';Start-Sleep -Milliseconds 30 } @{})
if($captured.Count){throw 'Real Out-Host emitted result objects'}
$summary=[pscustomobject]@{Passed=$true;Checks=($checks.Count+1);RealAuthentication=$false;ProviderCalls=0;ChecksDetail=$checks}
if($ResultsPath){$summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ResultsPath}
$summary
