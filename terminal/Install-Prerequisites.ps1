#requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('Plan','Check','Install')][string]$Mode='Plan',[switch]$IncludeExchange)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'setup/Prerequisites.psm1') -Force
Write-Host 'M365 prerequisite setup: local software only. No tenant sign-in, browser, listener, consent or role changes.'
Write-Host 'Default Plan and Check do not download or install. Install uses CurrentUser only; repository/license prompts remain.'
$result=Invoke-PrerequisiteSetup @PSBoundParameters
$result.Modules | Format-Table Name,Installed,Range,Status -AutoSize
foreach($row in @($result.Modules | Where-Object Status -in @('Blocked','Unsupported'))){Write-Warning ($row.Name+': '+$row.Reason)}
foreach($gap in $result.Gaps){Write-Host ('LIMITATION: '+$gap)}
if($Mode -eq 'Plan'){Write-Host 'Review docs/PREREQUISITES.md. To install selected missing modules, rerun with -Mode Install; add -WhatIf for a non-mutating preview.'}
elseif($Mode -eq 'Install' -and -not $WhatIfPreference){Write-Host 'Open a fresh PowerShell session after installation. Authentication is a separate operator action.'}
if($Mode -eq 'Check' -and -not $result.Ready){exit 2}
if($Mode -eq 'Install' -and -not $WhatIfPreference -and -not $result.Ready){exit 2}
