@echo off
setlocal
where pwsh.exe >nul 2>nul
if errorlevel 1 (
    echo Flapjacks requires PowerShell 7.4 or newer ^(pwsh.exe^), not Windows PowerShell 5.1.
    echo Install PowerShell using Microsoft's Windows setup guide, then open a new terminal.
    echo See docs/setup/windows/README.md in the repository.
    exit /b 1
)
set "FLAPJACKS_LAUNCH_ROOT=%~dp0"
rem Inline diagnostics can run even when Windows blocks the downloaded .ps1 entry point.
rem This check does not unblock files, change execution policy, or sign in.
pwsh.exe -NoLogo -NoProfile -Command "$ErrorActionPreference='Stop'; if ($PSVersionTable.PSVersion -lt [version]'7.4') { Write-Host 'Flapjacks requires PowerShell 7.4 or newer. Use your approved PowerShell deployment and reopen the terminal.'; exit 1 }; $policy=Get-ExecutionPolicy; if ($policy -eq 'Restricted') { Write-Host 'Stopped: PowerShell script execution is Restricted. Contact your administrator for an approved distribution or managed workstation permitted by the existing policy.'; Write-Host 'See docs/setup/windows/README.md. No policy, files or trust settings were changed.'; exit 1 }; if ($policy -in 'RemoteSigned','AllSigned') { $files=@(Get-ChildItem -LiteralPath $env:FLAPJACKS_LAUNCH_ROOT -Recurse -File | Where-Object Extension -in '.ps1','.psm1','.psd1'); foreach ($file in $files) { $downloaded=(Get-Content -LiteralPath $file.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) -match '^ZoneId=[34]\s*$'; if ($policy -eq 'AllSigned' -or $downloaded) { $signature=Get-AuthenticodeSignature -LiteralPath $file.FullName; if ($signature.Status -ne 'Valid') { Write-Host 'Stopped: an invalid or missing signature prevents this distribution from meeting the existing policy. Download-origin markers are preserved.'; Write-Host 'Contact your administrator for an approved signed or managed distribution. See docs/setup/windows/README.md.'; exit 1 }; $publishers=@(Get-ChildItem -Path 'Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\TrustedPublisher' -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $signature.SignerCertificate.Thumbprint); if (-not $publishers.Count) { Write-Host 'Stopped: the signing publisher is not already trusted on this workstation. Contact your administrator to verify the approved distribution and provision trust through the managed process.'; Write-Host 'See docs/setup/windows/README.md. No policy, files or trust settings were changed.'; exit 1 } } } }"
if errorlevel 1 exit /b 1
pwsh.exe -NoLogo -NoProfile -File "%~dp0Start-Flapjacks.ps1" %*
exit /b %ERRORLEVEL%
