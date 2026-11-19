# Flapjacks setup on Linux (Debian)

This setup path covers **Debian with PowerShell and Microsoft Graph**. Check Microsoft's current distribution/architecture support before installation. The project installer skips Exchange on Debian; Purview Security & Compliance PowerShell is unavailable on Linux. Those sources remain coverage gaps.

## 1. Install PowerShell

Install a supported stable/LTS **PowerShell 7.4+** release using [Microsoft's Debian guide](https://learn.microsoft.com/en-us/powershell/scripting/install/install-debian), currently covering Debian 12/13. Follow its official `.deb` installation or Microsoft package-repository instructions. Repository/key registration and OS package installation are separate administrator actions; Flapjacks does not perform them.

If the Microsoft package repository is already configured and approved, inspect the package source:

```sh
apt-cache policy powershell
```

With the expected `packages.microsoft.com` origin and authorization to install OS packages:

```sh
sudo apt-get update
sudo apt-get install powershell
```

Then start PowerShell as your **normal user**:

```sh
pwsh -NoLogo -NoProfile
```

## 2. Install the Graph module

Download/extract or clone [Flapjacks](https://github.com/PendingUpdates/Flapjacks). In PowerShell, change to the repository root containing `README.md` and `terminal`:

```powershell
$PSVersionTable.PSVersion
Set-Location '/path/to/Flapjacks'
./terminal/Install-Prerequisites.ps1 -Mode Check
./terminal/Install-Prerequisites.ps1 -Mode Install -WhatIf
./terminal/Install-Prerequisites.ps1 -Mode Install
```

Review the preview and Gallery/license prompts. This installs `Microsoft.Graph.Authentication` into `CurrentUser`; do not run it as root. Python, Node, a web server, and browser drivers are not app prerequisites. A missing/unsupported selected module causes the check to exit 2. See the [shared prerequisite contract](../../../terminal/docs/PREREQUISITES.md) for other platforms and version bounds.

## 3. Launch and save results

Open a fresh PowerShell window after installation, return to the repository root, and rerun `-Mode Check`. Launch:

```powershell
./Start-Flapjacks.ps1
```

From bash, use:

```sh
pwsh -NoLogo -NoProfile -File ./Start-Flapjacks.ps1
```

Type **LIVE** at the startup prompt, or add explicit `-Mode Live` to the launch command. Blank input, EOF, or any other response cancels before session access. The subsequent sign-in/reuse prompts also cancel on blank input or EOF; there is no default provider.

Choose startup **A** for the displayed approved Graph audit scopes, complete device-code sign-in, verify tenant/account, then type **AUDIT**. For extended checks, cancel that initial audit with Enter, choose **W**, and type **WORKBOOK**. **V** inspects results; **P** saves PDF, Excel, CSV, and evidence under a new directory in an existing private local folder; **S** saves JSON; **Q** exits.

For an existing approved Graph connection, run the `.ps1` inside **the same PowerShell process**, choose **R**, then **G**. Starting another `pwsh` process loses that process's connections. Linux has no Windows `RemoteSigned`/download-marker setup step; do not use Windows execution-policy changes to diagnose a Linux filesystem or executable-permission problem.

A Debian Graph-only run cannot assess the four Exchange-dependent checks in the standard five-check pilot. Extended checks also retain Exchange and native collaboration gaps. See [postures checked and why](../../posture/README.md); a collected source is not a complete workbook assessment.
