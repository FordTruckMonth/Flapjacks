# Flapjacks setup on macOS

## 1. Install PowerShell

Use a supported stable/LTS **PowerShell 7.4+** release from [Microsoft's macOS installation guide](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-macos). Choose the signed/notarized **arm64** PKG for Apple Silicon or **x64** PKG for Intel. Review the package installer prompts. Python and Homebrew are not required.

Open Terminal and run:

```sh
pwsh -NoLogo -NoProfile
```

The remaining commands run **inside PowerShell**, not zsh. Verify the version:

```powershell
$PSVersionTable.PSVersion
```

Windows execution-policy diagnostics do not apply on macOS. Keep Gatekeeper protections enabled; follow the official package guidance if macOS blocks the runtime.

## 2. Install modules

Download and extract [Flapjacks](https://github.com/PendingUpdates/Flapjacks), or clone it. Change to the repository root containing `README.md` and `terminal`, as your normal user:

```powershell
Set-Location '/path/to/Flapjacks'
./terminal/Install-Prerequisites.ps1 -Mode Check -IncludeExchange
./terminal/Install-Prerequisites.ps1 -Mode Install -IncludeExchange -WhatIf
./terminal/Install-Prerequisites.ps1 -Mode Install -IncludeExchange
```

Review the preview and Gallery/license prompts. Use per-user installation without `sudo`. The installer permits Exchange on macOS 14+ subject to Microsoft's current support matrix; unsupported components remain explicit gaps. For Graph-only use, omit `-IncludeExchange`.

Graph needs `Microsoft.Graph.Authentication`; Exchange needs `ExchangeOnlineManagement` 3.7+. Exchange module 3.10+ requires PowerShell 7.6+. The installer selects compatible versions. **Purview Security & Compliance PowerShell is unavailable on macOS** in the documented support matrix. Installing the Exchange module does not remove this limit. See [shared prerequisites](../../../terminal/docs/PREREQUISITES.md).

## 3. Launch and save results

Open a fresh `pwsh` after installation, return to the repository root, and rerun the prerequisite check. Launch:

```powershell
./Start-Flapjacks.ps1
```

From zsh, a fresh-process launch is also supported:

```sh
pwsh -NoLogo -NoProfile -File ./Start-Flapjacks.ps1
```

Type **LIVE** at the startup prompt, or add explicit `-Mode Live` to the launch command. Blank input, EOF, or any other response cancels before session access. The subsequent sign-in/reuse prompts also cancel on blank input or EOF; there is no default provider. To reuse approved sessions, invoke the `.ps1` directly in the **same PowerShell process** that owns them, then choose **R** and **G** or **E**. A new `pwsh -File` process cannot reuse those connections.

Choose startup **A** for the displayed approved Graph audit scopes, complete device-code sign-in, verify the tenant/account, and type **AUDIT**. For extended checks, cancel that initial audit with Enter, choose **W**, then type **WORKBOOK**. **V** inspects results; **P** saves PDF, Excel, CSV, and evidence under a new directory in an existing private local folder; **S** saves JSON; **Q** exits. The app saves nothing automatically.

Graph login does not establish Exchange/Purview access. Missing scopes, sessions, roles, licenses, or unsupported sources remain gaps. See [authentication](../../../terminal/docs/AUTHENTICATION.md) and [postures checked and why](../../posture/README.md). The 134-item workbook remains in progress.
