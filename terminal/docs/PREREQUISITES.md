# Prerequisites and setup (Windows, macOS, Debian)

Start with the standalone OS README: [Windows](../../docs/setup/windows/README.md), [macOS](../../docs/setup/macos/README.md), or [Linux/Debian](../../docs/setup/linux/README.md). The Windows guide covers trusted-download unblocking and line-one `UnauthorizedAccess` even with `RemoteSigned`.

This is a **two-step setup**, not an all-in-one operating-system bootstrap:

1. Install an official, supported **PowerShell 7** runtime for your OS.
2. Run the same `Install-Prerequisites.ps1` on Windows, macOS or Debian to check/install the selected Microsoft modules **for your user only**.

The application and setup scripts use only PowerShell. **Python, Node, a web server and a browser driver are not required.** A separate file-transfer helper may use Python; that is not a toolkit dependency and this installer never installs it.

## Requirements and boundaries

| Component | Requirement / selection |
|---|---|
| PowerShell | Toolkit/setup syntax floor **7.4**, not Windows PowerShell 5.1. Prefer a currently supported stable/LTS release and OS. |
| Graph | `Microsoft.Graph.Authentication`, exposing `Connect-MgGraph -UseDeviceCode`, `Get-MgContext`, `Invoke-MgGraphRequest`. Only this submodule is needed. Setup conservatively selects stable **2.x**; this is an installer compatibility range, not a claim that Microsoft documents 2.0 as the earliest API version. |
| Exchange, opt-in | `ExchangeOnlineManagement` **3.7.0+** for Trace V2, with REST metadata. On PowerShell 7.4/7.5 setup selects **>=3.7,<3.10**; on 7.6+ **>=3.7,<4**. EXO **3.10+ needs PowerShell 7.6+**. |
| Exchange dependencies | `PowerShellGet` and `PackageManagement`. Usually included in PowerShell; if absent/older, setup selects stable 2.2.5+ (below 3) and 1.4.8.1+ (below 2), respectively. These are conservative setup baselines. |
| Installer | `Microsoft.PowerShell.PSResourceGet`, included with PowerShell 7.4+. The `PSGallery` registration must point to `https://www.powershellgallery.com/api/v2`. No custom repository is added/repaired and trust is never changed by setup. |
| Optional audit sources | Intune, Defender, authentication/consent/role metadata and Graph beta user sign-ins use the same Graph authentication module. **No additional Graph SDK/Beta, AzureAD, MSOnline, Teams or Intune module is needed.** Licensing, approved scopes and workload roles remain separate prerequisites. |
| Purview | Uses the same Exchange module, not a separate install. Requires an already approved matching session on a supported host; this app never authenticates it. Microsoft currently documents `Connect-IPPSSession` as unavailable on macOS/Linux PowerShell 7. |

Installing software grants no tenant role, consent, license or collection authorization. A module-present result is not live validation. See [permission contracts](../Audit/docs/PERMISSIONS.md) and [authentication](AUTHENTICATION.md). The runtime checks required commands/parameters again before use. Installer ranges exclude prereleases and unknown future major versions; compatible installed versions are left alone, not upgraded unnecessarily.

Sources: [Graph installation and submodules](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation), [Exchange platform/runtime prerequisites](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2), [Trace V2 prerequisites](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac), [PSResourceGet](https://learn.microsoft.com/en-us/powershell/gallery/overview).

## Step 1: PowerShell on a clean machine

These are **operator-run** bootstrap instructions. OS installation can replace an existing runtime and may require an administrator; review the package/OS prompts. Nothing below is invoked by the module installer. Do not weaken execution policy, Gatekeeper, repository trust, TLS, identity controls or permissions to make setup work.

### Windows

With an existing WinGet, run from a normal terminal (Windows PowerShell 5.1 is sufficient for this bootstrap command):

```powershell
winget install --id Microsoft.PowerShell --exact --source winget --scope user
```

Keep agreement prompts. If this package/host cannot install in user scope, **stop** rather than falling back to elevation. Without WinGet, or for a managed/server deployment, use the official package choices in [Microsoft's Windows installation guide](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows). Open a new terminal and run `pwsh`. Check the Windows edition/lifecycle support matrix before using Exchange; setup does not certify OS support. If scripts are blocked, stop and contact your administrator for an [approved signed or managed Windows distribution](../../docs/setup/windows/README.md#2-obtain-an-approved-signed-or-managed-distribution). Keep the existing execution policy, download-origin markers and trust controls intact.

### macOS

For a clean Mac, use Microsoft's preferred **signed/notarized PKG**, choosing the stable/LTS Apple Silicon (arm64) or Intel (x64) package for your machine from [Microsoft's macOS installation guide](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-macos). Open that downloaded package and review the installer prompts, then run `pwsh` in a new terminal. No Python or Homebrew installation is necessary.

If you already use Homebrew and specifically choose its **community-maintained, source-built** alternative, Microsoft's [alternate installation guide](https://learn.microsoft.com/en-us/powershell/scripting/install/alternate-install-methods) documents:

```sh
brew install powershell
```

This is not Microsoft's signed binary package. Existing PowerShell cask installs can conflict; stop and review migration rather than automatically uninstalling anything. The toolkit does not install Homebrew, remove casks, disable Gatekeeper or change quarantine flags. This installer permits Exchange installation on macOS **14+**, subject to current OS/module lifecycle support; older versions require separate compatibility review. Purview remains unavailable on macOS, even with the module installed.

### Debian Linux

Use a supported Debian release and architecture listed in [Microsoft's Debian guide](https://learn.microsoft.com/en-us/powershell/scripting/install/install-debian) (currently Debian 12/13). On a clean machine, follow that guide's official Microsoft package/repository setup, or its direct official `.deb` package alternative. Registering a repository/key is a separate privileged trust decision for the operator/admin; this toolkit never performs it.

If the appropriate Microsoft repository is **already configured and approved**, inspect the package origin first:

```sh
apt-cache policy powershell
```

Require the expected `packages.microsoft.com` origin. Then, with explicit administrator approval for these OS package operations:

```sh
sudo apt-get update
sudo apt-get install powershell
```

No `-y`, repository/key additions or privilege escalation are hidden in the shared script. Open `pwsh` afterward.

**Debian limitation:** PowerShell/Graph setup is supported by this setup path. Debian is not listed in Microsoft's reviewed Exchange module Linux support matrix, so `-IncludeExchange` reports those modules as **Unsupported** and skips them on Debian. Purview is unavailable on Linux. Use an approved supported host for those sources; do not describe a Debian Graph-only run as a complete full-organization audit.

## Step 2: one shared module installer

From the repository root, in PowerShell 7.4+ as your normal user:

```powershell
# Default: local plan only, no downloads, authentication or filesystem changes.
./terminal/Install-Prerequisites.ps1

# Local check; exit 2 means selected modules are missing/blocked/unsupported.
./terminal/Install-Prerequisites.ps1 -Mode Check

# Preview all supported components, including optional Exchange dependencies.
./terminal/Install-Prerequisites.ps1 -Mode Install -IncludeExchange -WhatIf

# Install Graph only into CurrentUser.
./terminal/Install-Prerequisites.ps1 -Mode Install

# Explicitly opt in to Exchange too, on a supported host.
./terminal/Install-Prerequisites.ps1 -Mode Install -IncludeExchange
```

For a standalone extracted toolkit, omit `terminal/` from these paths. `Plan` and `Check` inspect local module metadata only. `Install -WhatIf` prints the local plan without loading PSResourceGet or inspecting its repository store, so it cannot initialize package-manager state. Repository validation happens only on an actual install. `-Confirm` is supported. Elevated/root installation is refused; reopen under your regular account. No output files or transcript are created.

An actual install uses PSResourceGet and may initialize that manager's user-local default repository metadata if this is its first use. Before every install, setup requires the resulting PSGallery URI to match the official HTTPS endpoint exactly; a mismatched/custom endpoint is refused, not repaired. Package downloads use that explicit official Gallery selection for the named packages/dependencies. It uses `CurrentUser`, stable bounded versions and `NoClobber`; it does not suppress repository trust/license prompts or persist trust. Review/decline those prompts normally. No app registration, sign-in, browser, consent grant, role activation, proxy/repository repair, uninstall or fallback package source is attempted. If organizational policy blocks Gallery, use your approved software deployment process rather than overriding the check. [Install-PSResource behavior](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.psresourceget/install-psresource)

An incompatible highest visible version is reported **Blocked**, not automatically removed or downgraded. An install failure stops the remaining installation sequence; already completed package installs are not rolled back. Rerunning checks the current state and skips compatible packages. Dependencies can also be installed by the package manager. Review the final table and gaps; an optional component that is unsupported remains a gap, not success.

After installation, open a fresh PowerShell session, rerun `-Mode Check` with the same component selection, then:

```powershell
./terminal/Start-Flapjacks.ps1
```

Authentication remains a separate choice. Microsoft device-code approval requires its web page on an approved browser/device. Full audit requires organization-scope confirmation and matching component identities; installing modules does not waive those gates.

## Validation limits

Native PowerShell syntax and mocked Windows/macOS/Debian plans, version selection, per-user install arguments, WhatIf, idempotency, repository rejection/change, unsupported components and failures are tested. Local Debian plan/check is exercised without installs. **No Windows/macOS/Debian package installation, Microsoft module download/import, tenant authentication or live collection was performed for this setup change.** These are historical private QA results. The public tree contains only static checks: run `./tools/Test-ReleaseBoundary.ps1` from the repository root; no QA scenarios are shipped or executed by public CI.
