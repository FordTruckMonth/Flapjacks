# Flapjacks setup on Windows

Use an administrator-approved distribution and run as your normal Windows user. Start in the **repository root**, the folder containing `README.md` and `terminal`. For a separately managed terminal toolkit, omit `terminal\` from installer paths below.

## 1. Install and open PowerShell 7

Flapjacks requires **PowerShell 7.4 or newer** (`pwsh.exe`). Windows PowerShell 5.1 (`powershell.exe`) and Windows Terminal are not substitutes: Terminal can host either shell.

Install a supported stable/LTS release using [Microsoft's Windows instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows). With WinGet available, one option is:

```powershell
winget install --id Microsoft.PowerShell --exact --source winget --scope user
```

If user-scope installation is unavailable, use your organization's software deployment process. Open a **new** terminal, start `pwsh`, and check:

```powershell
$PSVersionTable.PSVersion
Get-ExecutionPolicy -List
Get-ExecutionPolicy
```

Use the same PowerShell 7 window for the remaining steps. A policy set in Windows PowerShell is not sufficient evidence of the effective policy in `pwsh`.

## 2. Obtain an approved signed or managed distribution

**`UnauthorizedAccess` / `PSSecurityException` at line 1 can mean PowerShell blocked the file before any Flapjacks code ran.** `RemoteSigned` still requires a trusted signature on scripts marked as downloaded from the internet. A GitHub ZIP can pass that marker to extracted `.ps1`, `.psm1`, and `.psd1` files. This repository supplies unsigned source, not an organization-approved signed Windows package.

Ask your administrator to review the exact version and supply one of these routes under the workstation's **existing** controls:

- **Approved signed package:** the organization's release/signing process signs every PowerShell script, module and manifest with an approved code-signing certificate. IT provisions the certificate chain and publisher trust through its managed process. Verify the package version, hashes and approved publisher against information supplied by IT; a valid signature alone is not approval to run it. This route supports `RemoteSigned` and `AllSigned` when the required trust is already present and application control permits the code.
- **Approved managed deployment:** obtain the reviewed build through the organization's software portal or deployment system. IT must confirm that the deployed files are permitted by the existing execution policy and application-control rules. A managed copy does not exempt code from `AllSigned`, or a downloaded unsigned script from `RemoteSigned`.

The following checks are read-only. From the approved distribution root in PowerShell 7, inspect signatures:

```powershell
Get-ChildItem -LiteralPath . -Recurse -File |
    Where-Object Extension -in '.ps1', '.psm1', '.psd1' |
    ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName } |
    Select-Object Path, Status, StatusMessage, SignerCertificate
```

If a required signature is missing/invalid, the publisher is not already trusted, or the effective policy is **Restricted**, **stop and contact your administrator**. `MachinePolicy` and `UserPolicy` take precedence over user settings. Signing alone does not allow scripts under `Restricted`, and PowerShell policy does not override AppLocker, WDAC or other application controls. There may be no permitted route on this workstation until IT supplies a compliant distribution or an approved managed workstation.

Keep the existing policy and download-origin markers intact. Do not use a policy override, remove origin markers, or accept an unfamiliar publisher to make unsigned source run. The launchers do not change policy, files, certificate stores or publisher trust. See Microsoft's [execution-policy documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) and [script signing guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing).

## 3. Install the Microsoft modules

After IT confirms the distribution and Microsoft modules are permitted, use the repository root in PowerShell 7:

```powershell
.\terminal\Install-Prerequisites.ps1 -Mode Check -IncludeExchange
.\terminal\Install-Prerequisites.ps1 -Mode Install -IncludeExchange -WhatIf
.\terminal\Install-Prerequisites.ps1 -Mode Install -IncludeExchange
```

The first command only checks local software; exit code 2 means a selected component is missing, blocked, or unsupported. Use IT-deployed modules where required. If user-scope installation is approved, review the preview and normal Gallery/license prompts before installation. Installation uses `CurrentUser`; do not run it elevated. For Graph-only collection omit `-IncludeExchange`, and expect Exchange coverage gaps.

Open a fresh PowerShell 7 window after installation and rerun the check. Graph needs `Microsoft.Graph.Authentication`. Exchange needs `ExchangeOnlineManagement` 3.7+; versions 3.10+ need PowerShell 7.6+. The installer selects a compatible bounded version. Module installation does not grant tenant permissions. See the [shared prerequisites](../../../terminal/docs/PREREQUISITES.md) for exact compatibility and access requirements.

## 4. Start and run an audit

From the repository root, the Windows launcher selects PowerShell 7 and stops on detected policy or required signature/trust failures before starting:

```powershell
.\Start-Flapjacks.cmd
```

Or, from **inside PowerShell 7**:

```powershell
.\Start-Flapjacks.ps1
```

Both the root and `terminal\Start-Flapjacks.ps1` entry points are supported. Type **LIVE** at the startup prompt, or supply explicit `-Mode Live` to either launch command. Blank input, EOF, or any other response cancels before inspecting or opening a Microsoft session. The subsequent sign-in/reuse prompts also cancel on blank input or EOF; they never choose Graph by default. If you already have approved Graph/Exchange/Purview sessions, run the `.ps1` directly in **that same PowerShell process** and choose **R**, then **G** or **E**. The `.cmd` launcher and `pwsh -File` start a new process and cannot reuse another process's connections.

1. Choose startup **A** for the displayed, already-approved Graph audit read scopes. Complete the Microsoft device-code sign-in and verify the displayed tenant and account. **G** is identity-only and can leave configuration reads without permissions.
2. Type **AUDIT** to run the standard configuration audit. To choose the extended workbook profile instead, press Enter to cancel this initial audit, then choose **W** and type **WORKBOOK**.
3. Use **V** to inspect the result and coverage. Use **P** to save PDF, Excel, CSV, and supporting evidence to a **new** directory beneath an existing private local folder. **S** saves a single JSON file. **Q** exits.

Graph sign-in does not create Exchange or Purview sessions. Those sources require existing matching sessions and source-specific read access; unavailable sources remain visible gaps. See [authentication](../../../terminal/docs/AUTHENTICATION.md) and [what is checked and why](../../posture/README.md).

## If startup still fails

- **Not digitally signed / running scripts is disabled / publisher not trusted:** stop and send the policy/signature diagnostics to your administrator for an approved signed or managed distribution. A `.ps1` cannot fix its own execution-policy rejection because it has not started yet.
- **PowerShell 7.4 required / `pwsh` not found:** install PowerShell 7, reopen the terminal, and use the `.cmd` launcher or a PowerShell 7 tab.
- **Access to a path is denied:** identify the path named in the error. Extract the repository into a local user-writable folder and choose a writable private report destination. Execution policy does not fix filesystem permissions.
- **Application control, antivirus, or organization policy blocks execution:** use the administrator's approved deployment process; the distribution must satisfy those existing controls.

For a pilot report, include the command, full error text, PowerShell version, effective `Get-ExecutionPolicy -List` output, and build/ZIP version. Remove tenant identifiers, account names, device codes, and tokens before sharing.
