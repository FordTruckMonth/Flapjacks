#requires -Version 7.4
Set-StrictMode -Version Latest
function New-PrerequisiteRuntime {
    @{
        HostInfo={
            $family=if($IsWindows){'Windows'}elseif($IsMacOS){'macOS'}else{'Linux'}
            $distribution='';$release=''
            if($IsLinux -and (Test-Path -LiteralPath '/etc/os-release')){
                foreach($line in (Get-Content -LiteralPath '/etc/os-release')){
                    if($line -match '^ID=["'']?([a-zA-Z0-9._-]+)["'']?$'){$distribution=$Matches[1]}
                    if($line -match '^VERSION_ID=["'']?([0-9.]+)["'']?$'){$release=$Matches[1]}
                }
            }
            if($IsMacOS){$release=([string](& /usr/bin/sw_vers -productVersion)).Trim()}
            $elevated=if($IsWindows){
                $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
                ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            }else{[Environment]::UserName -eq 'root'}
            @{Version=$PSVersionTable.PSVersion;Family=$family;Distribution=$distribution;Release=$release;Elevated=$elevated}
        }
        Modules={param($name) @(Get-Module -ListAvailable -Name $name -ErrorAction Stop)}
        Repository={@(Microsoft.PowerShell.PSResourceGet\Get-PSResourceRepository -Name PSGallery -ErrorAction Stop)}
        Install={param($parameters) Microsoft.PowerShell.PSResourceGet\Install-PSResource @parameters -ErrorAction Stop}
    }
}
function Get-PrerequisiteCatalog {
    param([version]$Version,[switch]$IncludeExchange)
    # These are conservative installer package ranges, not publisher claims about earliest API support.
    $items=@(@{Name='Microsoft.Graph.Authentication';Minimum=[version]'2.0.0';Maximum=[version]'3.0.0';Range='[2.0.0,3.0.0)';Purpose='Graph sign-in and raw Graph reads; no full SDK/Beta module needed'})
    if($IncludeExchange){
        $items+=@{Name='PackageManagement';Minimum=[version]'1.4.8.1';Maximum=[version]'2.0.0';Range='[1.4.8.1,2.0.0)';Purpose='Exchange REST module dependency'}
        $items+=@{Name='PowerShellGet';Minimum=[version]'2.2.5';Maximum=[version]'3.0.0';Range='[2.2.5,3.0.0)';Purpose='Exchange REST module dependency'}
        $maximum=if($Version -lt [version]'7.6'){'3.10.0'}else{'4.0.0'}
        $items+=@{Name='ExchangeOnlineManagement';Minimum=[version]'3.7.0';Maximum=[version]$maximum;Range="[3.7.0,$maximum)";Purpose='Exchange read cmdlets and Trace V2; optional existing Purview session on supported Windows'}
    }
    return $items
}
function Get-PrerequisitePlan {
    param([hashtable]$Runtime,[switch]$IncludeExchange)
    $hostInfo=& $Runtime.HostInfo
    $version=[version]$hostInfo.Version
    if($version -lt [version]'7.4'){throw 'PowerShell 7.4+ is required. Follow docs/PREREQUISITES.md to install PowerShell first; Windows PowerShell 5.1 is not supported.'}
    if($hostInfo.Family -notin @('Windows','macOS','Linux')){throw 'Unsupported platform. No changes made.'}
    $gaps=[Collections.Generic.List[string]]::new()
    $exchangePlatform=$true
    if($hostInfo.Family -eq 'Linux'){
        $exchangePlatform=$hostInfo.Distribution -eq 'ubuntu' -and $hostInfo.Release -in @('22.04','24.04')
        if(-not $exchangePlatform){$gaps.Add('Exchange: this Linux distribution is not in the reviewed Microsoft support matrix (including Debian). Exchange modules are not installed by this script here; use a supported host for those sources.')}
        $gaps.Add('Purview: Microsoft currently documents Connect-IPPSSession as unavailable on PowerShell 7 Linux. Installing another module does not enable it.')
    }elseif($hostInfo.Family -eq 'macOS'){
        $macVersion=[version]'0.0'
        $exchangePlatform=[version]::TryParse([string]$hostInfo.Release,[ref]$macVersion) -and $macVersion.Major -ge 14
        if(-not $exchangePlatform){$gaps.Add('Exchange: this installer targets macOS 14+; older versions need separate review of Microsoft runtime/module support. No Exchange installation here.')}
        $gaps.Add('Purview: Microsoft currently documents Connect-IPPSSession as unavailable on PowerShell 7 macOS. Installing another module does not enable it.')
    }
    $rows=[Collections.Generic.List[object]]::new()
    foreach($item in (Get-PrerequisiteCatalog -Version $version -IncludeExchange:$IncludeExchange)){
        $installed=@(& $Runtime.Modules $item.Name | Sort-Object Version -Descending)
        $status='Missing';$found='';$reason=$item.Purpose
        if($installed.Count){
            $top=$installed[0];$found=[string]$top.Version
            $pre=$false
            if($top.PrivateData -is [Collections.IDictionary] -and $top.PrivateData.Contains('PSData')){
                $data=$top.PrivateData['PSData']
                if($data -is [Collections.IDictionary] -and $data.Contains('Prerelease')){$pre=[bool]$data['Prerelease']}
            }
            if($pre -or [version]$top.Version -ge $item.Maximum){$status='Blocked';$reason='Highest visible version is prerelease/outside the reviewed compatible range. No downgrade/removal/import is attempted; use a compatible clean environment.'}
            elseif([version]$top.Version -ge $item.Minimum){$status='Present'}
        }
        if($item.Name -ne 'Microsoft.Graph.Authentication' -and -not $exchangePlatform){$status='Unsupported';$reason='Exchange component unavailable in this installer on this platform. Graph setup can still proceed.'}
        $rows.Add([pscustomobject]@{Name=$item.Name;Installed=$found;Range=$item.Range;Status=$status;Reason=$reason})
    }
    if(-not $IncludeExchange){$gaps.Add('Exchange/Purview software not selected. Use -IncludeExchange on a supported host to include messaging components; no tenant rights or sessions are granted.')}
    $gaps.Add('Software presence does not verify cmdlet availability, tenant roles/consent, licensing, service data or live connectivity. Windows edition/lifecycle support must be checked separately.')
    return [pscustomobject]@{Host=$hostInfo;Modules=$rows.ToArray();Gaps=$gaps.ToArray();Ready=(@($rows | Where-Object Status -ne 'Present').Count -eq 0)}
}
function Assert-PrerequisiteGallery {
    param([hashtable]$Runtime)
    $repos=@(& $Runtime.Repository)
    if($repos.Count -ne 1){throw 'Exactly one existing PSGallery registration is required. No repository is registered or repaired automatically.'}
    $uri=[uri]$repos[0].Uri
    if(-not $uri.IsAbsoluteUri -or $uri.AbsoluteUri.TrimEnd('/') -cne 'https://www.powershellgallery.com/api/v2'){
        throw 'PSGallery does not point to the official HTTPS Gallery endpoint. Refusing installation; no trust or repository setting changed.'
    }
}
function Invoke-PrerequisiteSetup {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='Medium')]
    param([ValidateSet('Plan','Check','Install')][string]$Mode='Plan',[switch]$IncludeExchange,[hashtable]$Runtime)
    if(-not $Runtime){$Runtime=New-PrerequisiteRuntime}
    $plan=Get-PrerequisitePlan $Runtime -IncludeExchange:$IncludeExchange
    if($Mode -ne 'Install'){return $plan}
    if($plan.Host.Elevated -and -not $WhatIfPreference){throw 'Run module setup as your ordinary non-elevated account. CurrentUser installs must not target an administrator/root profile.'}
    $pending=@($plan.Modules | Where-Object Status -eq 'Missing')
    if(-not $pending.Count){return $plan}
    if($WhatIfPreference){
        # Even repository inspection can initialize PSResourceGet's user-local metadata.
        # A preview must not load that package manager or call any of its commands.
        foreach($item in $pending){$null=$PSCmdlet.ShouldProcess(($item.Name+' '+$item.Range+' from official PSGallery into CurrentUser'),'Install module and dependencies')}
        return $plan
    }
    $manager=@(& $Runtime.Modules 'Microsoft.PowerShell.PSResourceGet')
    if(-not $manager.Count){throw 'PSResourceGet is missing. Use an official PowerShell 7.4+ installation or your approved software process; no bootstrap download is performed.'}
    Assert-PrerequisiteGallery $Runtime
    foreach($item in $pending){
        if($PSCmdlet.ShouldProcess(($item.Name+' '+$item.Range+' from official PSGallery into CurrentUser'),'Install module and dependencies')){
            # Recheck source immediately before every package action; never auto-trust or accept licenses.
            Assert-PrerequisiteGallery $Runtime
            $parameters=@{Name=$item.Name;Version=$item.Range;Repository='PSGallery';Scope='CurrentUser';NoClobber=$true}
            & $Runtime.Install $parameters | Out-Null
        }
    }
    return Get-PrerequisitePlan $Runtime -IncludeExchange:$IncludeExchange
}
Export-ModuleMember -Function New-PrerequisiteRuntime,Get-PrerequisiteCatalog,Get-PrerequisitePlan,Assert-PrerequisiteGallery,Invoke-PrerequisiteSetup
