#requires -Version 7.4
# Static release checks only: parse source, inspect ASTs and Git attributes.
# Never import application modules, invoke a launcher/adapter, or run a scenario.
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference='Stop'
$repository=Split-Path $PSScriptRoot -Parent
$checks=[Collections.Generic.List[string]]::new()
$parsed=@{}
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw "FAIL: $Name"};$checks.Add($Name)}
function Read-Source([string]$Path){Get-Content -LiteralPath (Join-Path $repository $Path) -Raw}
function Find-Function($Ast,[string]$Name){
    $found=@($Ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true))
    Check ($found.Count -eq 1) "one definition of $Name"
    $found[0].Body
}
function Check-Mode($Body,[string]$Label){
    $mode=@($Body.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq 'Mode'})
    Check ($mode.Count -eq 1) "$Label has one Mode parameter"
    $sets=@($mode[0].Attributes | Where-Object {$_.TypeName.Name -eq 'ValidateSet'})
    Check ($sets.Count -eq 1 -and ($sets[0].PositionalArguments.Value -join ',') -ceq 'Live') "$Label accepts only Live"
    Check ($null -eq $mode[0].DefaultValue) "$Label has no live default"
}
$paths=@(& git -C $repository ls-files --cached --others --exclude-standard -- '*.ps1' '*.psm1' '*.psd1')
if($LASTEXITCODE -ne 0){throw 'Cannot enumerate source files'}
foreach($path in $paths){
    $tokens=$null;$errors=$null
    $parsed[$path]=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repository $path),[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0) "PowerShell parses: $path"
}
$entries=@(
    @{Path='Start-BecInvestigation.ps1';Name=''},
    @{Path='src/Investigation.ps1';Name='Invoke-BecInvestigation'},
    @{Path='terminal/Logs/src/Investigation.ps1';Name='Invoke-BecInvestigation'},
    @{Path='terminal/Audit/src/Run.ps1';Name='Invoke-M365SecurityAudit'},
    @{Path='terminal/Audit/src/Terminal.ps1';Name='Invoke-M365OrganizationAudit'},
    @{Path='src/Investigation.ps1';Name='Invoke-InvestigationCore'},
    @{Path='terminal/Logs/src/Investigation.ps1';Name='Invoke-InvestigationCore'},
    @{Path='terminal/Audit/src/Run.ps1';Name='Invoke-FlapjacksAuditCore'},
    @{Path='terminal/Audit/src/Terminal.ps1';Name='Invoke-FlapjacksOrganizationAuditCore'},
    @{Path='terminal/src/Workflow.ps1';Name='Invoke-ToolkitAuditWorkflow'},
    @{Path='terminal/src/Workflow.ps1';Name='Invoke-ToolkitLogsWorkflow'},
    @{Path='terminal/src/Workflow.ps1';Name='Invoke-M365Terminal'},
    @{Path='terminal/src/MailboxSnapshot.ps1';Name='Invoke-ToolkitCurrentMailboxSnapshot'},
    @{Path='terminal/Get-CurrentMailboxSnapshot.ps1';Name=''}
)
foreach($entry in $entries){
    $body=if($entry.Name){Find-Function $parsed[$entry.Path] $entry.Name}else{$parsed[$entry.Path]}
    $label=$entry.Path+' '+$entry.Name
    Check-Mode $body $label
    $guards=@($body.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -ceq "-not `$PSBoundParameters.ContainsKey('Mode')"})
    Check ($guards.Count -eq 1) "$label rejects omitted Mode"
    $guard=$guards[0]
    Check ($guard.Clauses.Count -eq 1 -and $null -eq $guard.ElseClause -and $guard.Clauses[0].Item2.Statements.Count -eq 1 -and $guard.Clauses[0].Item2.Statements[0] -is [Management.Automation.Language.ThrowStatementAst]) "$label guard only throws"
    $earlyCommands=@($body.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.Extent.StartOffset -lt $guard.Extent.EndOffset},$true))
    Check ($earlyCommands.Count -eq 0) "$label rejects omission before any command, context, session or output"
}
$wrappers=@{
    'Start-Flapjacks.ps1'='& "$PSScriptRoot/terminal/Start-Flapjacks.ps1" @PSBoundParameters'
    'terminal/Start-Flapjacks.ps1'='& "$PSScriptRoot/Start-M365Toolkit.ps1" @PSBoundParameters'
}
foreach($path in $wrappers.Keys){
    $body=$parsed[$path]
    Check-Mode $body $path
    Check ($body.EndBlock.Statements.Count -eq 1 -and $body.EndBlock.Statements[0].Extent.Text -ceq $wrappers[$path]) "$path forwards only actually bound arguments without manufacturing Live"
}
$launcher=$parsed['terminal/Start-M365Toolkit.ps1']
Check-Mode $launcher 'terminal/Start-M365Toolkit.ps1'
$launchStatements=@($launcher.EndBlock.Statements)
Check ($launchStatements.Count -eq 4 -and $launchStatements[0].Extent.Text -ceq "`$ErrorActionPreference='Stop'") 'interactive launcher has only error handling, live opt-in, import and invocation'
$optIn=$launchStatements[1]
Check ($optIn -is [Management.Automation.Language.IfStatementAst] -and $optIn.Clauses.Count -eq 1 -and $null -eq $optIn.ElseClause -and $optIn.Clauses[0].Item1.Extent.Text -ceq "-not `$PSBoundParameters.ContainsKey('Mode')") 'interactive launcher prompts only for omitted Mode'
$optInStatements=@($optIn.Clauses[0].Item2.Statements)
Check ($optInStatements.Count -eq 3 -and $optInStatements[0] -is [Management.Automation.Language.TryStatementAst] -and $optInStatements[0].Body.Statements.Count -eq 1 -and $optInStatements[0].Body.Statements[0].Extent.Text -ceq "`$liveChoice=Read-Host 'Type LIVE to enable Microsoft sign-in, session access and live workflows; Enter cancels'") 'live opt-in reads operator intent before importing application code'
$cancelText="Write-Host 'Startup canceled; no Microsoft session was inspected or opened.';return"
Check ($optInStatements[0].CatchClauses.Count -eq 1 -and $optInStatements[0].CatchClauses[0].IsCatchAll -and $null -eq $optInStatements[0].Finally -and $optInStatements[0].CatchClauses[0].Body.Extent.Text -ceq ('{'+$cancelText+'}')) 'live opt-in cancels on EOF/input failure without fallback'
Check ($optInStatements[1].Extent.Text -ceq ("if(`$liveChoice -ine 'LIVE'){"+$cancelText+'}')) 'blank, EOF and every non-LIVE response return before mode assignment'
Check ($optInStatements[2].Extent.Text -ceq "`$Mode='Live'") 'only affirmative LIVE input supplies an omitted mode'
Check ($launchStatements[2].Extent.Text -ceq 'Import-Module "$PSScriptRoot/M365Toolkit.psm1" -DisableNameChecking' -and $launchStatements[3].Body.Statements.Count -eq 1 -and $launchStatements[3].Body.Statements[0].Extent.Text -ceq 'Invoke-M365Terminal -Mode $Mode | Out-Null') 'launcher dispatch follows explicit parameter binding or affirmative opt-in'
$orchestrator=Find-Function $parsed['terminal/src/Workflow.ps1'] 'Invoke-M365Terminal'
foreach($inputName in @('choice','provider')){
    $inputReads=@($orchestrator.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.StartsWith('{'+"`$$inputName=Read-ToolkitInput ")},$true))
    Check ($inputReads.Count -eq 1 -and $inputReads[0].Body.Statements.Count -eq 1) "$inputName has one guarded startup input read"
    $read=$inputReads[0]
    $cancelText="{Write-ToolkitText `$Runtime 'Startup canceled; no Microsoft session was inspected or opened.';return}"
    Check ($read.CatchClauses.Count -eq 1 -and $read.CatchClauses[0].IsCatchAll -and $null -eq $read.Finally -and $read.CatchClauses[0].Body.Extent.Text -ceq $cancelText) "$inputName cancels on EOF/input failure before session access"
    $siblings=@($read.Parent.Statements);$position=[array]::IndexOf($siblings,$read)
    Check ($siblings[$position+1].Extent.Text -ceq "if([string]::IsNullOrWhiteSpace(`$$inputName) -or `$$inputName -ieq 'Q'){return}") "$inputName blank, whitespace or Q returns before provider dispatch"
    $dispatch=$siblings[$position+2]
    $conditions=@($dispatch.Clauses | ForEach-Object {$_.Item1.Extent.Text})
    $expected=if($inputName -eq 'choice'){@('G','A','E','R')}else{@('G','E')}
    Check ($dispatch -is [Management.Automation.Language.IfStatementAst] -and ($conditions -join ';') -ceq (($expected | ForEach-Object {"`$$inputName -ieq '$_'"}) -join ';') -and $dispatch.ElseClause.Statements.Count -eq 1 -and $dispatch.ElseClause.Statements[0] -is [Management.Automation.Language.ThrowStatementAst]) "$inputName session access requires an explicit recognized provider"
}
$plan=$parsed['terminal/Audit/Start-M365SecurityAudit.ps1'].ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq 'Mode'}
Check ($plan.DefaultValue.Value -ceq 'Plan') 'standalone posture audit retains Plan default'
foreach($path in @('M365Bec.psm1','terminal/Logs/M365Bec.psm1')){
    $exports=@($parsed[$path].FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Export-ModuleMember'},$true))
    Check ($exports.Count -eq 1 -and $exports[0].Extent.Text -ceq 'Export-ModuleMember -Function Invoke-BecInvestigation,New-BecContext,Test-BecManifest,Get-UtcQueryWindow') "$path exports only guarded investigation and non-collecting helpers"
}
$toolkitExports=@($parsed['terminal/M365Toolkit.psm1'].FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Export-ModuleMember'},$true))
Check ($toolkitExports.Count -eq 1 -and $toolkitExports[0].Extent.Text -ceq 'Export-ModuleMember -Function Invoke-M365Terminal,Invoke-ToolkitAuditWorkflow,Invoke-ToolkitLogsWorkflow,Invoke-ToolkitCurrentMailboxSnapshot,ConvertTo-ToolkitMailboxSnapshot,Export-ToolkitMailboxSnapshot,New-ToolkitRuntime,Resolve-ToolkitGraphContext,Resolve-ToolkitExchangeContext,ConvertTo-ToolkitText,Read-ToolkitInput,Write-ToolkitText,Test-ToolkitAddress') 'Toolkit exports supported workflows and non-collecting utilities, not generic command or transport helpers'
$snapshotBody=Find-Function $parsed['terminal/src/MailboxSnapshot.ps1'] 'Invoke-ToolkitCurrentMailboxSnapshot'
Check ($snapshotBody.Extent.Text.Contains('$logsModule=Import-Module') -and $snapshotBody.Extent.Text.Contains('& $logsModule { param($name,$readCommand,$readParameters,$readContext) Invoke-BecSnapshot')) 'guarded snapshot uses the imported module instance for private acquisition'
Check ([regex]::Matches($snapshotBody.Extent.Text,'& \$snapshotRead ').Count -eq 4) 'snapshot retains exactly four scoped logical read call sites'
$tracked=@(& git -C $repository ls-files --cached --others --exclude-standard)
if($LASTEXITCODE -ne 0){throw 'Cannot enumerate public tree'}
Check (@($tracked | Where-Object {$_ -match '(^|/)(tests|fixtures)/|FixtureSupport|Invoke-Test|\.synthetic\.json$'}).Count -eq 0) 'public Git tree contains no QA datasets, scenarios, adapters or replay scripts'
foreach($path in $paths | Where-Object {$_ -ne 'tools/Test-ReleaseBoundary.ps1'}){
    $ast=$parsed[$path]
    Check ($ast.Extent.Text -notmatch 'FixtureSupport|Get-InvestigationFixtureCollections|Invoke-Test(Investigation|SecurityAudit|OrganizationAudit|TracePager)|fixtures[/\\]|\.synthetic\.json|AuditRun') "$path has no offline replay consumer"
    $modeParameters=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ParameterAst] -and $n.Name.VariablePath.UserPath -eq 'Mode'},$true))
    foreach($parameter in $modeParameters){
        $values=@($parameter.Attributes | Where-Object {$_.TypeName.Name -eq 'ValidateSet'} | ForEach-Object {$_.PositionalArguments.Value})
        Check (@($values | Where-Object {$_ -in 'Fixture','Synthetic'}).Count -eq 0) "$path exposes no offline collection mode"
    }
    Check (@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ParameterAst] -and $n.Name.VariablePath.UserPath -eq 'FixturePath'},$true)).Count -eq 0) "$path accepts no fixture path"
}
# These are historical saved-evidence labels, not executable scenarios or collection modes.
Check ((Read-Source 'terminal/src/MailboxSnapshot.ps1').Contains("synthetic=(`$mode -eq 'Fixture')")) 'saved mailbox snapshots retain their declared fixture provenance'
Check ((Read-Source 'terminal/Audit/src/PostureReport.ps1').Contains("-ceq 'Synthetic'")) 'saved posture exports retain their declared synthetic provenance'
Check ((Read-Source 'terminal/Audit/src/Terminal.ps1').Contains("if (`$Result.Mode -eq 'Synthetic')")) 'saved audit summaries retain their historical synthetic warning'
$terminalWorkflow=Read-Source 'terminal/src/Workflow.ps1'
Check ($terminalWorkflow.Contains("if(`$confirm -cne `$requiredConfirmation)") -and $terminalWorkflow.Contains("if(`$answer -ine 'Y')")) 'interactive audit and mailbox authorization confirmations remain'
Check ($terminalWorkflow.Contains('Invoke-M365OrganizationAudit @parameters') -and $terminalWorkflow.Contains('Invoke-BecInvestigation @parameters')) 'confirmed workflows retain the real collection dispatches'
$snapshotLauncher=Read-Source 'terminal/Get-CurrentMailboxSnapshot.ps1'
Check ($snapshotLauncher.Contains('Invoke-ToolkitCurrentMailboxSnapshot -Mode $Mode') -and $snapshotLauncher.Contains('-cne $expected')) 'snapshot launcher passes explicit Live choice and retains typed authorization'
$workflow=Read-Source '.github/workflows/windows-startup.yml'
Check ($workflow -match 'runs-on: ubuntu-latest' -and $workflow -match 'run: ./tools/Test-ReleaseBoundary.ps1' -and $workflow -notmatch 'Test-All|Test-Launchers|FixtureSupport|Invoke-Test') 'release CI dispatches only static checks'
$cmd=Read-Source 'terminal/Start-Flapjacks.cmd'
$inline=[regex]::Match($cmd,'(?m)^pwsh\.exe -NoLogo -NoProfile -Command "([^\r\n]+)"$').Groups[1].Value
Check ([bool]$inline) 'CMD has inline diagnostics before the PowerShell entry point'
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($inline,[ref]$tokens,[ref]$errors)
Check ($errors.Count -eq 0) 'CMD inline PowerShell parses without execution'
foreach($pattern in @("-eq 'Restricted'","-eq 'AllSigned'","'RemoteSigned','AllSigned'","Status -ne 'Valid'","-not `$publishers.Count",'Contact your administrator')){
    Check ($inline.Contains($pattern)) "CMD diagnoses $pattern"
}
Check ($cmd.IndexOf('-Command') -lt $cmd.IndexOf('-File')) 'CMD checks policy and trust before launching'
Check ((Read-Source 'Start-Flapjacks.cmd').Contains('call "%~dp0terminal\Start-Flapjacks.cmd" %*') -and $cmd.Contains('pwsh.exe -NoLogo -NoProfile -File "%~dp0Start-Flapjacks.ps1" %*')) 'normal Windows CMD launchers forward operator arguments without injecting a mode'
Check ($cmd -notmatch 'Set-ExecutionPolicy|Unblock-File|(?<![\w-])-ExecutionPolicy\b|Import-Certificate|Set-AuthenticodeSignature|Remove-Item|Set-Content') 'CMD cannot alter policy, origin markers, signatures or trust'
foreach($path in @('README.md','terminal/README.md','docs/setup/windows/README.md')){
    $text=Read-Source $path
    Check ($text -notmatch 'Set-ExecutionPolicy|Unblock-File|-ExecutionPolicy (Bypass|Unrestricted)|unblock.*(ZIP|extract)') "$path offers no policy relaxation or origin stripping instructions"
}
$receipt=[pscustomobject]@{
    Passed=$true;StaticOnly=$true;PowerShell=$PSVersionTable.PSVersion.ToString();ParsedFiles=$paths.Count;TrackedFiles=$tracked.Count;CollectionEntryPointsChecked=$entries.Count;InteractiveLaunchScriptsChecked=3;Checks=$checks.Count
    ApplicationCodeExecuted=$false;SyntheticRuns=0;TenantCalls=0;WindowsExecution=$false;WorkstationPolicyChanges=0
    Details=$checks.ToArray()
}
if($ResultsPath){$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultsPath -Encoding utf8}
$receipt
