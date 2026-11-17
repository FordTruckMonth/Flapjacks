function Get-FlapjacksWorkbookSources {
    Get-FlapjacksWorkbookIdentitySources
    Get-FlapjacksWorkbookExchangeSources
    Get-FlapjacksWorkbookCollaborationSources
}

function Get-FlapjacksAllPostureChecks {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)
    Get-FlapjacksPostureChecks -Result $Result
    $meta=Get-AuditProperty $Result 'Metadata'
    $groups=@((Get-AuditProperty $meta 'SelectedGroups' @()))
    if ('WorkbookIdentity' -in $groups) { Get-FlapjacksWorkbookIdentityChecks -Result $Result }
    if ('WorkbookExchange' -in $groups) {
        $baseline=[string](Get-AuditProperty $meta 'WorkbookAntiPhishBaseline' 'None')
        if($baseline -cnotin @('None','Standard','Strict')){$baseline='None'}
        Get-FlapjacksWorkbookExchangeChecks -Result $Result -AntiPhishBaseline $baseline
        Get-FlapjacksMailBaselineChecks -Result $Result -Baseline $baseline
    }
    if ('WorkbookCollaboration' -in $groups) { Get-FlapjacksWorkbookCollaborationChecks -Result $Result }
}
