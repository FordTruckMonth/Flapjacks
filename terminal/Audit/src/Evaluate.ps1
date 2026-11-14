function Get-AuditObservations($Results) {
    $findings=[System.Collections.Generic.List[object]]::new()
    function Add-Observation($SourceId,$ObjectId,$Rule,$Title,$Detail) {
        $findings.Add([pscustomobject]@{ SourceId=$SourceId; ObjectId=[string]$ObjectId; Rule=$Rule; Severity='Review'; Title=$Title; Detail=$Detail })
    }
    foreach ($result in $Results) {
        # Never turn a missing/partial source into a positive assertion about its controls.
        if ($result.Status -ne 'Collected') { continue }
        switch ($result.SourceId) {
            'conditional-access' {
                if ($result.Count -eq 0) { Add-Observation $result.SourceId '' 'CA-EMPTY' 'No Conditional Access policies returned' 'This response contains no policies. Check security defaults and approved protection design. This is not a compliance verdict.' }
                foreach ($policy in $result.Items) {
                    $id=Get-AuditProperty $policy 'id' ''
                    $state=Get-AuditProperty $policy 'state' 'unknown'
                    if ($state -in @('disabled','enabledForReportingButNotEnforced')) { Add-Observation $result.SourceId $id 'CA-NOT-ENFORCED' 'Conditional Access policy is not enabled' "Stored state: $state. Disabled/report-only policies do not enforce their configured grant controls." }
                    if ($state -notin @('enabled','disabled','enabledForReportingButNotEnforced')) { Add-Observation $result.SourceId $id 'CA-STATE-UNKNOWN' 'Conditional Access policy state is unknown' 'Missing or unrecognized state. Enforcement cannot be determined from this response.' }
                    $users=Get-AuditProperty (Get-AuditProperty $policy 'conditions') 'users'
                    $excluded=@()
                    foreach ($key in @('excludeUsers','excludeGroups','excludeRoles')) {
                        $values=Get-AuditProperty $users $key @()
                        if (@($values).Count -gt 0) { $excluded+="$($key): $(@($values).Count)" }
                    }
                    if ($excluded.Count -gt 0) { Add-Observation $result.SourceId $id 'CA-EXCLUSIONS' 'Policy has user, group or role exclusions' (($excluded -join '; ')+'. Exclusions can be intentional, including emergency access. Membership and effective coverage were not evaluated.') }
                }
            }
            'security-defaults' {
                foreach ($policy in $result.Items) {
                    if ((Get-AuditProperty $policy 'isEnabled') -ceq $false) { Add-Observation $result.SourceId (Get-AuditProperty $policy 'id' '') 'DEFAULTS-OFF' 'Security defaults are disabled' 'This can be expected when Conditional Access is used. Review the intended alternative; this observation alone is not a security failure.' }
                }
            }
            'authorization-policy' {
                foreach ($policy in $result.Items) {
                    $perms=Get-AuditProperty $policy 'defaultUserRolePermissions'
                    if ((Get-AuditProperty $perms 'allowedToCreateApps') -ceq $true) { Add-Observation $result.SourceId (Get-AuditProperty $policy 'id' '') 'USER-APP-REGISTRATION' 'Default users may register applications' 'Confirm this matches the organization policy. Existing app permissions and credentials were not collected.' }
                }
            }
            'exchange-organization' {
                foreach ($policy in $result.Items) {
                    if ((Get-AuditProperty $policy 'AuditDisabled') -ceq $true) { Add-Observation $result.SourceId (Get-AuditProperty $policy 'Identity' '') 'MAILBOX-AUDIT-DISABLED' 'Organization mailbox auditing is disabled' 'Current organization flag only. No audit logs, per-mailbox overrides or historical coverage were collected.' }
                }
            }
            'exchange-outbound-spam-policies' {
                foreach ($policy in $result.Items) {
                    if ((Get-AuditProperty $policy 'AutoForwardingMode') -eq 'On') { Add-Observation $result.SourceId (Get-AuditProperty $policy 'Identity' '') 'AUTO-FORWARDING-ON' 'Outbound policy permits automatic forwarding' 'Review targeting and approved use. Other controls can still block forwarding; no effective delivery test was performed.' }
                }
            }
            'exchange-dkim' {
                foreach ($policy in $result.Items) {
                    if ((Get-AuditProperty $policy 'Enabled') -ceq $false) { Add-Observation $result.SourceId (Get-AuditProperty $policy 'Identity' '') 'DKIM-DISABLED' 'Stored DKIM signing configuration is disabled' 'Review whether this domain sends mail and the intended signing configuration. No DNS or delivery validation was performed.' }
                }
            }
        }
    }
    return $findings.ToArray()
}
