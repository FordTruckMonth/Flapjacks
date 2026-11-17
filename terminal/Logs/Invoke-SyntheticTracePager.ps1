#requires -Version 7.4
# Compatibility entry point for the original independent fixture suite.
# Original Claw versions are preserved in provenance/claw-before-direct-build/.
. "$PSScriptRoot/src/Core.ps1"
. "$PSScriptRoot/src/Paging.ps1"
function Invoke-SyntheticTracePager {
    param([Parameter(Mandatory)][scriptblock]$Query,[ValidateRange(1,1000)][int]$MaxPages=10)
    Invoke-BecPagedQuery -Query $Query -MaxPages $MaxPages
}
