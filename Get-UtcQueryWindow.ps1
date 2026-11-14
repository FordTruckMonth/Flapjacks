# Pure UTC window-planning helper for M365 message-trace collection.
# NOTE: Provider-specific endpoint, continuation and deduplication rules still
# need separate collector handling; this helper alone does not prove exhaustive
# message-trace collection.

function Get-UtcQueryWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][DateTimeOffset]$Start,
        [Parameter(Mandatory=$true)][DateTimeOffset]$End,
        [Parameter(Mandatory=$false)][double]$MaxWindowDays = 10
    )

    if (-not [double]::IsFinite($MaxWindowDays) -or $MaxWindowDays -lt 1 -or $MaxWindowDays -gt 10) {
        throw "MaxWindowDays must be a finite value in the inclusive range 1..10."
    }
    if ($End -le $Start) {
        throw "End must be strictly greater than Start."
    }

    $startUtc = $Start.ToUniversalTime()
    $endUtc   = $End.ToUniversalTime()
    $maxSpan  = [TimeSpan]::FromDays($MaxWindowDays)

    $cursor = $startUtc
    while ($cursor -lt $endUtc) {
        $remaining = $endUtc - $cursor
        if ($remaining -le $maxSpan) {
            $windowEnd = $endUtc
        } else {
            $windowEnd = $cursor + $maxSpan
        }
        [PSCustomObject]@{
            StartUtc = $cursor
            EndUtc   = $windowEnd
        }
        $cursor = $windowEnd
    }
}
