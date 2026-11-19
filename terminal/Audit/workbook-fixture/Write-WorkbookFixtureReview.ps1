function Write-WorkbookFixtureReview {
    param($Review, $AuditModule, [string]$OutputDirectory)
    $out = [IO.Path]::GetFullPath($OutputDirectory)
    $parent = [IO.Path]::GetDirectoryName($out)
    if (-not $parent -or -not [IO.Directory]::Exists($parent) -or (Test-Path -LiteralPath $out)) {
        throw 'Choose a new output directory below an existing directory.'
    }
    $stage = Join-Path $parent ('.workbook-fixture-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage)
    try {
        & $AuditModule {
            param($dir, $report)
            $display = @(foreach ($row in $report.Rows) {
                [pscustomobject][ordered]@{
                    Control="Workbook row $($row.Row)"; Status=$row.Status
                    'Status details'="Stored fixture comparison: $($row.StoredComparison). $($row.Reason)."
                    Rationale=$row.Predicate
                    'M365 access/licensing/prerequisites'='Invented local fixture. Tenant scope, licensing and effective outcomes are unverified.'
                }
            })
            $coverage = @(foreach ($group in ($report.Rows | Group-Object SourceId)) {
                [pscustomobject]@{Source=$group.Name; 'Collection state'='No collection'; 'Returned records'='Not assessed'}
            })
            $note = 'These seven comparisons use the packaged fixtures. See the ordinary audit report for its source and control counts.'
            $summary = 'Seven synthetic comparisons. All tenant outcomes Not assessed.'
            if ($report.SchemaVersion -cne 'FlapjacksWorkbookFixtureReview/1') {
                $note = "This fixture review has $($report.Rows.Count) rows. The ordinary audit reports its own source and control counts."
                $summary = "$($report.Rows.Count) synthetic comparisons. All tenant outcomes Not assessed."
            }
            $notes = @('SYNTHETIC DEMONSTRATION: independent invented fixtures only.',
                'Each comparison uses only its own fixture. All tenant assessments remain unperformed.',
                $note)
            Write-AuditJson (Join-Path $dir 'review.json') $report
            Write-AuditCsv (Join-Path $dir 'checks.csv') $report.Rows @('Row','SourceId','Field','Predicate','StoredComparison','Reason','Status','FullRowMappingCredit','LiveVerified')
            Write-AuditCsv (Join-Path $dir 'Posture-Report.csv') $display @('Control','Status','Status details','Rationale','M365 access/licensing/prerequisites')
            Write-FlapjacksPostureWorkbook -Path (Join-Path $dir 'Posture-Report.xlsx') -Controls $display -Coverage $coverage -Notes $notes
            $null = Write-FlapjacksPosturePdf -Path (Join-Path $dir 'Posture-Report.pdf') -Controls $display -Coverage $coverage -Notes $notes -Summary $summary -CoverageSummary 'No source collection.' -Synthetic $true
        } $stage $Review
        [IO.Directory]::Move($stage, $out)
    } finally {
        if ([IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
    }
}
