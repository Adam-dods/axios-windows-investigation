const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn complete_runner_returns_a_compact_receipt_instead_of_the_full_summary() {
    assert!(!RUNNER.contains("Get-Content -LiteralPath $SummaryPath"));
    assert!(RUNNER.contains("performance_summary_path = $PerformanceSummaryPath"));
    assert!(RUNNER.contains("forensic_export_path = $ManifestPath"));
    assert!(RUNNER.contains("reports_failed = 0"));
    assert!(RUNNER.contains("ConvertTo-Json -Depth 4 -Compress"));
}
