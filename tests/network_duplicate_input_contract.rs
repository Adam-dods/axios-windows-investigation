const SOURCE: &str = include_str!("../src/bin/axios-network-deep-review.rs");
const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

#[test]
fn explicit_targets_are_normalized_and_deduplicated() {
    assert!(SOURCE.contains("options.target.sort_unstable();"));
    assert!(SOURCE.contains("options.target.dedup();"));
    assert!(SOURCE.contains("target.to_ascii_lowercase()"));
}

#[test]
fn network_receipt_uses_real_summary_fields() {
    assert!(RUNNER.contains(r#"@("summary", "active_checks_completed")"#));
    assert!(RUNNER.contains(r#"@("summary", "active_open_ports")"#));
    assert!(!RUNNER.contains(r#"@("summary", "target_checks")"#));
    assert!(!RUNNER.contains(r#"@("summary", "target_open_ports")"#));
}
