const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn persistence_console_reports_real_inventory_counts() {
    for required in [
        "PERSISTENCE SURFACE",
        "Auto-start services",
        "Enabled tasks",
        "Run-key entries",
        "Startup commands",
        "Startup-folder items",
        "WMI PERSISTENCE SUBSCRIPTIONS",
        "Event consumers",
        "Event filters",
        "Filter bindings",
    ] {
        assert!(RUNNER.contains(required), "missing: {required}");
    }
}

#[test]
fn persistence_console_distinguishes_inventory_from_findings() {
    assert!(RUNNER.contains("\"Persistence findings\""));
    assert!(RUNNER.contains("Review items retained"));
    assert!(RUNNER.contains("Review items observed"));
    assert!(RUNNER.contains("Review list truncated"));
    assert!(RUNNER.contains("inventory candidates; not confirmed persistence threats"));
}

#[test]
fn persistence_truncation_display_is_windows_powershell_safe() {
    assert!(RUNNER.contains("$ReviewTruncationDisplay = if ($ReviewItemsTruncated)"));
    assert!(!RUNNER.contains("\"Review list truncated  : {0}\" -f (\n                if"));
}
