const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn context_is_separate_from_important_findings() {
    assert!(RUNNER.contains("$AllContextObservations"));
    assert!(RUNNER.contains("Context observations"));
    assert!(RUNNER.contains("SUPPORTING OBSERVATIONS"));
    assert!(RUNNER.contains("-Name \"classification\""));
    assert!(RUNNER.contains("-eq \"context\""));
}

#[test]
fn software_displays_real_inventory_and_update_state() {
    for value in [
        "INSTALLED SOFTWARE PROFILE",
        "Installed entries",
        "Inventory coverage",
        "Browser extensions",
        "Extension coverage",
        "UPDATE AND ENDPOINT PROTECTION",
        "Pending updates",
        "Restart state",
        "Restart reasons",
        "Defender signature age",
        "Tamper protection",
        "PENDING SECURITY UPDATES",
    ] {
        assert!(RUNNER.contains(value), "missing: {value}");
    }
}

#[test]
fn receipt_has_separate_context_count() {
    assert!(RUNNER.contains("context_observations = $AllContextObservations.Count"));
}
