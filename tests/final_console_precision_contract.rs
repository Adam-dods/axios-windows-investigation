const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn results_render_every_counted_context_observation() {
    assert!(LAYER.contains("$ForensicObservations"));
    assert!(LAYER.contains("@($ContextFindings)"));
    assert!(LAYER.contains("@($SeparateContextObservations)"));
    assert!(LAYER.contains("$ForensicHeading = \"FORENSIC VISIBILITY\""));
}

#[test]
fn results_explain_scope_and_render_dates_readably() {
    assert!(LAYER.contains("Result scope           : latest completed command"));
    assert!(LAYER.contains("AddMilliseconds"));
    assert!(LAYER.contains("yyyy-MM-dd HH:mm:ss K"));
    assert!(!LAYER.contains("\"  {0,-20}: {1}\""));
}

#[test]
fn firewall_visibility_limit_makes_focused_result_partial() {
    assert!(NETWORK.contains("$RequiredCapabilityUnavailable"));
    assert!(NETWORK.contains("$Focus -in @(\"firewall\", \"full\")"));
    assert!(NETWORK.contains("$CollectionStatus = \"partial\""));
}

#[test]
fn network_headings_use_title_length_separators() {
    assert!(NETWORK.contains("Write-Host (\"=\" * $NetworkHeading.Length)"));
    assert!(NETWORK.contains("Write-Host (\"-\" * $NetworkHeading.Length)"));
}

#[test]
fn administrator_is_the_only_full_investigation_mode() {
    assert!(LAUNCHER.contains("\"Administrator\" {"));
    assert!(!LAUNCHER.contains("\"Complete\" {"));
    assert!(!LAUNCHER.contains("Complete compatibility alias:"));
    assert!(!LAUNCHER.contains("Administrator exposure audit:"));
    assert!(!COMPLETE.contains("AXIOS complete investigation completed."));
}
