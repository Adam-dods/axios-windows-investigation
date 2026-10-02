const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const USER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");

#[test]
fn network_persists_normalized_status_and_capability_gaps() {
    assert!(NETWORK.contains("-NotePropertyName \"collection_status\""));
    assert!(NETWORK.contains("-NotePropertyName \"collection_errors\""));
    assert!(NETWORK.contains("$CapabilityGap = \"{0}: {1}; {2}\""));
    assert!(NETWORK.contains("after normalization"));
}

#[test]
fn quick_control_signals_become_structured_findings() {
    assert!(LAYER.contains("$ControlFindings"));
    assert!(LAYER.contains("classification = \"security_control_state\""));
    assert!(LAYER.contains("$LayerResult[\"findings\"]"));
    assert!(LAYER.contains("$LayerResult.summary[\"findings\"]"));
}

#[test]
fn standard_user_exports_findings_and_visibility_gaps() {
    assert!(USER.contains("findings = @("));
    assert!(USER.contains("@($Scope.findings)"));
    assert!(USER.contains("@($Exposure.findings)"));
    assert!(USER.contains("collection_gaps = @("));
    assert!(USER.contains("\"{0}: partial visibility\""));
}

#[test]
fn forensic_visibility_avoids_generic_classification_titles() {
    assert!(LAYER.contains("\"description\","));
    assert!(LAYER.contains("\"observation\","));
    assert!(LAYER.contains("\"message\","));
    assert!(LAYER.contains("\"evidence\""));
}

#[test]
fn firewall_profiles_are_rendered_as_distinct_groups() {
    assert!(USER.contains("\"firewall_profiles\","));
    assert!(USER.contains("Write-Host \"  Firewall profiles\""));
    assert!(USER.contains("\"    Profile             : {0}\""));
    assert!(USER.contains("\"      Default inbound   : {0}\""));
}
