const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn system_layer_derives_control_findings_from_security_evidence() {
    assert!(RUNNER.contains("if ($Layer -eq \"System\")"));
    assert!(RUNNER.contains("classification = \"confirmed_control_state\""));
    assert!(RUNNER.contains("Secure Boot is explicitly disabled"));
    assert!(RUNNER.contains("Microsoft Defender real-time protection is disabled"));
    assert!(RUNNER.contains("User Account Control is disabled"));
    assert!(RUNNER.contains("evidence_source = \"security-posture\""));
}

#[test]
fn system_console_does_not_call_all_signals_generic_findings() {
    assert!(RUNNER.contains("Control findings"));
}
