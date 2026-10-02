const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");
const REASONING: &str = include_str!("../src/bin/axios-reasoning-web.rs");

#[test]
fn complete_collects_and_routes_context_evidence() {
    assert!(COMPLETE.contains("context-posture.json"));
    assert!(COMPLETE.contains(r#"@("context-posture")"#));
    assert!(COMPLETE.contains("\"--context\", $ContextPosturePath"));
    assert!(COMPLETE.contains("context = $ContextPostureReport"));
}

#[test]
fn reasoning_requires_and_interprets_context() {
    assert!(REASONING.contains("const REQUIRED_INPUTS: [&str; 20]"));
    assert!(REASONING.contains("\"context\","));
    assert!(REASONING.contains("input.context.success"));
    assert!(REASONING.contains("context.timezone"));
    assert!(REASONING.contains("context.time_synchronization_state"));
    assert!(REASONING.contains("context.public_network_profiles"));
}
