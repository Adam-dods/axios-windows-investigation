const REASONING: &str = include_str!("../src/bin/axios-reasoning-web.rs");
const HYPOTHESIS: &str = include_str!("../src/reasoning/hypothesis.rs");

#[test]
fn dependent_collectors_are_grouped_by_underlying_source() {
    assert!(REASONING.contains("fn independence_group"));
    assert!(REASONING.contains("windows_process_execution"));
    assert!(REASONING.contains("windows_network_snapshot"));
    assert!(REASONING.contains("windows_security_configuration"));
    assert!(HYPOTHESIS.contains("independent_support_groups"));
    assert!(HYPOTHESIS.contains("fn independent_evidence"));
}

#[test]
fn identity_conflict_is_a_chain_contradiction_not_a_clean_verdict() {
    assert!(REASONING.contains("classification == \"identity_conflict\""));
    assert!(REASONING.contains("shared_artifact_identity:"));
    assert!(REASONING.contains("hypothesis: HypothesisKind::SuspiciousExecutionChain"));
    assert!(REASONING.contains("\"malware_confirmed\": false"));
    assert!(!REASONING.contains("\"system_clean\": true"));
}

#[test]
fn unknowns_and_explicit_contradictions_reduce_score_separately() {
    assert!(HYPOTHESIS.contains("independent_contradictions"));
    assert!(HYPOTHESIS.contains("after_contradictions"));
    assert!(HYPOTHESIS.contains("unknown_penalty"));
}
