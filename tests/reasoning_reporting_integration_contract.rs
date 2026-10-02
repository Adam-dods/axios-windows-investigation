const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");
const RESULTS: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn portable_result_carries_bounded_reasoning_intelligence() {
    for field in [
        "intelligence",
        "leading_hypothesis",
        "alternative_hypotheses",
        "proof_traces",
        "next_best_checks",
    ] {
        assert!(COMPLETE.contains(&format!("-Name \"{field}\"")));
    }

    assert!(COMPLETE.contains("Select-Object -First 3"));
    assert!(COMPLETE.contains("Select-Object -First 8"));
    assert!(COMPLETE.contains("Select-Object -First 5"));
}

#[test]
fn complete_console_prints_compact_hypothesis_summary() {
    for label in [
        "Leading hypothesis",
        "Hypothesis score",
        "Independent sources",
        "Contradictions",
        "Unresolved facts",
        "Next best checks",
    ] {
        assert!(COMPLETE.contains(label));
    }

    assert!(!COMPLETE.contains("Write-Host ($ReasoningWebReport | ConvertTo-Json"));
}

#[test]
fn results_mode_reads_optional_reasoning_fields_safely() {
    assert!(RESULTS.contains("-Name \"leading_hypothesis\""));
    assert!(RESULTS.contains("-Name \"next_best_checks\""));
    assert!(RESULTS.contains("-Default $null"));
    assert!(RESULTS.contains("Select-Object -First 5"));
    assert!(!RESULTS.contains("$Report.reasoning.leading_hypothesis"));
}
