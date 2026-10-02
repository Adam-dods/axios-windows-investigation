const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

const SCRIPT: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn final_reviews_run_before_success() {
    let success = SCRIPT
        .find(r#"$CompleteHeading = "COMPREHENSIVE SECURITY INVESTIGATION""#)
        .unwrap();

    for stage in [
        "[23/42] AXIOS network service review",
        "[26/42] AXIOS deep network evidence review",
        "[27/42] AXIOS boot chain review",
        "[28/42] AXIOS Code Integrity investigation",
        "[41/42] AXIOS persistent investigation state",
        "[42/42] AXIOS Reasoning Web and response plan",
    ] {
        assert!(SCRIPT.find(stage).unwrap() < success, "{stage}");
    }
}

#[test]
fn success_is_set_only_after_state_and_response_plan() {
    let pending = SCRIPT
        .find(r#"completion_state = "pending_investigation_state_and_response_plan""#)
        .unwrap();
    let completed = SCRIPT
        .find(r#"$Summary.completion_state = "completed""#)
        .unwrap();

    assert!(pending < completed);
}

#[test]
fn final_review_binaries_are_preflighted() {
    for binary in [
        "axios-network-service-review.exe",
        "axios-network-deep-review.exe",
        "axios-boot-chain-review.exe",
        "axios-code-integrity-investigation.exe",
        "axios-reasoning-web.exe",
    ] {
        assert!(SCRIPT.contains(binary), "{binary}");
    }

    assert!(!SCRIPT.contains("AXIOS_NETWORK_SERVICE_REVIEW_HOOK_V1"));
}

#[test]
fn state_input_is_successful_while_final_completion_is_pending() {
    assert!(SCRIPT.contains(
        r#"success = $true
        completion_state = "pending_investigation_state_and_response_plan""#
    ));
}

#[test]
fn performance_summary_is_written_before_completion() {
    let performance = SCRIPT.find("performance-summary.json").unwrap();
    let success = SCRIPT
        .find(r#"$CompleteHeading = "COMPREHENSIVE SECURITY INVESTIGATION""#)
        .unwrap();

    assert!(performance < success);
    assert!(SCRIPT.contains("axios_performance_summary"));
    assert!(SCRIPT.contains("profile before parallelizing"));
}

#[test]
fn reasoning_web_is_forensic_evidence_before_completion() {
    let reasoning = SCRIPT.find("reasoning-web.json").unwrap();
    let forensic = SCRIPT.find("reasoning_web=$ReasoningWebPath").unwrap();
    let success = SCRIPT
        .find(r#"$CompleteHeading = "COMPREHENSIVE SECURITY INVESTIGATION""#)
        .unwrap();

    assert!(reasoning < forensic);
    assert!(forensic < success);
    assert!(SCRIPT.contains("$ReasoningWeb"));
}

#[test]
fn console_complete_hides_temporary_paths_and_machine_receipt() {
    assert!(COMPLETE.contains("if ($env:AXIOS_CONSOLE_SESSION -ne \"1\")"));
    assert!(COMPLETE.contains("Detailed TXT report"));
    assert!(COMPLETE.contains("Portable JSON result"));
    assert!(COMPLETE.contains("Raw evidence directory"));
}

#[test]
fn complete_progress_numbers_every_collector() {
    assert!(COMPLETE.contains("[31/42] AXIOS Defender evidence review"));
    assert!(COMPLETE.contains("[32/42] AXIOS collection integrity and contradiction review"));
    assert!(COMPLETE.contains("[42/42]"));
    assert!(!COMPLETE.contains("/40]"));
}
