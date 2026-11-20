const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

const SCRIPT: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn final_reviews_run_before_success() {
    let success = SCRIPT
        .find(r#"$CompleteHeading = "COMPREHENSIVE SECURITY INVESTIGATION""#)
        .unwrap();

    for stage in [
        r#"Write-AxiosProgress -Stage 23 -Name "AXIOS network service review""#,
        r#"Write-AxiosProgress -Stage 26 -Name "AXIOS deep network evidence review""#,
        r#"Write-AxiosProgress -Stage 27 -Name "AXIOS boot chain review""#,
        r#"Write-AxiosProgress -Stage 28 -Name "AXIOS Code Integrity investigation""#,
        r#"Write-AxiosProgress -Stage 41 -Name "AXIOS persistent investigation state""#,
        r#"Write-AxiosProgress -Stage 42 -Name "AXIOS Reasoning Web and response plan""#,
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
    assert!(COMPLETE.contains("Write-AxiosProgress -Stage 31 -Name \"AXIOS Defender evidence review\""));
    assert!(COMPLETE.contains("Write-AxiosProgress -Stage 32 -Name \"AXIOS collection integrity and contradiction review\""));
    assert!(COMPLETE.contains("Write-AxiosProgress -Stage 42"));
    assert!(!COMPLETE.contains("/40]"));
}
