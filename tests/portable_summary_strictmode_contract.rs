use std::fs;
use std::path::PathBuf;

fn runner_source() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    fs::read_to_string(root.join("installer/windows/Run-AXIOS-Complete-Investigation.ps1"))
        .expect("complete investigation runner should be readable")
}

#[test]
fn portable_builder_tolerates_missing_summary_sections() {
    let source = runner_source();

    let forbidden = [
        "$Summary.hardware",
        "$Summary.health_posture",
        "$Summary.kernel_runtime_integrity",
        "$Summary.boot_chain_review",
        "$Summary.firmware_identity_review",
        "$Summary.network_posture",
        "$Summary.network_exposure",
        "$Summary.network_identity_review",
        "$Summary.network_service_review",
        "$Summary.defender_evidence",
        "$Summary.security_controls_review",
        "$Summary.remote_access_review",
        "$Summary.platform_hardening_review",
        "$ReasoningWebReport.conclusions",
        "$ReasoningWebReport.claim_policy",
        "$ResponsePlanReport.plan",
        "$ResponsePlanReport.items",
    ];

    for property in forbidden {
        assert!(
            !source.contains(property),
            "unsafe StrictMode property read remains: {property}"
        );
    }

    let required_optional_reads = [
        r#"-Value $Summary -Name "hardware""#,
        r#"-Value $Summary -Name "health_posture""#,
        r#"-Value $Summary -Name "kernel_runtime_integrity""#,
        r#"-Value $Summary -Name "boot_chain_review""#,
        r#"-Value $Summary -Name "firmware_identity_review""#,
        r#"-Value $Summary -Name "network_posture""#,
        r#"-Value $Summary -Name "network_exposure""#,
        r#"-Value $Summary -Name "network_identity_review""#,
        r#"-Value $Summary -Name "network_service_review""#,
        r#"-Value $Summary -Name "defender_evidence""#,
        r#"-Value $Summary -Name "security_controls_review""#,
        r#"-Value $Summary -Name "remote_access_review""#,
        r#"-Value $Summary -Name "platform_hardening_review""#,
        r#"-Value $ReasoningWebReport -Name "conclusions""#,
        r#"-Value $ReasoningWebReport -Name "claim_policy""#,
        r#"-Value $ResponsePlanReport -Name "plan""#,
        r#"-Value $ResponsePlanReport -Name "items""#,
    ];

    for property in required_optional_reads {
        assert!(
            source.contains(property),
            "safe optional property read is missing: {property}"
        );
    }
}

#[test]
fn required_completion_fields_remain_required() {
    let source = runner_source();

    assert!(source.contains("$Summary.success -eq $true"));
    assert!(source.contains("completion_state = $Summary.completion_state"));
}
