const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn complete_investigation_writes_a_bounded_portable_result() {
    let result_build = RUNNER
        .find("$PortableResultsSchemaVersion = 1")
        .expect("portable result should be built");
    let completion = RUNNER
        .find("COMPREHENSIVE SECURITY INVESTIGATION")
        .expect("completion marker should exist");

    assert!(result_build < completion);
    assert!(RUNNER.contains("$PortableResultsMaximumBytes = 2500000"));
    assert!(RUNNER.contains("AXIOS-Investigation-Results-{0}.json"));
    assert!(RUNNER.contains("findings_omitted_due_to_size"));
    assert!(RUNNER.contains("collection_errors_omitted"));
    assert!(RUNNER.contains("portable_results_size_bytes"));
    assert!(RUNNER.contains("portable_results_maximum_bytes"));
    assert!(RUNNER.contains("[Text.UTF8Encoding]::new($false)"));
    assert!(RUNNER.contains("portable_report_is_not_a_replacement_for_raw_evidence"));
}

#[test]
fn portable_result_preserves_precision_and_evidence_references() {
    assert!(RUNNER.contains("full_evidence_path"));
    assert!(RUNNER.contains("evidence_manifest"));
    assert!(RUNNER.contains("claim_policy"));
    assert!(RUNNER.contains("partial_reports"));
    assert!(RUNNER.contains("collection_gaps"));
    assert!(RUNNER.contains(r#"-Value $ReasoningWebReport -Name "conclusions" -DefaultValue @()"#));
    assert!(!RUNNER.contains("$ReasoningWebReport.conclusions"));
    assert!(RUNNER.contains("PortableFindingKeys"));
}

#[test]
fn portable_result_tolerates_reports_without_optional_summary() {
    let runner = std::fs::read_to_string("installer/windows/Run-AXIOS-Complete-Investigation.ps1")
        .expect("complete investigation runner should be readable");

    assert!(runner.contains("function Get-AxiosOptionalProperty"));

    assert!(runner.contains("PSObject.Properties[$Name]"));

    assert!(!runner.contains("$Report.summary"));
    assert!(!runner.contains("$Report.collection_status"));
    assert!(!runner.contains("$Report.collection_errors"));
    assert!(!runner.contains("$Report.findings"));
}

#[test]
fn portable_builder_handles_every_optional_report_and_finding_field() {
    let runner = std::fs::read_to_string("installer/windows/Run-AXIOS-Complete-Investigation.ps1")
        .expect("complete runner should be readable");

    assert!(runner.contains("function Get-AxiosOptionalPath"));
    assert!(runner.contains("$Current.PSObject.Properties[$Name]"));

    for unsafe_access in [
        "$PortableDocument.declared_limits",
        "$PortableDocument.summary",
        "$PortableDocument.truncation",
        "$PortableDocument.collection_errors",
        "$PortableDocument.findings",
        "$PortableFinding.",
        "$Summary.administrator_exposure_audit.summary",
    ] {
        assert!(
            !runner.contains(unsafe_access),
            "unsafe optional property access remains: {unsafe_access}"
        );
    }
}
