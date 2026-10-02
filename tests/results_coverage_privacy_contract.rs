const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn coverage_renderer_flattens_structured_errors_professionally() {
    assert!(LAYER.contains("function Add-AxiosCoverageMessage"));
    assert!(LAYER.contains("Add-AxiosCoverageMessage -Value $RawError"));
    assert!(LAYER.contains("[IO.Path]::GetFileName($SourceName)"));
    assert!(LAYER.contains("$NormalizedErrors.Contains($Message)"));
}

#[test]
fn coverage_renderer_suppresses_internal_evidence_paths() {
    for field in [
        "full_evidence_path",
        "evidence_path",
        "result_path",
        "output_path",
        "artifact_path",
        "machine_receipt",
    ] {
        assert!(
            LAYER.contains(&format!("\"{field}\"")),
            "hidden coverage field is missing: {field}"
        );
    }

    assert!(LAYER.contains("[internal evidence path]"));
}

#[test]
fn coverage_console_does_not_stringify_raw_objects_directly() {
    assert!(!LAYER.contains("Write-Host (\"- {0}\" -f [string]$RawError)"));
    assert!(!LAYER.contains("$NormalizedErrors.Add([string]$RawError)"));
}
