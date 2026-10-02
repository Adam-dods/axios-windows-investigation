const SCRIPT: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn investigation_uses_unique_output_directory() {
    assert!(SCRIPT.contains("complete-investigation-$RunId"));
}

#[test]
fn investigation_includes_application_analysis() {
    assert!(SCRIPT.contains("axios-application-investigation.exe"));

    assert!(SCRIPT.contains("application-investigation.json"));
}

#[test]
fn investigation_includes_update_exposure_data() {
    assert!(SCRIPT.contains("update-exposure.json"));
    assert!(SCRIPT.contains("-Arguments @(\"updates\")"));
    assert!(SCRIPT.contains("update_exposure = Get-AxiosCompactReport"));
}

#[test]
fn investigation_verifies_binary_hashes() {
    assert!(SCRIPT.contains("SHA256SUMS.txt"));
    assert!(SCRIPT.contains("Get-FileHash"));
}

#[test]
fn investigation_writes_utf8_without_bom() {
    assert!(SCRIPT.contains("System.Text.UTF8Encoding($false)"));
}

#[test]
fn investigation_does_not_contain_legacy_parser_bug() {
    assert!(!SCRIPT.contains("$LASTEXITCODE:"));
}

#[test]
fn investigation_reuses_the_universal_file_audit() {
    assert!(SCRIPT.contains("\"--audit\",\n            $AuditPath"));
}

#[test]
fn investigation_defaults_to_fast_bounded_audit_with_smart_override() {
    assert!(SCRIPT.contains(r#"[ValidateSet("fast", "smart")]"#));
    assert!(SCRIPT.contains(r#"[string]$AuditMode = "fast""#));
    assert!(SCRIPT.contains("\"--mode\",\n            $AuditMode"));
    assert!(SCRIPT.contains("audit_mode = $AuditMode"));
    assert!(SCRIPT.contains("audit_scope = $AuditReport.scan_scope"));

    assert!(SCRIPT.contains("\"--seed-report\",\n            $CombinedPersistencePath"));
    assert!(SCRIPT.contains("\"--seed-report\",\n            $LiveActivityPath"));
}

#[test]
fn investigation_does_not_request_full_drive_audit() {
    assert!(!SCRIPT.contains("\"--full\""));
}

#[test]
fn command_reports_are_validated_before_they_are_saved() {
    let invoke_start = SCRIPT.find("function Invoke-AxiosJson").unwrap();
    let invoke_end = SCRIPT[invoke_start..]
        .find("function Test-AxiosHashes")
        .map(|offset| invoke_start + offset)
        .unwrap();
    let invoke = &SCRIPT[invoke_start..invoke_end];

    for validation in [
        "returned an empty report",
        "returned invalid JSON",
        "report is missing success",
        "non-boolean success value",
        "report indicates failure",
    ] {
        assert!(invoke.contains(validation), "{validation}");
    }

    let validation = invoke.find("report indicates failure").unwrap();
    let save = invoke
        .find("Write-AxiosText `\n        -Path $Destination")
        .unwrap();

    assert!(validation < save);
}

#[test]
fn hash_manifest_entries_are_confined_to_the_package_root() {
    assert!(SCRIPT.contains("Path]::IsPathRooted($RelativePath)"));
    assert!(SCRIPT.contains("$RelativePath.Contains(\":\")"));
    assert!(SCRIPT.contains("SHA256SUMS entry escapes the package root"));
    assert!(SCRIPT.contains("GetFullPath($Root)"));
    assert!(SCRIPT.contains("OrdinalIgnoreCase"));
}
