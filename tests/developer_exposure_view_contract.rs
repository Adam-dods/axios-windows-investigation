const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");
const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");

#[test]
fn developer_exposure_is_a_hidden_mode_and_supports_save() {
    assert!(LAUNCHER.contains("\"DeveloperExposure\" {"));
    assert!(LAUNCHER.contains("Run-AXIOS-Developer-Exposure-View.ps1"));
    assert!(LAUNCHER.contains("[switch]$Save"));

    let help_start = LAUNCHER.find("function Show-AxiosHelp").unwrap();
    let help_end = LAUNCHER[help_start..]
        .find("$Administrator = Test-AxiosAdministrator")
        .unwrap();
    let public_help = &LAUNCHER[help_start..help_start + help_end];

    assert!(!public_help.contains("DeveloperExposure"));
}

#[test]
fn developer_exposure_view_is_evidence_only() {
    assert!(RUNNER.contains("exploitation_performed = $false"));
    assert!(RUNNER.contains("connection_attempted = $false"));
    assert!(RUNNER.contains("system_modified = $false"));
    assert!(RUNNER.contains("credentials_collected = $false"));
    assert!(!RUNNER.contains("next_check ="));
    assert!(!RUNNER.contains("remediation ="));
    assert!(!RUNNER.contains("response_plan"));
}

#[test]
fn developer_exposure_view_is_packaged_without_a_new_binary() {
    assert!(BUILD.contains("Run-AXIOS-Developer-Exposure-View.ps1"));
    assert!(RUNNER.contains("axios-user-exposure-audit"));
    assert!(RUNNER.contains("axios-remote-access-review"));
    assert!(RUNNER.contains("axios-security-controls-review"));
}

#[test]
fn user_exposure_collector_supports_cim_and_legacy_wmi() {
    let source = include_str!("../src/bin/axios-user-exposure-audit.rs");

    assert!(source.contains("function Get-AxiosManagementInstance"));
    assert!(source.contains("Get-Command Get-CimInstance"));
    assert!(source.contains("Get-Command Get-WmiObject"));
    assert!(source.contains("Windows management instrumentation is unavailable."));
}

#[test]
fn user_scope_process_collection_supports_cim_and_legacy_wmi() {
    let source = include_str!("../src/bin/axios-user-scope-access-review.rs");

    assert!(source.contains("function Get-AxiosUserManagementInstance"));
    assert!(source.contains("Get-Command Get-CimInstance"));
    assert!(source.contains("Get-Command Get-WmiObject"));
    assert!(source.contains("Get-AxiosUserManagementInstance \"Win32_Process\""));
}
