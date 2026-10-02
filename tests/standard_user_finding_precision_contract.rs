const EXPOSURE: &str = include_str!("../src/bin/axios-user-exposure-audit.rs");
const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");

#[test]
fn service_path_detection_requires_spaces_in_the_executable_path() {
    assert!(EXPOSURE.contains("$executablePath.Contains(' ')"));
    assert!(!EXPOSURE.contains("$commandLine -match '(?i)\\.exe\\s'"));
}

#[test]
fn response_actions_remain_internal_and_are_not_displayed_as_findings() {
    assert!(RUNNER.contains("response_actions = [int]$ResponsePlan.summary.response_actions"));
    assert!(!RUNNER.contains(
        "[int]$Exposure.summary.findings +\n            [int]$ResponsePlan.summary.response_actions"
    ));
    assert!(RUNNER.contains("Security findings"));
    assert!(!RUNNER.contains("Write-Host (\"Response actions"));
    assert!(!RUNNER.contains("Write-Host \"RECOMMENDED ACTIONS\""));
}
