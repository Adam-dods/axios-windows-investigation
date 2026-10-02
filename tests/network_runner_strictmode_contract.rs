const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

#[test]
fn network_runner_uses_optional_property_accessors() {
    assert!(RUNNER.contains("function Get-AxiosOptionalProperty"));
    assert!(RUNNER.contains("function Get-AxiosOptionalPath"));
    assert!(RUNNER.contains("-Names @(\"summary\", \"active_checks_completed\")"));
    assert!(RUNNER.contains("-Names @(\"summary\", \"active_open_ports\")"));
}

#[test]
fn network_runner_does_not_dereference_optional_summary_fields() {
    assert!(!RUNNER.contains("$Report.summary.active_checks_completed"));
    assert!(!RUNNER.contains("$Report.summary.active_open_ports"));
}

#[test]
fn overview_without_active_checks_completed_has_stable_defaults() {
    assert!(RUNNER.contains("$ActiveChecks = Get-AxiosOptionalPath"));
    assert!(RUNNER.contains("$ActiveOpenPorts = Get-AxiosOptionalPath"));
    assert!(RUNNER.contains("active_checks = [int]$ActiveChecks"));
    assert!(RUNNER.contains("active_open_ports = [int]$ActiveOpenPorts"));
    assert!(RUNNER.contains("-DefaultValue 0"));
}

#[test]
fn network_receipt_preserves_truthful_status_and_errors() {
    assert!(RUNNER.contains("$CollectionStatus = Get-AxiosOptionalProperty"));
    assert!(RUNNER.contains("$CollectionErrors = @("));
    assert!(RUNNER.contains("collection_errors = $CollectionErrors.Count"));
    assert!(RUNNER.contains("collection_status = [string]$CollectionStatus"));
}

#[test]
fn network_runner_uses_utf8_consistently() {
    assert!(RUNNER.contains("[Console]::InputEncoding = $AxiosUtf8"));
    assert!(RUNNER.contains("[Console]::OutputEncoding = $AxiosUtf8"));
    assert!(RUNNER.contains("$OutputEncoding = $AxiosUtf8"));
}
