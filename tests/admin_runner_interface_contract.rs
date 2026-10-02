const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

const ADMIN_RUNNER: &str =
    include_str!("../installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1");

#[test]
fn administrator_mode_routes_to_the_full_privileged_investigation() {
    let administrator_branch = LAUNCHER
        .split("\"Administrator\" {")
        .nth(1)
        .expect("administrator branch must exist")
        .split("\"Network\" {")
        .next()
        .expect("administrator branch must terminate before Network");

    assert!(administrator_branch.contains("Run-AXIOS-Complete-Investigation.ps1"));
    assert!(administrator_branch.contains("-MaxFiles $MaxFiles"));
    assert!(administrator_branch.contains("-AuditMode $AuditMode"));
    assert!(administrator_branch.contains("-OutputDirectory $OutputDirectory"));
    assert!(!administrator_branch.contains("Run-AXIOS-Administrator-Exposure-Audit.ps1"));
}
#[test]
fn administrator_runner_requires_elevation() {
    assert!(ADMIN_RUNNER.contains("WindowsBuiltInRole]::Administrator"));
    assert!(ADMIN_RUNNER.contains("must run as Administrator"));
}

#[test]
fn administrator_runner_is_strictmode_safe() {
    assert!(ADMIN_RUNNER.contains("Set-StrictMode -Version 2.0"));
    assert!(ADMIN_RUNNER.contains("function Get-AxiosOptionalProperty"));
    assert!(!ADMIN_RUNNER.contains("$Report.summary.findings"));
    assert!(!ADMIN_RUNNER.contains("$Report.collection_status)"));
}

#[test]
fn administrator_runner_returns_compact_receipt() {
    assert!(ADMIN_RUNNER.contains("collector = \"axios_admin_exposure_audit\""));
    assert!(ADMIN_RUNNER.contains("collection_status = [string]$CollectionStatus"));
    assert!(ADMIN_RUNNER.contains("collection_errors = $CollectionErrors.Count"));
    assert!(ADMIN_RUNNER.contains("ConvertTo-Json -Depth 5 -Compress"));
}

#[test]
fn administrator_runner_uses_utf8() {
    assert!(ADMIN_RUNNER.contains("[Console]::InputEncoding = $AxiosUtf8"));
    assert!(ADMIN_RUNNER.contains("[Console]::OutputEncoding = $AxiosUtf8"));
    assert!(ADMIN_RUNNER.contains("$OutputEncoding = $AxiosUtf8"));
}
