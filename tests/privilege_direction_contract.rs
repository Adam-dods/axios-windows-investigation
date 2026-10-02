const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

const USER_RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");

#[test]
fn administrator_can_invoke_user_layer() {
    assert!(!LAUNCHER.contains("AXIOS User mode cannot run from elevated PowerShell."));

    assert!(!USER_RUNNER.contains("AXIOS User mode requires a standard-user PowerShell session."));

    assert!(LAUNCHER.contains("Run-AXIOS-Standard-User-Audit.ps1"));
}

#[test]
fn administrator_mode_still_requires_elevation() {
    assert!(LAUNCHER.contains("Administrator mode requires elevated PowerShell."));
    assert!(!LAUNCHER.contains("AXIOS Complete mode requires elevated PowerShell."));
}
#[test]
fn actual_execution_context_remains_truthful() {
    assert!(USER_RUNNER.contains("$IsAdministrator = $CurrentPrincipal.IsInRole("));

    assert!(USER_RUNNER.contains("administrator"));
}
