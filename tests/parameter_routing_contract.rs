const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

#[test]
fn mode_specific_parameters_are_rejected_outside_their_modes() {
    assert!(LAUNCHER.contains("$PSBoundParameters.ContainsKey($Name)"));
    assert!(LAUNCHER.contains("is only accepted with -Mode Network"));
    assert!(LAUNCHER.contains("is accepted only with -Mode Administrator"));
    assert!(LAUNCHER.contains("$Mode -ne \"Administrator\""));
}

#[test]
fn ports_require_an_explicit_target() {
    assert!(LAUNCHER.contains("-Ports requires at least one explicit -Target"));
    assert!(LAUNCHER.contains("$NetworkFocus -notin @(\"connections\", \"targeted\")"));
}
