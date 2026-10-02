const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

#[test]
fn launcher_preflights_output_directory_writability() {
    assert!(LAUNCHER.contains("AXIOS OutputDirectory is not writable:"));
    assert!(LAUNCHER.contains(".axios-write-probe-"));
    assert!(LAUNCHER.contains("[System.IO.File]::WriteAllText("));
    assert!(LAUNCHER.contains("-ErrorAction SilentlyContinue"));
}

#[test]
fn help_mode_does_not_require_a_writable_output_directory() {
    assert!(LAUNCHER.contains(r#"if ($Mode -ne "Help") {"#));
}
