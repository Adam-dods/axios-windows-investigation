const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

#[test]
fn launcher_restores_native_working_directory_in_finally() {
    assert!(LAUNCHER.contains("$PreviousNativeDirectory = [Environment]::CurrentDirectory"));
    assert!(LAUNCHER.contains("finally {"));
    assert!(LAUNCHER.contains("[Environment]::CurrentDirectory = $PreviousNativeDirectory"));
}

#[test]
fn invalid_previous_directory_does_not_mask_execution_result() {
    assert!(
        LAUNCHER.contains("Test-Path -LiteralPath $PreviousNativeDirectory -PathType Container")
    );
}
