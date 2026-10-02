const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");

#[test]
fn launcher_verifies_package_before_execution() {
    let verification = LAUNCHER
        .find("Assert-AxiosPackageIntegrity")
        .expect("integrity verifier should exist");

    let mode_switch = LAUNCHER
        .find("switch ($Mode)")
        .expect("mode switch should exist");

    assert!(verification < mode_switch);
    assert!(LAUNCHER.contains("Get-FileHash"));
    assert!(LAUNCHER.contains("-Algorithm SHA256"));
    assert!(LAUNCHER.contains("modified file"));
    assert!(LAUNCHER.contains("missing file"));
    assert!(LAUNCHER.contains("manifest is malformed"));
}

#[test]
fn manifest_paths_are_confined_to_package() {
    assert!(LAUNCHER.contains("[System.IO.Path]::IsPathRooted"));
    assert!(LAUNCHER.contains("[System.IO.Path]::GetFullPath"));
    assert!(LAUNCHER.contains("[System.StringComparison]::OrdinalIgnoreCase"));
    assert!(LAUNCHER.contains("manifest path escaped the package"));
}

#[test]
fn release_manifest_covers_binaries_scripts_and_commands() {
    assert!(BUILD.contains("bin/*.exe"));
    assert!(BUILD.contains("scripts/*.ps1"));
    assert!(BUILD.contains("AXIOS-COMMANDS.txt"));
    assert!(BUILD.contains("> SHA256SUMS.txt"));
}
