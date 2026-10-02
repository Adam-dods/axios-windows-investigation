use std::fs;

#[test]
fn launcher_sets_native_working_directory_to_package_root() {
    let launcher =
        fs::read_to_string("installer/windows/Run-AXIOS.ps1").expect("launcher should be readable");

    assert!(launcher.contains("[Environment]::CurrentDirectory = $PackageRoot"));
}
