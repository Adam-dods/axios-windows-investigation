use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn package_contains_administrator_exposure_audit() {
    let root = root();
    let build = fs::read_to_string(root.join("scripts/build-windows-complete-investigation.sh"))
        .expect("build script should be readable");
    let runner = fs::read_to_string(
        root.join("installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1"),
    )
    .expect("administrator runner should be readable");

    assert!(build.contains("axios-admin-exposure-audit"));
    assert!(build.contains("Run-AXIOS-Administrator-Exposure-Audit.ps1"));
    assert!(runner.contains("axios-admin-exposure-audit.exe"));
    assert!(runner.contains("must run as Administrator"));
}
