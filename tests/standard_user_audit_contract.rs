use std::fs;
use std::path::PathBuf;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn package_contains_standard_user_audit_components() {
    let root = project_root();
    let build = fs::read_to_string(root.join("scripts/build-windows-complete-investigation.sh"))
        .expect("build script should be readable");
    let runner =
        fs::read_to_string(root.join("installer/windows/Run-AXIOS-Standard-User-Audit.ps1"))
            .expect("standard user runner should be readable");

    assert!(build.contains("axios-user-scope-access-review"));
    assert!(build.contains("axios-user-exposure-audit"));
    assert!(build.contains("axios-standard-user-response-plan"));
    assert!(build.contains("Run-AXIOS-Standard-User-Audit.ps1"));
    assert!(runner.contains("axios-core.exe"));
    assert!(runner.contains("network-posture"));
    assert!(runner.contains("axios-user-scope-access-review.exe"));
    assert!(runner.contains("axios-user-exposure-audit.exe"));
    assert!(runner.contains("axios-standard-user-response-plan.exe"));
    assert!(runner.contains("standard-user-response-plan.json"));
}

#[test]
fn standard_user_runner_never_requires_administrator() {
    let root = project_root();
    let runner =
        fs::read_to_string(root.join("installer/windows/Run-AXIOS-Standard-User-Audit.ps1"))
            .expect("standard user runner should be readable");

    assert!(runner.contains("read_only_standard_user_assessment"));
    assert!(runner.contains("system_wide_kernel_memory_visibility"));
    assert!(!runner.contains("Test-IsAdministrator"));
    assert!(!runner.contains("must run as Administrator"));
}
