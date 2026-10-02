use std::fs;
use std::path::PathBuf;

#[test]
fn complete_investigation_runs_and_exports_administrator_exposure_audit() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let runner =
        fs::read_to_string(root.join("installer/windows/Run-AXIOS-Complete-Investigation.ps1"))
            .expect("complete investigation runner should be readable");

    let variable = runner
        .find("$AdminExposureAudit =")
        .expect("administrator exposure executable should be defined");
    let invocation = runner
        .find("-FilePath $AdminExposureAudit")
        .expect("administrator exposure audit should run");
    let reasoning = runner
        .find("-FilePath $ReasoningWeb")
        .expect("reasoning should run");

    assert!(variable < invocation);
    assert!(invocation < reasoning);
    assert!(runner.contains("administrator-exposure-audit.json"));
    assert!(runner.contains("administrator_exposure_audit=$AdminExposureAuditPath"));
    assert!(runner
        .contains("administrator_exposure_audit -NotePropertyValue $AdminExposureAuditReport"));
}
