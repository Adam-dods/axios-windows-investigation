const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

const DEVELOPER: &str = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");

#[test]
fn raw_and_unique_context_counts_are_labeled_truthfully() {
    assert!(COMPLETE.contains("Raw context records    : {0}"));
    assert!(LAYER.contains("Unique context records : {0}"));
}

#[test]
fn developer_context_is_not_labeled_as_security_exposure() {
    assert!(DEVELOPER.contains("Assessment observations : {0}"));
    assert!(!DEVELOPER.contains("Security exposures      : {0}"));
}
