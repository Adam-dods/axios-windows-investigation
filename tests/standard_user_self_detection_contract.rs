const SOURCE: &str = include_str!("../src/bin/axios-user-scope-access-review.rs");

#[test]
fn standard_user_collector_excludes_only_its_own_process() {
    assert!(SOURCE.contains("let collector_pid = std::process::id();"));
    assert!(SOURCE.contains("$axiosCollectorProcessId = {collector_pid}"));
    assert!(SOURCE.contains("[uint32]$_.ProcessId -ne $axiosCollectorProcessId"));
    assert!(!SOURCE.contains("$_.Name -notlike 'axios-*'"));
}
