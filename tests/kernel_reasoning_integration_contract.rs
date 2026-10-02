const KERNEL: &str = include_str!("../src/bin/axios-kernel-runtime-integrity.rs");
const REASONING: &str = include_str!("../src/bin/axios-reasoning-web.rs");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn kernel_runtime_artifacts_reach_reasoning_web() {
    assert!(KERNEL.contains("\"artifacts\": artifacts"));
    assert!(REASONING.contains("nonempty_array_count(kernel, \"/artifacts\")"));
    assert!(REASONING.contains("\"kernel-runtime-integrity.artifacts\""));
    assert!(!REASONING.contains("\"kernel-runtime-integrity.findings\""));
}

#[test]
fn complete_mode_routes_kernel_runtime_report_to_reasoning() {
    assert!(COMPLETE.contains("\"--kernel\", $KernelRuntimeIntegrityPath"));
    assert!(COMPLETE.contains("kernel_runtime_integrity=$KernelRuntimeIntegrityPath"));
}
