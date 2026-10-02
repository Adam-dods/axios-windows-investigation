const MAIN: &str = include_str!("../src/main.rs");
const MODULES: &str = include_str!("../src/system/mod.rs");
const COLLECTOR: &str = include_str!("../src/system/context_posture.rs");
const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const COMMANDS: &str = include_str!("../installer/windows/AXIOS-COMMANDS.txt");

#[test]
fn context_posture_is_a_real_core_capability() {
    assert!(MODULES.contains("pub mod context_posture;"));
    assert!(MAIN.contains("ContextPosture"));
    assert!(MAIN.contains("system::context_posture::collect()"));
    assert!(COLLECTOR.contains("windows_context_posture"));
}

#[test]
fn context_is_a_system_focus_branch() {
    assert!(LAUNCHER.contains("\"context\" {"));
    assert!(LAUNCHER.contains("\"Context\""));
    assert!(LAUNCHER.contains("-Layer $SystemLayer"));

    assert!(COMMANDS.contains("-Mode System -SystemFocus context"));
    assert!(!COMMANDS.contains("-Mode Context"));
}
#[test]
fn quick_includes_context_evidence() {
    let quick_start = LAYER.find("\"Quick\" {").expect("Quick layer should exist");
    let quick_end = LAYER[quick_start..]
        .find("\n    }")
        .expect("Quick layer should end");

    assert!(LAYER[quick_start..quick_start + quick_end].contains("\"context-posture\""));
}

#[test]
fn context_collection_is_bounded() {
    for required in [
        "maximum_languages",
        "maximum_network_profiles",
        "maximum_network_interfaces",
        "Select-Object -First 32",
        "Select-Object -First 64",
    ] {
        assert!(COLLECTOR.contains(required));
    }
}
