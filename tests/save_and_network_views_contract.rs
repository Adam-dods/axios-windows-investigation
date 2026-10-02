const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const NETWORK_RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const NETWORK_SOURCE: &str = include_str!("../src/bin/axios-network-deep-review.rs");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn save_is_opt_in_and_console_runs_use_a_cleanup_bound_session() {
    assert!(LAUNCHER.contains("[switch]$Save"));
    assert!(LAUNCHER.contains("AXIOS parameter -OutputDirectory requires -Save."));
    assert!(LAUNCHER.contains("AXIOS-Session-{0}"));
    assert!(LAUNCHER.contains("AXIOS_SESSION_DIRECTORY"));
    assert!(LAUNCHER.contains("PowerShell.Exiting"));
    assert!(LAUNCHER.contains("$SessionOutputDirectory"));
    assert!(LAUNCHER.contains("-Recurse"));
    assert!(LAUNCHER.contains("-ErrorAction SilentlyContinue"));
}

#[test]
fn network_exposes_exactly_seven_primary_views() {
    for view in [
        "overview",
        "wifi",
        "connections",
        "services",
        "dns",
        "routing",
        "firewall",
    ] {
        assert!(LAUNCHER.contains(&format!("\"{view}\"")));
        assert!(NETWORK_RUNNER.contains(&format!("\"{view}\"")));
    }

    assert!(LAUNCHER.contains("[string]$NetworkFocus = \"full\""));
    assert!(NETWORK_RUNNER.contains("[string]$Focus = \"full\""));
    assert!(NETWORK_SOURCE.contains("default_value_t = Focus::Full"));
}

#[test]
fn targeted_checks_are_nested_under_connections_with_legacy_compatibility() {
    assert!(LAUNCHER.contains("-NetworkFocus connections -Target"));
    assert!(LAUNCHER.contains("legacy targeted"));
    assert!(NETWORK_SOURCE.contains("Self::Connections | Self::Targeted | Self::Full"));
}

#[test]
fn complete_and_results_respect_console_only_output_routing() {
    assert!(COMPLETE.contains("[string]$OutputDirectory"));
    assert!(COMPLETE.contains("$OutputRoot = $OutputDirectory"));
    assert!(COMPLETE.contains("$PortableResultsDirectory = $OutputDirectory"));
    assert!(LAYER.contains("[string[]]$ResultSearchDirectory = @($OutputDirectory)"));
    assert!(LAUNCHER.contains("-ResultSearchDirectory $ResultDirectories"));
}

#[test]
fn wifi_review_does_not_collect_or_export_credentials() {
    let combined = format!("{LAUNCHER}\n{NETWORK_RUNNER}\n{NETWORK_SOURCE}").to_ascii_lowercase();
    for forbidden in [
        "key=clear",
        "key content",
        "wifi password",
        "wlan show profile name=",
    ] {
        assert!(
            !combined.contains(forbidden),
            "credential extraction token found: {forbidden}"
        );
    }
}
