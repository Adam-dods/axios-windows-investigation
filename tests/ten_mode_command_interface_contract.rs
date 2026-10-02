const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

const LAYER_RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

const COMMANDS: &str = include_str!("../installer/windows/AXIOS-COMMANDS.txt");

const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");

#[test]
fn launcher_exposes_seven_main_help_and_three_hidden_developer_modes() {
    for mode in [
        "Help",
        "User",
        "Administrator",
        "Network",
        "System",
        "Persistence",
        "Software",
        "Results",
        "DeveloperExposure",
        "DeveloperCredential",
        "DeveloperArchive",
    ] {
        assert!(
            LAUNCHER.contains(&format!("\"{mode}\"")),
            "launcher is missing mode {mode}"
        );
    }

    for public_mode in [
        "Help",
        "User",
        "Administrator",
        "Network",
        "System",
        "Persistence",
        "Software",
        "Results",
    ] {
        assert!(
            COMMANDS.contains(&format!("-Mode {public_mode}")),
            "command documentation is missing mode {public_mode}"
        );
    }

    for hidden_or_removed in [
        "DeveloperExposure",
        "DeveloperCredential",
        "DeveloperArchive",
        "-Mode Complete",
        "-Mode Quick",
        "-Mode Context",
    ] {
        assert!(
            !COMMANDS.contains(hidden_or_removed),
            "non-public mode is documented: {hidden_or_removed}"
        );
    }
}

#[test]
fn focused_public_modes_use_the_shared_layer_runner() {
    assert!(LAUNCHER.contains("$SystemLayer = switch ($SystemFocus)"));
    assert!(LAUNCHER.contains("\"Quick\""));
    assert!(LAUNCHER.contains("\"Context\""));
    assert!(LAUNCHER.contains("-Layer $SystemLayer"));

    for layer in ["Persistence", "Software", "Results"] {
        assert!(
            LAUNCHER.contains(&format!("-Layer {layer}")),
            "launcher is missing layer {layer}"
        );
    }

    assert!(LAUNCHER.contains("Run-AXIOS-Layer.ps1"));
}

#[test]
fn layers_use_real_existing_core_capabilities() {
    for command in [
        "security-posture",
        "health-posture",
        "live-activity",
        "network-posture",
        "hardware-trust",
        "kernel-posture",
        "registry-persistence",
        "extended-persistence",
        "persistence-coverage",
        "software-inventory",
        "updates",
        "browser-extensions",
        "deep-investigation",
    ] {
        assert!(
            LAYER_RUNNER.contains(&format!("\"{command}\"")),
            "layer runner is missing core command {command}"
        );
    }
}

#[test]
fn layer_results_are_bounded_and_truthful() {
    assert!(LAYER_RUNNER.contains("reports_failed"));
    assert!(LAYER_RUNNER.contains("collection_errors"));
    assert!(LAYER_RUNNER.contains("2500000"));
    assert!(LAYER_RUNNER.contains("invalid JSON"));
    assert!(LAYER_RUNNER.contains("$LASTEXITCODE"));
    assert!(
        LAYER_RUNNER.contains("[Text.UTF8Encoding]::new($false)")
            || LAYER_RUNNER.contains("[System.Text.UTF8Encoding]::new($false)")
    );
}

#[test]
fn results_mode_reports_required_user_information() {
    for field in [
        "overall_status",
        "confirmed_threats",
        "important_findings",
        "collection_gaps",
        "recommended_actions",
        "result_path",
        "result_size_bytes",
    ] {
        assert!(
            LAYER_RUNNER.contains(field),
            "Results mode is missing field {field}"
        );
    }
}

#[test]
fn missing_status_is_normalized_from_success_and_errors() {
    assert!(LAYER_RUNNER.contains("if ($Status -eq \"unknown\")"));
    assert!(LAYER_RUNNER.contains("$Success -eq $true -and $Errors.Count -eq 0"));
    assert!(LAYER_RUNNER.contains("$Status = \"complete\""));
}

#[test]
fn results_separate_context_from_important_findings() {
    assert!(LAYER_RUNNER.contains("$ImportantFindings"));
    assert!(LAYER_RUNNER.contains("\"context\""));
    assert!(LAYER_RUNNER.contains("contextual_observations"));
    assert!(LAYER_RUNNER.contains("important_findings = $ImportantFindings.Count"));
}

#[test]
fn package_contains_layer_runner() {
    assert!(BUILD.contains("$ROOT/scripts/Run-AXIOS-Layer.ps1"));
}
