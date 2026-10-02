const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const COMMANDS: &str = include_str!("../installer/windows/AXIOS-COMMANDS.txt");
const STANDARD_USER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");
const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");
const COMMAND_EXECUTION: &str = include_str!("../src/command.rs");

#[test]
fn launcher_exposes_the_eleven_supported_modes() {
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

    for removed in ["\"Complete\",", "\"Quick\",", "\"Context\","] {
        assert!(
            !LAUNCHER.contains(removed),
            "obsolete top-level mode remains: {removed}"
        );
    }
}

#[test]
fn privilege_boundaries_are_checked_before_execution() {
    let privilege_check = LAUNCHER
        .find("$Administrator = Test-AxiosAdministrator")
        .expect("privilege check should exist");

    let user_runner = LAUNCHER
        .find("Run-AXIOS-Standard-User-Audit.ps1")
        .expect("user runner should exist");

    let administrator_runner = LAUNCHER
        .find("Run-AXIOS-Complete-Investigation.ps1")
        .expect("administrator runner should exist");

    assert!(privilege_check < user_runner);
    assert!(privilege_check < administrator_runner);

    assert!(!LAUNCHER.contains("AXIOS User mode cannot run from elevated PowerShell."));

    assert!(LAUNCHER.contains("Administrator mode requires elevated PowerShell."));

    assert!(!LAUNCHER.contains("AXIOS Complete mode requires elevated PowerShell."));
}

#[test]
fn user_mode_is_available_in_standard_and_elevated_sessions() {
    assert!(LAUNCHER.contains("\"User\" {"));

    assert!(!LAUNCHER.contains("AXIOS User mode cannot run from elevated PowerShell."));

    assert!(!STANDARD_USER.contains("AXIOS User mode requires a standard-user PowerShell session."));

    assert!(STANDARD_USER.contains("$IsAdministrator = $CurrentPrincipal.IsInRole("));

    assert!(STANDARD_USER.contains("administrator"));

    assert!(STANDARD_USER.contains("[Console]::OutputEncoding = $AxiosUtf8"));
}

#[test]
fn targeted_network_checks_require_explicit_targets() {
    assert!(LAUNCHER.contains("$NetworkFocus -eq \"targeted\""));
    assert!(LAUNCHER.contains("$Target.Count -eq 0"));
    assert!(LAUNCHER.contains("AXIOS targeted network review requires at least"));
    assert!(LAUNCHER.contains("-Target is only accepted with"));
}

#[test]
fn command_reference_documents_only_the_public_interface() {
    for command in [
        "-Mode Help",
        "-Mode User",
        "-Mode Administrator",
        "-Mode Network",
        "-Mode System",
        "-Mode Persistence",
        "-Mode Software",
        "-Mode Results",
    ] {
        assert!(
            COMMANDS.contains(command),
            "command reference is missing {command}"
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
            "non-public command is documented: {hidden_or_removed}"
        );
    }
}

#[test]
fn package_contains_launcher_and_command_reference() {
    assert!(BUILD.contains("$ROOT/scripts/Run-AXIOS.ps1"));
    assert!(BUILD.contains("$ROOT/AXIOS-COMMANDS.txt"));
}

#[test]
fn embedded_powershell_uses_utf8_input_output_and_code_page() {
    assert!(COMMAND_EXECUTION.contains("[Console]::InputEncoding = $axiosUtf8"));
    assert!(COMMAND_EXECUTION.contains("[Console]::OutputEncoding = $axiosUtf8"));
    assert!(COMMAND_EXECUTION.contains("$OutputEncoding = $axiosUtf8"));
    assert!(COMMAND_EXECUTION.contains("chcp.com 65001"));
}

#[test]
fn administrator_is_the_only_full_investigation_command() {
    assert!(LAUNCHER.contains("Administrator is the primary full privileged investigation."));

    assert!(!LAUNCHER.contains("Complete remains a compatibility alias"));

    assert_eq!(
        LAUNCHER
            .matches("Run-AXIOS-Complete-Investigation.ps1")
            .count(),
        1,
        "only Administrator may route to the full investigation"
    );
}
