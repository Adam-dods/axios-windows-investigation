const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const COMMANDS: &str = include_str!("../installer/windows/AXIOS-COMMANDS.txt");

#[test]
fn launcher_exposes_seven_main_help_and_three_hidden_developer_modes() {
    for mode in [
        "User",
        "Administrator",
        "Network",
        "System",
        "Persistence",
        "Software",
        "Results",
        "Help",
        "DeveloperExposure",
        "DeveloperCredential",
        "DeveloperArchive",
    ] {
        assert!(
            LAUNCHER.contains(&format!("\"{mode}\"")),
            "missing mode: {mode}"
        );
    }

    for obsolete in ["\"Complete\",", "\"Quick\",", "\"Context\","] {
        assert!(!LAUNCHER.contains(obsolete), "{obsolete}");
    }
}

#[test]
fn quick_and_context_are_system_branches() {
    assert!(LAUNCHER.contains("[string]$SystemFocus"));
    assert!(LAUNCHER.contains("\"quick\""));
    assert!(LAUNCHER.contains("\"context\""));
    assert!(LAUNCHER.contains("-Layer $SystemLayer"));
}

#[test]
fn public_help_does_not_expose_developer_commands() {
    let help_start = LAUNCHER.find("function Show-AxiosHelp").unwrap();
    let help_end = LAUNCHER[help_start..]
        .find("$Administrator = Test-AxiosAdministrator")
        .unwrap();
    let help = &LAUNCHER[help_start..help_start + help_end];

    for hidden in [
        "DeveloperExposure",
        "DeveloperCredential",
        "DeveloperArchive",
        "DeveloperExposureView",
        "DeveloperCredentialView",
        "DecryptCredentialFile",
    ] {
        assert!(!help.contains(hidden), "{hidden}");
    }
}

#[test]
fn hidden_developer_commands_route_to_isolated_tools() {
    assert!(LAUNCHER.contains("\"DeveloperExposure\" {"));
    assert!(LAUNCHER.contains("\"DeveloperCredential\" {"));
    assert!(LAUNCHER.contains("\"DeveloperArchive\" {"));
    assert!(LAUNCHER.contains("Invoke-AxiosDeveloperCredentialTool -Decrypt"));
}

#[test]
fn shipped_reference_contains_only_public_interface() {
    for command in [
        "1. USER",
        "2. ADMINISTRATOR",
        "3. NETWORK",
        "4. SYSTEM",
        "5. PERSISTENCE",
        "6. SOFTWARE",
        "7. RESULTS",
        "8. HELP",
    ] {
        assert!(COMMANDS.contains(command), "{command}");
    }

    assert!(!COMMANDS.contains("DEVELOPER"));
    assert!(!COMMANDS.contains("-Mode Quick"));
    assert!(!COMMANDS.contains("-Mode Context"));
    assert!(!COMMANDS.contains("-Mode Complete"));
}
