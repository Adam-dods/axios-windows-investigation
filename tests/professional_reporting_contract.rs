const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const CREDENTIAL: &str = include_str!("../src/bin/axios-developer-credential-view.rs");

#[test]
fn shared_modes_use_professional_security_headings() {
    for heading in [
        "RAPID SECURITY ASSESSMENT",
        "SYSTEM CONTEXT ASSESSMENT",
        "INSTALLED SOFTWARE PROFILE",
        "UPDATE AND ENDPOINT PROTECTION",
        "PERSISTENCE SURFACE",
        "ASSESSMENT COVERAGE",
        "SYSTEM AND RUNTIME ACTIVITY",
        "SECURITY CONTROL STATE",
    ] {
        assert!(
            LAYER.contains(heading),
            "missing shared-mode heading: {heading}"
        );
    }
}

#[test]
fn every_network_view_uses_professional_headings() {
    for heading in [
        "NETWORK SECURITY ASSESSMENT",
        "NETWORK ADAPTER INVENTORY",
        "ADDRESSING AND DNS CONFIGURATION",
        "FIREWALL SECURITY PROFILE",
        "WIRELESS NETWORK PROFILE",
        "NETWORK VISIBILITY",
        "OBSERVED NETWORK DATA",
        "SECURITY-RELEVANT OBSERVATIONS",
        "VERIFIED NETWORK FINDINGS",
        "COLLECTION LIMITATIONS",
    ] {
        assert!(
            NETWORK.contains(heading),
            "missing network heading: {heading}"
        );
    }
}

#[test]
fn explicit_credential_commands_use_clear_professional_status() {
    assert!(CREDENTIAL.contains("PRIVATE NETWORK CREDENTIAL ACCESS"));
    assert!(CREDENTIAL.contains("ENCRYPTED CREDENTIAL ARCHIVE"));
    assert!(CREDENTIAL.contains("Decryption status      : authenticated"));
    assert!(CREDENTIAL.contains("Plaintext file created : no"));
}

#[test]
fn obsolete_product_prefixes_are_removed_from_human_titles() {
    for obsolete in [
        "AXIOS QUICK SCAN",
        "AXIOS SYSTEM CONTEXT",
        "AXIOS NETWORK REVIEW",
        "AXIOS PRIVATE NETWORK ACCESS",
        "AXIOS ENCRYPTED CREDENTIAL FILES",
    ] {
        assert!(!LAYER.contains(obsolete));
        assert!(!NETWORK.contains(obsolete));
        assert!(!CREDENTIAL.contains(obsolete));
    }
}

#[test]
fn primary_layer_titles_are_professional_and_product_prefix_free() {
    for title in [
        "SYSTEM SECURITY ASSESSMENT",
        "SOFTWARE SECURITY ASSESSMENT",
        "PERSISTENCE SECURITY ASSESSMENT",
    ] {
        assert!(LAYER.contains(title));
    }

    for obsolete in [
        "AXIOS SYSTEM REVIEW",
        "AXIOS SOFTWARE REVIEW",
        "AXIOS PERSISTENCE REVIEW",
    ] {
        assert!(!LAYER.contains(obsolete));
    }
}

#[test]
fn layer_section_underlines_follow_the_actual_title_length() {
    assert!(LAYER.contains("function Write-AxiosConsoleHeading"));
    assert!(LAYER.contains("Write-Host ($Underline * $Title.Length)"));
}
