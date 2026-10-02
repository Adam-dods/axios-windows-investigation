const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const USER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");
const ADMIN: &str = include_str!("../installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");

#[test]
fn every_public_execution_family_has_human_output() {
    for (source, heading) in [
        (LAYER, "RAPID SECURITY ASSESSMENT"),
        (LAYER, "SYSTEM CONTEXT ASSESSMENT"),
        (LAYER, "SECURITY ASSESSMENT SUMMARY"),
        (USER, "STANDARD USER SECURITY ASSESSMENT"),
        (ADMIN, "PRIVILEGED SECURITY ASSESSMENT"),
        (NETWORK, "NETWORK SECURITY ASSESSMENT"),
        (COMPLETE, "COMPREHENSIVE SECURITY INVESTIGATION"),
    ] {
        assert!(source.contains(heading), "missing heading {heading}");
    }
}

#[test]
fn reports_keep_json_and_add_detailed_text() {
    for source in [LAYER, USER, ADMIN, NETWORK, COMPLETE] {
        assert!(source.contains("ConvertTo-Json"));
        assert!(source.contains("Detailed TXT report"));
        assert!(source.contains("WriteAllText") || source.contains("Write-AxiosText"));
    }
}

#[test]
fn quick_reports_context_and_real_system_details() {
    for field in [
        "TIME, LANGUAGE AND NETWORK CONTEXT",
        "Processor",
        "Graphics",
        "Physical disk",
        "Logical disk",
        "Network profile",
        "Time synchronization",
    ] {
        assert!(LAYER.contains(field), "missing Quick field {field}");
    }
}
