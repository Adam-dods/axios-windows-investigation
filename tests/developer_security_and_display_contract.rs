const CREDENTIAL: &str = include_str!("../src/bin/axios-developer-credential-view.rs");
const EXPOSURE: &str = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

#[test]
fn developer_archive_secret_input_is_masked_and_validated() {
    assert!(CREDENTIAL.contains("ENABLE_ECHO_INPUT"));
    assert!(CREDENTIAL.contains("read_secret_line"));
    assert!(CREDENTIAL.contains("MINIMUM_ARCHIVE_PASSWORD_BYTES"));
    assert!(CREDENTIAL.contains("Confirm file encryption password"));
    assert!(!CREDENTIAL.contains("let mut file_password_text = read_line()"));
    assert!(!CREDENTIAL.contains("let mut password_text = read_line()"));
}

#[test]
fn console_mode_is_restored_after_secret_input() {
    assert!(CREDENTIAL.contains("set_console_mode(input, protected_mode)"));
    assert!(CREDENTIAL.contains("set_console_mode(input, original_mode)"));
    assert!(CREDENTIAL.contains("cannot restore console input mode"));
}

#[test]
fn developer_archive_uses_dynamic_headings_and_structured_output() {
    assert!(CREDENTIAL.contains("fn print_heading"));
    assert!(CREDENTIAL.contains("\"=\".repeat(title.chars().count())"));
    assert!(CREDENTIAL.contains("serde_json::from_slice(&plaintext)"));
    assert!(!CREDENTIAL.contains("println!(\"{display}\")"));
}

#[test]
fn developer_exposure_does_not_duplicate_partial_status() {
    assert!(EXPOSURE.contains("$ReportErrors.Count -eq 0"));
    assert!(EXPOSURE.contains("Collectors returned"));
    assert!(!EXPOSURE.contains("Collectors completed"));
}

#[test]
fn results_sort_priority_and_normalize_verification() {
    assert!(LAYER.contains("$PriorityRank"));
    assert!(LAYER.contains("Sort-Object Domain, PriorityRank"));
    assert!(LAYER.contains("$VerificationState.ToLowerInvariant()"));
}

#[test]
fn focused_views_hide_irrelevant_packet_capture_noise() {
    assert!(NETWORK.contains("$_.name -ne \"raw_packet_capture\""));
    assert!(NETWORK.contains("$Focus -eq \"full\""));
    assert!(NETWORK.contains("Not requested by view"));
}
