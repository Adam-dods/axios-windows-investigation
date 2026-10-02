const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const VIEWER: &str = include_str!("../src/bin/axios-developer-credential-view.rs");
const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");

#[test]
fn exact_one_line_developer_command_is_supported() {
    assert!(LAUNCHER.contains("[Alias(\"View\")]"));
    assert!(LAUNCHER.contains("[switch]$DeveloperCredentialView"));
    assert!(LAUNCHER.contains("-Mode Network -View wifi -DeveloperCredentialView"));
    assert!(LAUNCHER.contains("-DeveloperCredentialView requires"));
}

#[test]
fn private_view_is_isolated_from_normal_collectors() {
    assert!(!COMPLETE.contains("axios-developer-credential-view"));
    assert!(!NETWORK.contains("axios-developer-credential-view"));
    assert!(!COMPLETE.contains("DeveloperCredentialView"));
    assert!(!NETWORK.contains("DeveloperCredentialView"));
}

#[test]
fn viewer_uses_authenticated_native_encryption_without_a_fixed_secret() {
    assert!(VIEWER.contains("BCryptEncrypt"));
    assert!(VIEWER.contains("ChainingModeGCM"));
    assert!(VIEWER.contains("PBKDF2_ITERATIONS"));
    assert!(VIEWER.contains("Plaintext file created : no"));
    assert!(!VIEWER.contains("const ENCRYPTION_PASSWORD"));
}

#[test]
fn release_package_contains_private_viewer() {
    assert!(BUILD.contains("axios-developer-credential-view"));
}

#[test]
fn encrypted_files_have_an_isolated_console_only_decrypt_branch() {
    assert!(LAUNCHER.contains("[switch]$DecryptCredentialFile"));
    assert!(LAUNCHER.contains("& $CredentialViewer --decrypt"));
    assert!(VIEWER.contains("BCryptDecrypt"));
    assert!(VIEWER.contains("Decryption status      : authenticated"));
    assert!(VIEWER.contains("Plaintext file created : no"));
    assert!(!COMPLETE.contains("DecryptCredentialFile"));
    assert!(!NETWORK.contains("DecryptCredentialFile"));
}
