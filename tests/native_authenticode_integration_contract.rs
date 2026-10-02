const AUDIT_SOURCE: &str = include_str!("../src/system/universal_file_audit.rs");

const NATIVE_SOURCE: &str = include_str!("../src/security/native_authenticode.rs");

#[test]
fn universal_audit_does_not_start_powershell() {
    assert!(!AUDIT_SOURCE.contains("Command::new(\"powershell.exe\")"));

    assert!(!AUDIT_SOURCE.contains("Get-AuthenticodeSignature"));
}

#[test]
fn universal_audit_calls_native_authenticode() {
    assert!(AUDIT_SOURCE.contains("verify_file(&path)"));

    assert!(AUDIT_SOURCE.contains("AuthenticodeVerification"));
}

#[test]
fn universal_audit_reports_signature_engine() {
    assert!(AUDIT_SOURCE.contains("\"signature_engine\": \"winverifytrust\""));
}

#[test]
fn native_engine_uses_winverifytrust() {
    assert!(NATIVE_SOURCE.contains("WinVerifyTrust"));

    assert!(NATIVE_SOURCE.contains("WTD_CACHE_ONLY_URL_RETRIEVAL"));
}

#[test]
fn signature_checks_remain_bounded() {
    assert!(AUDIT_SOURCE.contains("SIGNATURE_CHECK_BUDGET"));

    assert!(AUDIT_SOURCE.contains("signature_checks < signature_budget"));
    assert!(AUDIT_SOURCE.contains("FAST_DEEP_VERIFICATION_BUDGET"));
}

#[test]
fn old_enrichment_envelope_is_removed() {
    assert!(!AUDIT_SOURCE.contains("EnrichmentEnvelope"));
}
