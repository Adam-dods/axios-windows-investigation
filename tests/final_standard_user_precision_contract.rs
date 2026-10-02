const EXTENDED: &str = include_str!("../src/persistence/extended.rs");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");
const COMPLETE: &str = include_str!("../installer/windows/Run-AXIOS-Complete-Investigation.ps1");
const TAMPER: &str = include_str!("../src/bin/axios-defender-tamper-review.rs");

#[test]
fn extended_persistence_preserves_partial_evidence_on_access_denied() {
    assert!(EXTENDED.contains("Get-AxiosPersistenceValue"));
    assert!(EXTENDED.contains("collection_errors = $collectionErrors"));
    assert!(EXTENDED.contains("collection_status = if"));
    assert!(EXTENDED.contains("-ErrorAction Stop"));
}

#[test]
fn results_count_unique_context_observations() {
    assert!(LAYER.contains("$SeparateContextObservations"));
    assert!(LAYER.contains("$ContextFindings"));
    assert!(LAYER.contains("$UniqueForensicObservations"));
    assert!(LAYER.contains("contextual_observations = $ForensicObservations.Count"));
    assert!(!LAYER.contains("$SeparateContextObservations.Count +"));
}
#[test]
fn focused_network_modes_have_professional_console_data() {
    for required in [
        "OBSERVED NETWORK DATA",
        "TCP connections",
        "DNS cache entries",
        "Firewall rules",
        "SECURITY-RELEVANT OBSERVATIONS",
        "VISIBILITY LIMITATIONS",
    ] {
        assert!(NETWORK.contains(required), "missing: {required}");
    }
}

#[test]
fn complete_results_have_titles_and_cross_report_secure_boot_deduplication() {
    assert!(COMPLETE.contains("consolidated|secure_boot_disabled"));
    assert!(COMPLETE.contains("$PortableTitle"));
    assert!(COMPLETE.contains(".Replace(\"_\", \" \")"));
}

#[test]
fn complete_defender_review_checks_tamper_protection() {
    assert!(TAMPER.contains("IsTamperProtected"));
    assert!(TAMPER.contains("Microsoft Defender tamper protection is disabled"));
}
