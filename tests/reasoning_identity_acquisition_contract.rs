const MEMORY: &str = include_str!("../src/bin/axios-memory-execution-review.rs");
const NETWORK: &str = include_str!("../src/bin/axios-network-identity-review.rs");
const CORRELATION: &str = include_str!("../src/bin/axios-audit-correlate.rs");
const SCORE: &str = include_str!("../src/bin/axios-correlation-score.rs");

#[test]
fn memory_and_network_propagate_process_identity_without_invention() {
    for source in [MEMORY, NETWORK] {
        assert!(source.contains("\"start_time\": start_time"));
        assert!(source.contains("\"sha256\": sha256.map(str::to_ascii_lowercase)"));
        assert!(source.contains("\"identity_quality\": quality"));
        assert!(source.contains("\"partial\""));
    }

    assert!(NETWORK.contains("\"identity_quality\": \"unresolved\""));
}

#[test]
fn file_hash_reaches_correlation_scoring() {
    assert!(CORRELATION.contains("sha256: Option<String>"));
    assert!(SCORE.contains("finding.get(\"sha256\")"));
}

#[test]
fn identity_enrichment_does_not_claim_malware_or_intrusion() {
    for source in [MEMORY, NETWORK, CORRELATION, SCORE] {
        assert!(!source.contains("\"malware_confirmed\": true"));
        assert!(!source.contains("\"intrusion_confirmed\": true"));
    }
}
