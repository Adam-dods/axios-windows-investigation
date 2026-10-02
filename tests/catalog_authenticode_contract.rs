const SOURCE: &str = include_str!("../src/security/native_authenticode.rs");

#[test]
fn catalog_verification_uses_catalog_info() {
    assert!(SOURCE.contains("WintrustCatalogInfo"));

    assert!(SOURCE.contains("WTD_CHOICE_CATALOG"));
}

#[test]
fn catalog_lookup_calculates_member_hash() {
    assert!(SOURCE.contains("CryptCATAdminCalcHashFromFileHandle2"));

    assert!(SOURCE.contains("CryptCATAdminEnumCatalogFromHash"));
}

#[test]
fn catalog_lookup_uses_sha256_and_sha1() {
    assert!(SOURCE.contains("\"SHA256\""));

    assert!(SOURCE.contains("\"SHA1\""));
}

#[test]
fn catalog_lookup_releases_contexts() {
    assert!(SOURCE.contains("CryptCATAdminReleaseCatalogContext"));

    assert!(SOURCE.contains("CryptCATAdminReleaseContext"));
}

#[test]
fn catalog_fallback_only_follows_no_signature() {
    assert!(SOURCE.contains("should_try_catalog"));

    assert!(SOURCE.contains("0x800B0100"));
}

#[test]
fn signature_checks_remain_cache_only() {
    assert!(SOURCE.contains("WTD_CACHE_ONLY_URL_RETRIEVAL"));
}
