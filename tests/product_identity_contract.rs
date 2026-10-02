const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README.md");
const BUILD: &str = include_str!("../scripts/build-windows-complete-investigation.sh");
const ENTRYPOINT: &str = include_str!("../installer/windows/axios.ps1");
const NETWORK_REVIEW: &str = include_str!("../src/bin/axios-network-deep-review.rs");

#[test]
fn product_uses_calendar_release_identity() {
    assert!(MANIFEST.contains("version = \"2026.9.27\""));
    assert!(!README.contains("AXIOS v1"));
    assert!(!README.contains("AXIOS v2"));
    assert!(README.contains("calendar releases"));
}

#[test]
fn public_package_and_entrypoint_are_stable_and_professional() {
    assert!(BUILD.contains("PACKAGE_NAME=\"axios-windows-investigation\""));
    assert!(BUILD.contains("$OUTPUT_DIR/$PACKAGE_NAME.zip"));
    assert!(BUILD.contains("$ROOT/axios.ps1"));
    assert!(ENTRYPOINT.contains("scripts\\Run-AXIOS.ps1"));
    assert!(ENTRYPOINT.contains("[CmdletBinding()]"));
    assert!(ENTRYPOINT.contains("[string]$Mode = \"Help\""));
    assert!(ENTRYPOINT.contains("& $Launcher @PSBoundParameters"));
    assert!(!ENTRYPOINT.contains("@ForwardedArguments"));
}

#[test]
fn repository_metadata_is_complete() {
    assert!(MANIFEST
        .contains("repository = \"https://github.com/Adam-dods/axios-windows-investigation\""));
    assert!(MANIFEST.contains("license = \"Apache-2.0\""));
    assert!(MANIFEST.contains("readme = \"README.md\""));
}

#[test]
fn network_worker_queue_recovers_from_mutex_poisoning() {
    assert!(NETWORK_REVIEW.contains("Err(poisoned) => poisoned.into_inner()"));
    assert!(!NETWORK_REVIEW.contains("scan queue lock poisoned"));
}
