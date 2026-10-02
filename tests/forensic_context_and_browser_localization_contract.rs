const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

const BROWSER: &str = include_str!("../src/system/browser_extensions.rs");

#[test]
fn forensic_observations_are_deduplicated_before_counting() {
    assert!(LAYER.contains("$UniqueForensicObservations"));
    assert!(LAYER.contains("contextual_observations = $ForensicObservations.Count"));

    assert_eq!(LAYER.matches("$ForensicObservations = @(").count(), 1);
}

#[test]
fn forensic_titles_reject_generic_context_labels() {
    assert!(LAYER.contains("$GenericObservationTitles"));
    assert!(LAYER.contains("\"reason\","));
    assert!(LAYER.contains("\"Artifact correlation context\""));

    let reason = LAYER.find("\"reason\",").unwrap();
    let identifier = LAYER[reason..].find("\"id\",").unwrap();

    assert!(
        identifier > 0,
        "reason should be considered before generic identifiers"
    );
}

#[test]
fn chromium_localized_manifest_names_are_resolved() {
    for required in [
        "function Resolve-AxiosManifestMessage",
        "default_locale",
        r"_locales\{{0}}\messages.json",
        "$Messages.PSObject.Properties",
        "$ResolvedName",
        "$ResolvedDescription",
    ] {
        assert!(
            BROWSER.contains(required),
            "browser localization is missing {required}"
        );
    }

    assert!(BROWSER.contains("name = [string]$ResolvedName"));
    assert!(BROWSER.contains("description = [string]$ResolvedDescription"));
}

#[test]
fn unresolved_tokens_are_preserved_truthfully() {
    assert!(BROWSER.contains("return $Value"));
    assert!(!LAYER.contains("Unresolved localized name"));
}

#[test]
fn forensic_context_uses_semantic_deduplication() {
    assert!(LAYER.contains("$ObservationSemanticTitle"));
    assert!(LAYER.contains("\"object:{0}|{1}|{2}\""));
    assert!(LAYER.contains("Artifact activity correlated across "));
    assert!(LAYER.contains("audit and runtime evidence"));
}
