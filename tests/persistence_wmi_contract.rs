use std::fs;

const SOURCE_PATH: &str = "src/persistence/coverage.rs";

fn source() -> String {
    fs::read_to_string(SOURCE_PATH).expect("persistence coverage source should be readable")
}

#[test]
fn wmi_bindings_use_cim_instance_properties() {
    let source = source();

    assert!(source.contains("$binding.CimInstanceProperties['Filter']"));
    assert!(source.contains("$binding.CimInstanceProperties['Consumer']"));

    assert!(!source.contains("$_.Properties['Filter'].Value"));
    assert!(!source.contains("$_.Properties['Consumer'].Value"));
}

#[test]
fn malformed_wmi_bindings_are_explicit_collection_errors() {
    let source = source();

    assert!(source.contains("WMI binding is missing its Filter property."));
    assert!(source.contains("WMI binding is missing its Consumer property."));
    assert!(source.contains("WMI binding contains an empty Filter reference."));
    assert!(source.contains("WMI binding contains an empty Consumer reference."));
    assert!(source.contains("Invoke-AxiosCollection 'wmi_filter_bindings'"));
    assert!(source.contains("$collectionErrors"));
    assert!(source.contains("collection_status"));
    assert!(source.contains("collection_errors"));
}

#[test]
fn wmi_inventory_remains_bounded_and_truthful() {
    let source = source();

    assert!(source.contains("wmi_filter_bindings_truncated"));
    assert!(source.contains("wmi_filter_bindings_total"));
    assert!(source.contains("$maxWmiSubscriptions"));
    assert!(source.contains("$allBindings | Select-Object -First $maxWmiSubscriptions"));
}
