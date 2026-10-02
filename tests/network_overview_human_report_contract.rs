const CORE: &str = include_str!("../src/bin/axios-network-deep-review.rs");
const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

#[test]
fn ip_configuration_is_flattened_before_json_serialization() {
    for required in [
        "interface_alias =",
        "network_name =",
        "network_category =",
        "ipv4_addresses =",
        "ipv6_addresses =",
        "ipv4_gateways =",
        "ipv6_gateways =",
        "dns_servers =",
    ] {
        assert!(CORE.contains(required), "missing: {required}");
    }

    assert!(!CORE
        .contains("Select-Object InterfaceAlias, InterfaceIndex,\n                    NetProfile"));
}

#[test]
fn overview_console_reports_real_network_context() {
    for required in [
        "NETWORK ADAPTER INVENTORY",
        "Active adapters",
        "ADDRESSING AND DNS CONFIGURATION",
        "FIREWALL",
        "WIRELESS",
        "NETWORK VISIBILITY",
        "Capabilities collected",
        "Not requested by view",
    ] {
        assert!(RUNNER.contains(required), "missing: {required}");
    }
}
