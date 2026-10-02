use std::fs;

#[test]
fn network_deep_review_has_privilege_and_focus_routing() {
    let source = fs::read_to_string("src/bin/axios-network-deep-review.rs")
        .expect("network deep source should be readable");

    assert!(source.contains("enum Profile"));
    assert!(source.contains("enum Focus"));
    assert!(source.contains("requested_profile"));
    assert!(source.contains("effective_profile"));
    assert!(source.contains("Test-AxiosFocus"));
    assert!(source.contains("administrator_required"));
    assert!(source.contains("raw_packet_capture"));
    assert!(!source.contains("SilentlyContinue"));
}

#[test]
fn network_active_checks_are_explicit_bounded_and_conservative() {
    let source = fs::read_to_string("src/bin/axios-network-deep-review.rs")
        .expect("network deep source should be readable");

    assert!(source.contains("const MAX_TARGETS: usize = 32"));
    assert!(source.contains("const MAX_PORTS: usize = 128"));
    assert!(source.contains("TcpStream::connect_timeout"));
    assert!(source.contains("targets require --focus connections, targeted, or full"));
    assert!(source.contains("CIDR, wildcard, and whitespace are rejected"));
    assert!(source.contains("\"vulnerability_confirmed\": false"));
    assert!(source.contains("\"service_version_confirmed\": false"));
    assert!(source.contains("\"packet_capture_performed\": false"));
}

#[test]
fn package_contains_network_deep_runner() {
    let runner = fs::read_to_string("installer/windows/Run-AXIOS-Network-Deep-Review.ps1")
        .expect("network runner should be readable");

    assert!(runner.contains("axios-network-deep-review.exe"));
    assert!(runner.contains("AXIOS-Network-Deep-Review-"));
    assert!(runner.contains("$Size -gt 2500000"));
    assert!(runner.contains("collection_status"));
}

#[test]
fn network_firewall_sorting_is_valid_powershell() {
    let source = std::fs::read_to_string("src/bin/axios-network-deep-review.rs")
        .expect("network deep source should be readable");

    assert!(!source.contains("Sort-Object Enabled -Descending, Direction, DisplayName"));

    assert!(
        source.contains("Sort-Object -Property @{ Expression = 'Enabled'; Descending = $true }")
    );
}

#[test]
fn standalone_runner_uses_real_network_summary_fields() {
    let runner = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

    assert!(runner.contains("-Names @(\"summary\", \"active_checks_completed\")"));
    assert!(runner.contains("-Names @(\"summary\", \"active_open_ports\")"));
    assert!(runner.contains("active_checks = [int]$ActiveChecks"));
    assert!(runner.contains("active_open_ports = [int]$ActiveOpenPorts"));

    assert!(!runner.contains("$Report.summary.active_checks_completed"));
    assert!(!runner.contains("$Report.summary.active_open_ports"));
}

#[test]
fn targeted_observations_render_the_actual_endpoint_without_an_empty_pid() {
    let runner = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

    assert!(runner.contains("-Name \"resolved_address\""));
    assert!(runner.contains("-Name \"target\""));
    assert!(runner.contains("-Name \"port\""));
    assert!(runner.contains("$ObservationLine = \"- {0}; endpoint={1}:{2}\""));
    assert!(runner.contains("$ObservationLine += \"; pid={0}\""));
    assert!(!runner.contains("\"- {0}; endpoint={1}:{2}; pid={3}\""));
}
