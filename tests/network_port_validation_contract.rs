const SOURCE: &str = include_str!("../src/bin/axios-network-deep-review.rs");

#[test]
fn targeted_network_ports_reject_zero() {
    assert!(SOURCE.contains("value_parser = clap::value_parser!(u16).range(1..)"));
}
