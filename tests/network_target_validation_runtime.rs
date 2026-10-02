use std::process::Command;

#[test]
fn unsafe_and_ambiguous_targets_are_rejected() {
    for target in [
        "127.0.0.1;calc.exe",
        "127.0.0.1 && whoami",
        "$(whoami)",
        "192.168.*.*",
        "192.168.1.0/24",
        "-example.com",
        "example-.com",
        "example..com",
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_axios-network-deep-review"))
            .args(["--focus", "targeted", "--target", target, "--ports", "443"])
            .status()
            .expect("network review should start");

        assert!(!status.success(), "unsafe target was accepted: {target}");
    }
}

#[test]
fn port_zero_is_rejected() {
    let status = Command::new(env!("CARGO_BIN_EXE_axios-network-deep-review"))
        .args([
            "--focus",
            "targeted",
            "--target",
            "127.0.0.1",
            "--ports",
            "0",
        ])
        .status()
        .expect("network review should start");

    assert!(!status.success());
}
