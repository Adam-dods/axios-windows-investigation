use serde_json::Value;
use std::collections::HashSet;
use std::process::Command;

#[test]
fn aliases_do_not_repeat_the_same_resolved_endpoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_axios-network-deep-review"))
        .args([
            "--focus",
            "targeted",
            "--target",
            "localhost",
            "--target",
            "::1",
            "--ports",
            "9",
            "--timeout-ms",
            "50",
        ])
        .output()
        .expect("network review should start");

    assert!(output.status.success());

    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");

    let results = report["active_target_results"]
        .as_array()
        .expect("active results should be an array");

    let endpoints: HashSet<_> = results
        .iter()
        .map(|item| {
            (
                item["resolved_address"].as_str().unwrap_or(""),
                item["port"].as_u64().unwrap_or(0),
            )
        })
        .collect();

    assert_eq!(results.len(), endpoints.len());
}
