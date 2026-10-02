use anyhow::{bail, Result};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-kernel-runtime-integrity")]
struct Options {
    #[arg(long)]
    hardware: PathBuf,
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    drivers: PathBuf,
    #[arg(long)]
    boot: PathBuf,
    #[arg(long)]
    code_integrity: PathBuf,
    #[arg(long, default_value_t = 100)]
    max_findings: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_findings == 0 || options.max_findings > 500 {
        bail!("max-findings must be between 1 and 500");
    }

    let hardware = read_success(&options.hardware, "hardware")?;
    let kernel = read_success(&options.kernel, "kernel")?;
    let drivers = read_success(&options.drivers, "drivers")?;
    let boot = read_success(&options.boot, "boot")?;
    let code_integrity = read_success(&options.code_integrity, "code integrity")?;

    let report = build_report(
        &hardware,
        &kernel,
        &drivers,
        &boot,
        &code_integrity,
        options.max_findings,
    );

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn read_success(path: &PathBuf, label: &str) -> Result<Value> {
    let value = json_file::read_value(path)?;

    if value.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{label} report is not successful");
    }

    Ok(value)
}

fn build_report(
    hardware: &Value,
    kernel: &Value,
    drivers: &Value,
    boot: &Value,
    code_integrity: &Value,
    max_findings: usize,
) -> Value {
    let secure_boot_disabled = hardware
        .pointer("/secure_boot/enabled")
        .and_then(Value::as_bool)
        == Some(false);

    let kernel_findings = findings(kernel);
    let boot_findings = findings(boot);
    let driver_review_items = review_items(drivers);
    let code_integrity_findings = findings(code_integrity);

    let driver_signal = !driver_review_items.is_empty();
    let kernel_signal = !kernel_findings.is_empty();
    let boot_signal = !boot_findings.is_empty();
    let code_integrity_signal = !code_integrity_findings.is_empty();

    let mut artifacts = Vec::new();

    if secure_boot_disabled {
        artifacts.push(json!({
            "priority": "high",
            "classification": "confirmed_security_weakening",
            "id": "secure_boot_disabled",
            "title": "Secure Boot is disabled",
            "evidence": {
                "hardware_trust.secure_boot.enabled": false,
                "kernel_findings_present": kernel_signal,
                "boot_findings_present": boot_signal,
                "driver_review_items_present": driver_signal,
                "code_integrity_findings_present": code_integrity_signal
            },
            "reason": "boot_chain_protection_reduced; this is not proof of a firmware backdoor"
        }));
    }

    if driver_signal && (kernel_signal || code_integrity_signal) {
        artifacts.push(json!({
            "priority": "medium",
            "classification": "cross_layer_cooccurrence_requires_review",
            "id": "driver_kernel_code_integrity_cooccurrence",
            "title": "Driver review items coexist with kernel or Code Integrity findings",
            "evidence": {
                "driver_review_item_count": driver_review_items.len(),
                "kernel_finding_count": kernel_findings.len(),
                "code_integrity_finding_count": code_integrity_findings.len(),
                "shared_artifact_identity_confirmed": false
            },
            "reason": "cooccurrence_only; shared_artifact_identity_not_confirmed; requires_manual_driver_provenance_review"
        }));
    }

    if boot_signal && code_integrity_signal {
        artifacts.push(json!({
            "priority": "medium",
            "classification": "cross_layer_cooccurrence_requires_review",
            "id": "boot_code_integrity_cooccurrence",
            "title": "Boot-chain and Code Integrity findings both require review",
            "evidence": {
                "boot_finding_count": boot_findings.len(),
                "code_integrity_finding_count": code_integrity_findings.len(),
                "secure_boot_disabled": secure_boot_disabled,
                "shared_artifact_identity_confirmed": false
            },
            "reason": "cooccurrence_only; shared_artifact_identity_not_confirmed; review_evidence_together"
        }));
    }

    let rootkit_hypothesis =
        driver_signal && kernel_signal && code_integrity_signal && secure_boot_disabled;

    if rootkit_hypothesis {
        artifacts.push(json!({
            "priority": "medium",
            "classification": "hypothesis_requires_external_verification",
            "id": "kernel_integrity_hypothesis",
            "title": "Cross-layer kernel integrity hypothesis",
            "evidence": {
                "secure_boot_disabled": secure_boot_disabled,
                "driver_review_items": driver_review_items.len(),
                "kernel_findings": kernel_findings.len(),
                "code_integrity_findings": code_integrity_findings.len(),
                "shared_artifact_identity_confirmed": false
            },
            "reason": "cross_layer_cooccurrence_only; evidence_is_insufficient_to_confirm_rootkit_or_firmware_backdoor_from_windows_alone"
        }));
    }

    artifacts.truncate(max_findings);

    let high = artifacts
        .iter()
        .filter(|item| item.get("priority").and_then(Value::as_str) == Some("high"))
        .count();

    let medium = artifacts
        .iter()
        .filter(|item| item.get("priority").and_then(Value::as_str) == Some("medium"))
        .count();

    json!({
        "success": true,
        "collector": "axios_kernel_runtime_integrity",
        "read_only": true,
        "rootkit_confirmed": false,
        "firmware_backdoor_confirmed": false,
        "zero_day_confirmed": false,
        "policy": {
            "driver_signal_alone": "not_a_rootkit_verdict",
            "kernel_signal_alone": "not_a_rootkit_verdict",
            "firmware_claim_from_windows_only": "not_confirmable",
            "cross_layer_hypothesis": "requires_external_verification"
        },
        "summary": {
            "secure_boot_disabled": secure_boot_disabled,
            "kernel_finding_count": kernel_findings.len(),
            "boot_finding_count": boot_findings.len(),
            "driver_review_item_count": driver_review_items.len(),
            "code_integrity_finding_count": code_integrity_findings.len(),
            "high_priority_findings": high,
            "medium_priority_findings": medium,
            "reported_findings": artifacts.len()
        },
        "artifacts": artifacts
    })
}

fn findings(report: &Value) -> Vec<Value> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn review_items(report: &Value) -> Vec<Value> {
    report
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    matches!(
                        item.get("classification").and_then(Value::as_str),
                        Some("needs_review") | Some("unknown")
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_boot_is_reported_as_a_weakening_not_a_backdoor() {
        let report = build_report(
            &json!({"secure_boot": {"enabled": false}}),
            &json!({"findings": []}),
            &json!({"artifacts": []}),
            &json!({"findings": []}),
            &json!({"findings": []}),
            100,
        );

        assert_eq!(report["summary"]["secure_boot_disabled"], true);
        assert_eq!(report["rootkit_confirmed"], false);
        assert_eq!(report["firmware_backdoor_confirmed"], false);
        assert_eq!(report["artifacts"][0]["id"], "secure_boot_disabled");
    }

    #[test]
    fn cross_layer_cooccurrence_is_not_claimed_as_artifact_correlation() {
        let report = build_report(
            &json!({"secure_boot": {"enabled": true}}),
            &json!({"findings": [{"id": "unrelated-kernel-item"}]}),
            &json!({"artifacts": [{"classification": "needs_review"}]}),
            &json!({"findings": [{"id": "unrelated-boot-item"}]}),
            &json!({"findings": [{"id": "unrelated-code-integrity-item"}]}),
            100,
        );

        let artifacts = report["artifacts"]
            .as_array()
            .expect("artifacts must be an array");

        assert!(artifacts.iter().any(|item| {
            item["id"] == "driver_kernel_code_integrity_cooccurrence"
                && item["evidence"]["shared_artifact_identity_confirmed"] == false
        }));

        assert!(artifacts.iter().any(|item| {
            item["id"] == "boot_code_integrity_cooccurrence"
                && item["evidence"]["shared_artifact_identity_confirmed"] == false
        }));

        assert!(!artifacts.iter().any(|item| {
            item["id"]
                .as_str()
                .is_some_and(|id| id.ends_with("_correlation"))
        }));
    }

    #[test]
    fn rootkit_hypothesis_never_becomes_confirmation() {
        let report = build_report(
            &json!({"secure_boot": {"enabled": false}}),
            &json!({"findings": [{"id": "kernel"}]}),
            &json!({"artifacts": [{"classification": "needs_review"}]}),
            &json!({"findings": []}),
            &json!({"findings": [{"id": "ci"}]}),
            100,
        );

        assert_eq!(report["rootkit_confirmed"], false);
        assert!(report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "kernel_integrity_hypothesis"));
    }
}
