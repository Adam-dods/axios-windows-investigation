use anyhow::{bail, Result};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-firmware-identity-review")]
struct Options {
    #[arg(long)]
    hardware: PathBuf,
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    let hardware = read_success(&options.hardware, "hardware")?;
    let kernel = read_success(&options.kernel, "kernel")?;
    let report = build_report(&hardware, &kernel);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn read_success(path: &PathBuf, label: &str) -> Result<Value> {
    let report = json_file::read_value(path)?;

    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{label} report is not successful");
    }

    Ok(report)
}

fn build_report(hardware: &Value, kernel: &Value) -> Value {
    let secure_boot_disabled = hardware
        .pointer("/secure_boot/enabled")
        .and_then(Value::as_bool)
        == Some(false);

    let identity = json!({
        "bios": first_present(hardware, &["/bios", "/firmware", "/system_firmware"]),
        "baseboard": first_present(hardware, &["/baseboard", "/motherboard"]),
        "computer_system": first_present(hardware, &["/computer_system", "/system"]),
        "tpm": first_present(hardware, &["/tpm"]),
        "secure_boot": first_present(hardware, &["/secure_boot"]),
        "device_guard": first_present(hardware, &["/device_guard"]),
        "kernel_hardware_context": first_present(kernel, &["/hardware_kernel_context"])
    });

    let mut findings = Vec::new();

    if secure_boot_disabled {
        findings.push(json!({
            "priority": "high",
            "classification": "confirmed_security_weakening",
            "id": "secure_boot_disabled",
            "reason": "boot_chain_protection_reduced; not_proof_of_firmware_compromise"
        }));
    }

    json!({
        "success": true,
        "collector": "axios_firmware_identity_review",
        "read_only": true,
        "persistent_state_written": false,
        "database_used": false,
        "firmware_backdoor_confirmed": false,
        "zero_day_confirmed": false,
        "identity": identity,
        "summary": {
            "secure_boot_disabled": secure_boot_disabled,
            "findings": findings.len()
        },
        "policy": {
            "current_identity": "observation_only",
            "firmware_backdoor_from_windows_only": "not_confirmable",
            "future_baseline_comparison": "not_enabled"
        },
        "findings": findings
    })
}

fn first_present(value: &Value, pointers: &[&str]) -> Value {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).cloned())
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_boot_is_a_weakening_not_firmware_compromise() {
        let report = build_report(&json!({"secure_boot": {"enabled": false}}), &json!({}));

        assert_eq!(report["persistent_state_written"], false);
        assert_eq!(report["firmware_backdoor_confirmed"], false);
        assert_eq!(report["findings"][0]["id"], "secure_boot_disabled");
    }
}
