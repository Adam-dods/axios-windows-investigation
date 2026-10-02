use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "axios-trust-review")]
struct Cli {
    #[arg(long)]
    hardware_trust: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = read_json(&cli.hardware_trust)?;
    println!("{}", serde_json::to_string_pretty(&build_report(&report))?);
    Ok(())
}

fn read_json(path: &PathBuf) -> Result<Value> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Could not read hardware trust report: {}", path.display()))?;

    let report: Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).with_context(|| {
            format!(
                "Hardware trust report is not valid JSON: {}",
                path.display()
            )
        })?;

    validate_success(&report, "hardware trust")?;
    Ok(report)
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn build_report(hardware: &Value) -> Value {
    let mut findings = Vec::new();

    if hardware
        .pointer("/secure_boot/enabled")
        .and_then(Value::as_bool)
        == Some(false)
    {
        findings.push(finding(
            "secure-boot-disabled",
            "confirmed_security_weakening",
            "high",
            "Secure Boot is disabled",
            "UEFI Secure Boot is disabled, so the Windows boot chain has reduced protection against boot-level tampering.",
            json!({
                "secure_boot": hardware.get("secure_boot"),
                "boot_state": hardware.get("boot_state")
            }),
        ));
    }

    let tpm_ready = hardware.pointer("/tpm/TpmReady").and_then(Value::as_bool);

    if tpm_ready != Some(true) {
        findings.push(finding(
            "tpm-not-ready",
            "needs_review",
            "medium",
            "TPM is not ready",
            "TPM readiness could not be confirmed. Hardware-backed key protection and attestation should be reviewed.",
            json!({ "tpm": hardware.get("tpm") }),
        ));
    }

    let vbs_status = hardware
        .pointer("/device_guard/VirtualizationBasedSecurityStatus")
        .and_then(Value::as_i64);

    if vbs_status != Some(2) {
        findings.push(finding(
            "vbs-not-running",
            "needs_review",
            "medium",
            "Virtualization-based security is not confirmed as running",
            "AXIOS could not confirm that Windows virtualization-based security is running.",
            json!({ "device_guard": hardware.get("device_guard") }),
        ));
    }

    let c_drive = hardware
        .get("bitlocker")
        .and_then(Value::as_array)
        .and_then(|volumes| {
            volumes.iter().find(|volume| {
                volume
                    .get("MountPoint")
                    .and_then(Value::as_str)
                    .map(|mount| mount.eq_ignore_ascii_case("C:"))
                    == Some(true)
            })
        });

    if c_drive
        .and_then(|volume| volume.get("ProtectionStatus"))
        .and_then(Value::as_i64)
        == Some(0)
    {
        findings.push(finding(
            "system-drive-bitlocker-off",
            "confirmed_security_weakening",
            "high",
            "System drive is not protected by BitLocker",
            "The Windows system drive reports BitLocker protection off. Offline access to the drive is not protected by a BitLocker key protector.",
            json!({ "system_drive": c_drive }),
        ));
    }

    for disk in hardware
        .get("physical_disks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let status = disk
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if !status.eq_ignore_ascii_case("OK") {
            findings.push(finding(
                "physical-disk-health-review",
                "needs_review",
                "medium",
                "Physical disk health requires review",
                "A physical disk did not report an OK status.",
                json!({ "physical_disk": disk }),
            ));
        }
    }

    let summary = json!({
        "confirmed_security_weakenings": findings.iter()
            .filter(|finding| finding["classification"] == "confirmed_security_weakening")
            .count(),
        "needs_review": findings.iter()
            .filter(|finding| finding["classification"] == "needs_review")
            .count(),
        "informational": 0
    });

    json!({
        "schema_version": 1,
        "collector": "axios_trust_review",
        "success": hardware.get("success").and_then(Value::as_bool) == Some(true),
        "summary": summary,
        "findings": findings
    })
}

fn finding(
    id: &str,
    classification: &str,
    confidence: &str,
    title: &str,
    summary: &str,
    evidence: Value,
) -> Value {
    json!({
        "id": id,
        "classification": classification,
        "confidence": confidence,
        "title": title,
        "summary": summary,
        "evidence": evidence
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_hardware() -> Value {
        json!({
            "success": true,
            "secure_boot": { "enabled": true },
            "tpm": { "TpmReady": true },
            "device_guard": { "VirtualizationBasedSecurityStatus": 2 },
            "bitlocker": [{
                "MountPoint": "C:",
                "ProtectionStatus": 1
            }],
            "physical_disks": [{
                "Status": "OK"
            }]
        })
    }

    #[test]
    fn failed_hardware_report_is_rejected() {
        assert!(validate_success(&json!({"success": false}), "hardware").is_err());
        assert!(validate_success(&json!({}), "hardware").is_err());
        assert!(validate_success(&json!({"success": true}), "hardware").is_ok());
    }

    #[test]
    fn trusted_hardware_has_no_findings() {
        assert!(build_report(&baseline_hardware())["findings"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn disabled_secure_boot_is_a_confirmed_weakening() {
        let mut hardware = baseline_hardware();
        hardware["secure_boot"]["enabled"] = json!(false);

        assert_eq!(
            build_report(&hardware)["summary"]["confirmed_security_weakenings"],
            1
        );
    }

    #[test]
    fn unprotected_system_drive_is_a_confirmed_weakening() {
        let mut hardware = baseline_hardware();
        hardware["bitlocker"][0]["ProtectionStatus"] = json!(0);

        assert_eq!(
            build_report(&hardware)["summary"]["confirmed_security_weakenings"],
            1
        );
    }
}
