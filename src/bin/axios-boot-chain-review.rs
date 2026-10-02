use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "axios-boot-chain-review")]
struct Options {
    #[arg(long)]
    hardware_trust: PathBuf,

    #[arg(long)]
    kernel_posture: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();

    let hardware = read_json(&options.hardware_trust, "hardware trust")?;
    let kernel = read_json(&options.kernel_posture, "kernel posture")?;

    let mut findings = Vec::new();

    let secure_boot_enabled = boolean_at(&hardware, &["secure_boot", "enabled"]);
    let tpm_ready = boolean_at(&hardware, &["tpm", "TpmReady"]);
    let vbs_status = number_at(
        &hardware,
        &["device_guard", "VirtualizationBasedSecurityStatus"],
    );

    let system_drive_unprotected = hardware["bitlocker"].as_array().is_some_and(|volumes| {
        volumes.iter().any(|volume| {
            text_at(volume, &["MountPoint"]).eq_ignore_ascii_case("C:")
                && (number_at(volume, &["ProtectionStatus"]) == Some(0)
                    || number_at(volume, &["VolumeStatus"]) == Some(0))
        })
    });

    if secure_boot_enabled == Some(false) {
        findings.push(finding(
            "secure-boot-disabled",
            "confirmed_security_weakening",
            "high",
            "Secure Boot is disabled",
            "UEFI Secure Boot is disabled. This weakens protection of the boot chain before Windows starts.",
            json!({
                "secure_boot": value_at(&hardware, &["secure_boot"]),
                "boot_state": value_at(&hardware, &["boot_state"])
            }),
        ));
    }

    if system_drive_unprotected {
        findings.push(finding(
            "system-drive-bitlocker-off",
            "confirmed_security_weakening",
            "high",
            "System drive is not protected by BitLocker",
            "The Windows system drive reports BitLocker protection off, reducing protection against offline disk access.",
            json!({
                "system_drive": hardware["bitlocker"]
            }),
        ));
    }

    if tpm_ready != Some(true) {
        findings.push(finding(
            "tpm-not-ready",
            "needs_review",
            "high",
            "TPM readiness is unavailable",
            "AXIOS could not confirm that a ready TPM is available for the local boot trust chain.",
            json!({
                "tpm": value_at(&hardware, &["tpm"])
            }),
        ));
    }

    if vbs_status.is_some_and(|status| status == 0) {
        findings.push(finding(
            "vbs-not-running",
            "needs_review",
            "medium",
            "Virtualization-based security is not running",
            "Windows reports that virtualization-based security is not active.",
            json!({
                "device_guard": value_at(&hardware, &["device_guard"])
            }),
        ));
    }

    let test_signing = contains_true_key(&kernel, "testsigning");
    let no_integrity_checks = contains_true_key(&kernel, "nointegritychecks");
    let kernel_debugger =
        contains_true_key(&kernel, "debug") && contains_true_key(&kernel, "kernel");

    if test_signing || no_integrity_checks || kernel_debugger {
        findings.push(finding(
            "boot-configuration-integrity-weakening",
            "confirmed_security_weakening",
            "high",
            "Boot configuration weakens kernel integrity",
            "Boot configuration evidence indicates test signing, disabled integrity checks, or kernel debugging.",
            json!({
                "test_signing_detected": test_signing,
                "no_integrity_checks_detected": no_integrity_checks,
                "kernel_debugger_detected": kernel_debugger
            }),
        ));
    }

    let whql_disabled_events = count_event_id(&kernel, 3085).max(maximum_number_for_key(
        &kernel,
        "whql_enforcement_disabled_events",
    ));
    if whql_disabled_events > 0 {
        findings.push(finding(
            "whql-driver-enforcement-disabled",
            "confirmed_security_weakening",
            "high",
            "WHQL driver enforcement was disabled for one or more boots",
            "Windows Code Integrity recorded boot-session events that disable WHQL driver enforcement. This is a security weakening that requires remediation review.",
            json!({
                "event_id": 3085,
                "events_observed": whql_disabled_events
            }),
        ));
    }

    let blocked_module_events =
        count_event_id(&kernel, 3033).max(maximum_number_for_key(&kernel, "blocked_module_events"));
    if blocked_module_events > 0 {
        findings.push(finding(
            "code-integrity-blocked-module-events",
            "needs_review",
            "high",
            "Code Integrity blocked module loading",
            "Windows Code Integrity blocked one or more modules. This is evidence requiring investigation, not a malware verdict by itself.",
            json!({
                "event_id": 3033,
                "events_observed": blocked_module_events
            }),
        ));
    }

    if secure_boot_enabled == Some(false) && system_drive_unprotected {
        findings.push(finding(
            "boot-and-disk-trust-gap",
            "confirmed_security_weakening",
            "high",
            "Boot and disk trust protections are both weakened",
            "Secure Boot is disabled and the Windows system drive is not BitLocker-protected. This creates a combined boot and offline-access trust gap.",
            json!({
                "secure_boot_enabled": false,
                "system_drive_bitlocker_protected": false
            }),
        ));
    }

    if secure_boot_enabled == Some(false) && whql_disabled_events > 0 {
        findings.push(finding(
            "boot-chain-and-driver-policy-gap",
            "confirmed_security_weakening",
            "high",
            "Boot-chain and driver-policy protections are both weakened",
            "Secure Boot is disabled and Code Integrity recorded disabled WHQL driver enforcement. AXIOS observed weakening evidence from separate trust layers.",
            json!({
                "secure_boot_enabled": false,
                "whql_disabled_events": whql_disabled_events
            }),
        ));
    }

    let confirmed = findings
        .iter()
        .filter(|finding| finding["classification"] == "confirmed_security_weakening")
        .count();
    let review = findings
        .iter()
        .filter(|finding| finding["classification"] == "needs_review")
        .count();

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "collector": "axios_boot_chain_review",
            "success": true,
            "summary": {
                "confirmed_security_weakenings": confirmed,
                "needs_review": review,
                "secure_boot_enabled": secure_boot_enabled,
                "tpm_ready": tpm_ready,
                "vbs_status": vbs_status,
                "whql_enforcement_disabled_events": whql_disabled_events,
                "code_integrity_blocked_module_events": blocked_module_events
            },
            "findings": findings
        }))?
    );

    Ok(())
}

fn read_json(path: &PathBuf, name: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);

    let report: Value = serde_json::from_slice(bytes)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;

    validate_success(&report, name)?;
    Ok(report)
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn boolean_at(value: &Value, path: &[&str]) -> Option<bool> {
    match value_at(value, path) {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Number(value)) => value.as_i64().map(|number| number != 0),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => Some(true),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn number_at(value: &Value, path: &[&str]) -> Option<i64> {
    match value_at(value, path) {
        Some(Value::Number(value)) => value.as_i64(),
        Some(Value::String(value)) => value.trim().parse().ok(),
        _ => None,
    }
}

fn text_at(value: &Value, path: &[&str]) -> String {
    value_at(value, path)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn contains_true_key(value: &Value, key_fragment: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key.to_ascii_lowercase()
                .contains(&key_fragment.to_ascii_lowercase())
                && matches!(value, Value::Bool(true)))
                || contains_true_key(value, key_fragment)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_true_key(value, key_fragment)),
        _ => false,
    }
}

fn count_event_id(value: &Value, wanted: u64) -> u64 {
    match value {
        Value::Object(object) => {
            let direct = object.iter().any(|(key, value)| {
                let normalized = normalize_key(key);

                (normalized == "eventid" || normalized == "id")
                    && (value.as_u64() == Some(wanted)
                        || value.as_str() == Some(&wanted.to_string()))
            });

            u64::from(direct)
                + object
                    .values()
                    .map(|value| count_event_id(value, wanted))
                    .sum::<u64>()
        }
        Value::Array(values) => values
            .iter()
            .map(|value| count_event_id(value, wanted))
            .sum(),
        _ => 0,
    }
}

fn maximum_number_for_key(value: &Value, wanted_key: &str) -> u64 {
    match value {
        Value::Object(object) => {
            let direct = object
                .iter()
                .filter(|(key, _)| normalize_key(key) == normalize_key(wanted_key))
                .filter_map(|(_, value)| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
                })
                .max()
                .unwrap_or_default();

            direct.max(
                object
                    .values()
                    .map(|value| maximum_number_for_key(value, wanted_key))
                    .max()
                    .unwrap_or_default(),
            )
        }
        Value::Array(values) => values
            .iter()
            .map(|value| maximum_number_for_key(value, wanted_key))
            .max()
            .unwrap_or_default(),
        _ => 0,
    }
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
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

    fn hardware() -> Value {
        json!({
            "secure_boot": { "enabled": false },
            "tpm": { "TpmReady": true },
            "device_guard": { "VirtualizationBasedSecurityStatus": 2 },
            "bitlocker": [{
                "MountPoint": "C:",
                "ProtectionStatus": 0,
                "VolumeStatus": 0
            }]
        })
    }

    #[test]
    fn failed_boot_inputs_are_rejected() {
        assert!(validate_success(&json!({"success": false}), "kernel").is_err());
        assert!(validate_success(&json!({}), "hardware").is_err());
        assert!(validate_success(&json!({"success": true}), "kernel").is_ok());
    }

    #[test]
    fn boot_disk_gap_is_detected() {
        assert_eq!(
            boolean_at(&hardware(), &["secure_boot", "enabled"]),
            Some(false)
        );
        assert_eq!(number_at(&hardware(), &["bitlocker", "missing"]), None);
    }

    #[test]
    fn event_count_handles_nested_events() {
        let input = json!({
            "events": [
                { "event_id": 3085 },
                { "event_id": "3085" },
                { "event_id": 3033 }
            ]
        });

        assert_eq!(count_event_id(&input, 3085), 2);
        assert_eq!(count_event_id(&input, 3033), 1);
    }

    #[test]
    fn kernel_summary_metrics_are_used_when_raw_events_are_not_present() {
        let input = json!({
            "summary": {
                "whql_enforcement_disabled_events": 9,
                "blocked_module_events": 8
            }
        });

        assert_eq!(
            maximum_number_for_key(&input, "whql_enforcement_disabled_events"),
            9
        );
        assert_eq!(maximum_number_for_key(&input, "blocked_module_events"), 8);
    }

    #[test]
    fn true_key_search_is_recursive() {
        let input = json!({
            "boot": {
                "testsigning": true
            }
        });

        assert!(contains_true_key(&input, "testsigning"));
    }
}
