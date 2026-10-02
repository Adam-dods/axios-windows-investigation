use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "axios-kernel-review")]
struct Options {
    #[arg(long)]
    kernel_posture: PathBuf,
    #[arg(long)]
    hardware_trust: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let posture = read_json(&options.kernel_posture, "kernel posture")?;
    let hardware = options
        .hardware_trust
        .as_ref()
        .map(|path| read_json(path, "hardware trust"))
        .transpose()?;

    println!(
        "{}",
        serde_json::to_string_pretty(&build_report(&posture, hardware.as_ref()))?
    );
    Ok(())
}

fn read_json(path: &PathBuf, name: &str) -> Result<Value> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let json_input = raw.strip_prefix('\u{feff}').unwrap_or(&raw);

    let report: Value = serde_json::from_str(json_input)
        .with_context(|| format!("{name} input is not valid JSON"))?;

    validate_success(&report, name)?;
    Ok(report)
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn build_report(posture: &Value, hardware: Option<&Value>) -> Value {
    let mut findings = Vec::new();
    let mut confirmed = 0u64;

    let secure_boot_enabled = hardware
        .and_then(|report| report.pointer("/secure_boot/enabled"))
        .and_then(Value::as_bool);

    if secure_boot_enabled == Some(false) {
        confirmed += 1;
        findings.push(json!({
            "id": "secure-boot-disabled",
            "classification": "confirmed_security_weakening",
            "confidence": "high",
            "title": "Secure Boot is disabled",
            "summary": "Hardware trust reports that Secure Boot is disabled. This reduces boot-chain protection and should be reviewed together with boot configuration, Code Integrity, and driver trust.",
            "evidence": {
                "hardware_trust.secure_boot.enabled": false
            }
        }));
    }

    let hardware_kernel_context = json!({
        "available": hardware.is_some(),
        "secure_boot_enabled": secure_boot_enabled,
        "device_guard": hardware
            .and_then(|report| report.get("device_guard"))
            .cloned()
            .unwrap_or(Value::Null)
    });

    let bcd = posture.get("bcd_security").and_then(Value::as_object);

    for (key, id, title, summary) in [
        (
            "test_signing",
            "test-signing-enabled",
            "Test-signing is enabled",
            "Windows test-signing mode permits test-signed kernel code.",
        ),
        (
            "no_integrity_checks",
            "integrity-checks-disabled",
            "Kernel integrity checks are disabled",
            "Windows boot configuration disables kernel integrity checking.",
        ),
        (
            "kernel_debugger",
            "kernel-debugger-enabled",
            "Kernel debugger is enabled",
            "Kernel debugging is enabled in the current boot configuration.",
        ),
        (
            "boot_debugger",
            "boot-debugger-enabled",
            "Boot debugger is enabled",
            "Boot debugging is enabled in the current boot configuration.",
        ),
    ] {
        if bcd
            .and_then(|values| values.get(key))
            .map(is_enabled)
            .unwrap_or(false)
        {
            confirmed += 1;
            findings.push(json!({
                "id": id,
                "classification": "confirmed_security_weakening",
                "confidence": "high",
                "title": title,
                "summary": summary,
                "evidence": {
                    "bcd_setting": key,
                    "value": bcd.and_then(|values| values.get(key)).cloned().unwrap_or(Value::Null)
                }
            }));
        }
    }

    let events = posture
        .get("code_integrity_events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut whql_disabled_events = Vec::new();
    let mut blocked_module_events = Vec::new();
    let mut other_review_events = Vec::new();
    let mut informational_events = 0u64;

    for event in &events {
        match classify_code_integrity_event(event) {
            EventClass::WhqlEnforcementDisabled => whql_disabled_events.push(event.clone()),
            EventClass::BlockedModule => blocked_module_events.push(event.clone()),
            EventClass::OtherReview => other_review_events.push(event.clone()),
            EventClass::Informational => informational_events += 1,
        }
    }

    if !whql_disabled_events.is_empty() {
        confirmed += 1;
        findings.push(json!({
            "id": "whql-driver-enforcement-disabled",
            "classification": "confirmed_security_weakening",
            "confidence": "high",
            "title": "WHQL driver enforcement is disabled for this boot session",
            "summary": "Code Integrity recorded that WHQL driver signing requirements are not enforced for the current boot session. This weakens driver trust enforcement and should be investigated together with Secure Boot and boot policy.",
            "evidence": {
                "event_count": whql_disabled_events.len(),
                "events": whql_disabled_events
            }
        }));
    }

    if !blocked_module_events.is_empty() {
        findings.push(json!({
            "id": "code-integrity-module-load-blocked",
            "classification": "needs_review",
            "confidence": "high",
            "title": "Code Integrity blocked or rejected module loading",
            "summary": "A process attempted to load a module that did not meet the active signing-level requirements. Review the process, module path, file signature, and application update state before making a security conclusion.",
            "evidence": {
                "event_count": blocked_module_events.len(),
                "events": blocked_module_events
            }
        }));
    }

    if !other_review_events.is_empty() {
        findings.push(json!({
            "id": "code-integrity-review-events",
            "classification": "needs_review",
            "confidence": "medium",
            "title": "Other Code Integrity review events were recorded",
            "summary": "Windows recorded Code Integrity warnings or failures that require evidence review but do not independently establish malware.",
            "evidence": {
                "event_count": other_review_events.len(),
                "events": other_review_events
            }
        }));
    }

    let running_driver_count = posture
        .get("running_driver_count")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            posture
                .get("running_drivers")
                .and_then(Value::as_array)
                .map(|drivers| drivers.len() as u64)
                .unwrap_or(0)
        });

    let review_count = findings
        .iter()
        .filter(|finding| {
            finding.get("classification").and_then(Value::as_str) == Some("needs_review")
        })
        .count() as u64;

    json!({
        "schema_version": 3,
        "collector": "axios_kernel_review",
        "success": true,
        "summary": {
            "confirmed_security_weakenings": confirmed,
            "needs_review": review_count,
            "running_driver_count": running_driver_count,
            "code_integrity_events_collected": events.len(),
            "code_integrity_informational_events": informational_events,
            "whql_enforcement_disabled_events": whql_disabled_events.len(),
            "blocked_module_events": blocked_module_events.len(),
            "other_code_integrity_review_events": other_review_events.len()
        },
        "hardware_kernel_context": hardware_kernel_context,
        "findings": findings
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventClass {
    WhqlEnforcementDisabled,
    BlockedModule,
    OtherReview,
    Informational,
}

fn classify_code_integrity_event(event: &Value) -> EventClass {
    let event_id = event
        .get("Id")
        .or_else(|| event.get("id"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let level = event
        .get("LevelDisplayName")
        .or_else(|| event.get("level"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    let message = event
        .get("Message")
        .or_else(|| event.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if event_id == 3085 {
        return EventClass::WhqlEnforcementDisabled;
    }

    if [
        3033u64, 3034, 3035, 3036, 3063, 3077, 3078, 3079, 3081, 3086,
    ]
    .contains(&event_id)
    {
        return EventClass::BlockedModule;
    }

    if level.contains("error")
        || level.contains("erreur")
        || level.contains("warning")
        || level.contains("avertissement")
        || [
            "blocked",
            "denied",
            "failed",
            "failure",
            "not trusted",
            "revoked",
            "unsigned",
            "invalid signature",
            "integrity violation",
            "could not verify",
            "cannot verify",
        ]
        .iter()
        .any(|signal| message.contains(signal))
    {
        EventClass::OtherReview
    } else {
        EventClass::Informational
    }
}

fn is_enabled(value: &Value) -> bool {
    match value {
        Value::Bool(enabled) => *enabled,
        Value::Number(number) => number.as_u64().unwrap_or(0) != 0,
        Value::String(text) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "enabled"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> Value {
        json!({
            "bcd_security": {
                "test_signing": false,
                "no_integrity_checks": false,
                "kernel_debugger": false,
                "boot_debugger": false
            },
            "running_driver_count": 190,
            "code_integrity_events": []
        })
    }

    #[test]
    fn failed_kernel_or_hardware_input_is_rejected() {
        assert!(validate_success(&json!({"success": false}), "kernel posture").is_err());
        assert!(validate_success(&json!({}), "hardware trust").is_err());
        assert!(validate_success(&json!({"success": true}), "kernel posture").is_ok());
    }

    #[test]
    fn secure_boot_disabled_is_a_confirmed_kernel_weakening() {
        let hardware = json!({
            "secure_boot": { "enabled": false },
            "device_guard": {
                "VirtualizationBasedSecurityStatus": 2,
                "SecurityServicesRunning": [2]
            }
        });

        let report = build_report(&baseline(), Some(&hardware));

        assert_eq!(report["summary"]["confirmed_security_weakenings"], 1);
        assert_eq!(report["findings"][0]["id"], "secure-boot-disabled");
        assert_eq!(
            report["hardware_kernel_context"]["secure_boot_enabled"],
            false
        );
    }

    #[test]
    fn clean_posture_has_no_findings() {
        let report = build_report(&baseline(), None);
        assert_eq!(report["summary"]["confirmed_security_weakenings"], 0);
        assert_eq!(report["summary"]["needs_review"], 0);
    }

    #[test]
    fn test_signing_is_a_confirmed_weakening() {
        let mut posture = baseline();
        posture["bcd_security"]["test_signing"] = json!(true);

        let report = build_report(&posture, None);
        assert_eq!(report["summary"]["confirmed_security_weakenings"], 1);
        assert_eq!(report["findings"][0]["id"], "test-signing-enabled");
    }

    #[test]
    fn policy_activation_is_informational() {
        let mut posture = baseline();
        posture["code_integrity_events"] = json!([{
            "Id": 3099,
            "LevelDisplayName": "Information",
            "Message": "Refreshed and activated Code Integrity policy. Status 0x0"
        }]);

        let report = build_report(&posture, None);
        assert_eq!(report["summary"]["needs_review"], 0);
        assert_eq!(report["summary"]["code_integrity_informational_events"], 1);
    }

    #[test]
    fn whql_disabled_is_a_confirmed_weakening() {
        let mut posture = baseline();
        posture["code_integrity_events"] = json!([{
            "Id": 3085,
            "LevelDisplayName": "Information",
            "Message": "Code Integrity will disable WHQL driver enforcement for this boot session."
        }]);

        let report = build_report(&posture, None);
        assert_eq!(report["summary"]["confirmed_security_weakenings"], 1);
        assert_eq!(
            report["findings"][0]["id"],
            "whql-driver-enforcement-disabled"
        );
    }

    #[test]
    fn blocked_module_requires_review() {
        let mut posture = baseline();
        posture["code_integrity_events"] = json!([{
            "Id": 3033,
            "LevelDisplayName": "Erreur",
            "Message": "A process attempted to load a module that did not meet signing requirements."
        }]);

        let report = build_report(&posture, None);
        assert_eq!(report["summary"]["needs_review"], 1);
        assert_eq!(
            report["findings"][0]["id"],
            "code-integrity-module-load-blocked"
        );
    }
}
