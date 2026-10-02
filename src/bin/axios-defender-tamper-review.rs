use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf};

struct Options {
    defender: PathBuf,
    max_findings: usize,
    event_cap: usize,
}

fn main() -> Result<()> {
    let options = options()?;
    let defender = read_json(&options.defender)?;
    validate_defender_evidence(&defender)?;
    let report = build_report(&defender, options.max_findings, options.event_cap);

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn options() -> Result<Options> {
    let mut defender = None;
    let mut max_findings = 100usize;
    let mut event_cap = 500usize;
    let mut args = env::args().skip(1);

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--defender" => {
                defender = Some(PathBuf::from(
                    args.next().context("--defender needs a path")?,
                ))
            }
            "--max-findings" => {
                max_findings = args
                    .next()
                    .context("--max-findings needs a number")?
                    .parse()
                    .context("--max-findings must be a number")?;
            }
            "--event-cap" => {
                event_cap = args
                    .next()
                    .context("--event-cap needs a number")?
                    .parse()
                    .context("--event-cap must be a number")?;
            }
            "--help" => {
                println!(
                    "Usage: axios-defender-tamper-review.exe --defender <defender-evidence.json> [--max-findings 100] [--event-cap 500]"
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument: {flag}"),
        }
    }

    if !(1..=500).contains(&max_findings) {
        bail!("--max-findings must be between 1 and 500");
    }
    if !(1..=2000).contains(&event_cap) {
        bail!("--event-cap must be between 1 and 2000");
    }

    Ok(Options {
        defender: defender.context("--defender is required")?,
        max_findings,
        event_cap,
    })
}

fn read_json(path: &PathBuf) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    serde_json::from_str(&text).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn validate_defender_evidence(defender: &Value) -> Result<()> {
    if defender.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("Defender evidence report must explicitly declare success=true");
    }

    Ok(())
}

fn build_report(defender: &Value, max_findings: usize, event_cap: usize) -> Value {
    let source = defender.get("source").unwrap_or(defender);
    let status = source.get("status").unwrap_or(&Value::Null);
    let events = source
        .get("operational_events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut current_protection_findings = current_protection_findings(status);
    let mut configuration_findings = Vec::new();
    let mut routine_configuration_events = 0usize;
    let mut security_events = 0usize;

    for event in &events {
        let id = event.get("id").and_then(Value::as_u64).unwrap_or_default();

        if id != 5007 {
            security_events += 1;
            continue;
        }

        let message = event
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let Some(control) = sensitive_control(message) else {
            routine_configuration_events += 1;
            continue;
        };

        let assessment = assess_change(&control, message);

        configuration_findings.push(json!({
            "event_id": id,
            "time_created": event.get("time_created").cloned().unwrap_or(Value::Null),
            "control": control,
            "priority": assessment.0,
            "classification": assessment.1,
            "reason": assessment.2,
            "message": compact_message(message)
        }));
    }

    current_protection_findings.sort_by(|left, right| {
        priority_rank(right["priority"].as_str().unwrap_or("low"))
            .cmp(&priority_rank(left["priority"].as_str().unwrap_or("low")))
    });

    configuration_findings.sort_by(|left, right| {
        priority_rank(right["priority"].as_str().unwrap_or("low"))
            .cmp(&priority_rank(left["priority"].as_str().unwrap_or("low")))
    });

    configuration_findings.truncate(max_findings);

    let high_priority = current_protection_findings
        .iter()
        .chain(configuration_findings.iter())
        .filter(|item| item["priority"] == "high")
        .count();

    let medium_priority = current_protection_findings
        .iter()
        .chain(configuration_findings.iter())
        .filter(|item| item["priority"] == "medium")
        .count();

    let event_cap_reached = events.len() >= event_cap;

    json!({
        "success": true,
        "collector": "axios_defender_tamper_review",
        "tampering_confirmed": false,
        "interpretation": {
            "note": "This report identifies Defender protection gaps and sensitive configuration changes. A sensitive change is not proof of malicious tampering without actor, ownership, and timing evidence.",
            "no_remediation_performed": true
        },
        "summary": {
            "operational_events_examined": events.len(),
            "event_cap": event_cap,
            "event_cap_reached": event_cap_reached,
            "security_events": security_events,
            "routine_configuration_events": routine_configuration_events,
            "sensitive_configuration_changes": configuration_findings.len(),
            "current_protection_gaps": current_protection_findings.len(),
            "high_priority_findings": high_priority,
            "medium_priority_findings": medium_priority
        },
        "current_protection_findings": current_protection_findings,
        "sensitive_configuration_changes": configuration_findings,
        "collection_limit_note": if event_cap_reached {
            "The Defender event collection reached its configured cap. Increase --event-cap only when a broader historical review is needed."
        } else {
            "The Defender event collection did not reach its configured cap."
        }
    })
}

fn current_protection_findings(status: &Value) -> Vec<Value> {
    let mut findings = Vec::new();

    for (field, title) in [
        (
            "IsTamperProtected",
            "Microsoft Defender tamper protection is disabled",
        ),
        (
            "AntivirusEnabled",
            "Microsoft Defender Antivirus is disabled",
        ),
        (
            "AntispywareEnabled",
            "Microsoft Defender antispyware protection is disabled",
        ),
        (
            "RealTimeProtectionEnabled",
            "Microsoft Defender real-time protection is disabled",
        ),
        (
            "BehaviorMonitorEnabled",
            "Microsoft Defender behavior monitoring is disabled",
        ),
    ] {
        if status_bool(status, field) == Some(false) {
            findings.push(json!({
                "priority": "high",
                "classification": "current_protection_gap",
                "control": field,
                "title": title,
                "evidence": { field: false }
            }));
        }
    }

    if let Some(mode) = status.get("AMRunningMode").and_then(Value::as_str) {
        if !mode.eq_ignore_ascii_case("normal") {
            findings.push(json!({
                "priority": "medium",
                "classification": "defender_running_mode_requires_review",
                "control": "AMRunningMode",
                "title": "Microsoft Defender is not reporting Normal running mode",
                "evidence": { "AMRunningMode": mode }
            }));
        }
    }

    findings
}

fn status_bool(status: &Value, field: &str) -> Option<bool> {
    match status.get(field) {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => Some(true),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn sensitive_control(message: &str) -> Option<String> {
    let normalized = message.to_ascii_lowercase();

    let controls = [
        ("disablerealtimemonitoring", "DisableRealtimeMonitoring"),
        ("disablebehaviormonitoring", "DisableBehaviorMonitoring"),
        ("disableioavprotection", "DisableIOAVProtection"),
        ("disablescriptscanning", "DisableScriptScanning"),
        ("disablearchivescanning", "DisableArchiveScanning"),
        ("disableemailscanning", "DisableEmailScanning"),
        ("disableantivirus", "DisableAntiVirus"),
        ("disableantispyware", "DisableAntiSpyware"),
        ("cloudblocklevel", "CloudBlockLevel"),
        ("mapsreporting", "MAPSReporting"),
        ("submitsamplesconsent", "SubmitSamplesConsent"),
        ("exclusionpath", "ExclusionPath"),
        ("exclusionprocess", "ExclusionProcess"),
        ("exclusionextension", "ExclusionExtension"),
        ("\\exclusions\\", "DefenderExclusions"),
    ];

    controls
        .iter()
        .find_map(|(needle, label)| normalized.contains(needle).then(|| (*label).to_string()))
}

fn assess_change(control: &str, message: &str) -> (&'static str, &'static str, &'static str) {
    let normalized = message.to_ascii_lowercase();

    let explicit_disable = normalized.contains("new value: 0x00000001")
        || normalized.contains("new value = 1")
        || normalized.contains("nouvelle valeur : 0x00000001")
        || normalized.contains("désactiv")
        || normalized.contains("disabled");

    if control.starts_with("Disable") && explicit_disable {
        (
            "high",
            "protection_weakening_requires_review",
            "A Defender protection control appears to have been disabled. Review actor, time, policy ownership, and current Defender status.",
        )
    } else if control == "DefenderExclusions"
        || control == "ExclusionPath"
        || control == "ExclusionProcess"
        || control == "ExclusionExtension"
    {
        (
            "medium",
            "defender_exclusion_change_requires_review",
            "A Defender exclusion-related setting changed. Exclusions can be legitimate, but they reduce inspection coverage and require ownership review.",
        )
    } else {
        (
            "medium",
            "sensitive_defender_configuration_change",
            "A sensitive Defender setting changed. The event alone does not establish whether the change was malicious or policy-managed.",
        )
    }
}

fn compact_message(message: &str) -> String {
    const LIMIT: usize = 1200;
    let text = message.trim();

    if text.chars().count() <= LIMIT {
        return text.to_string();
    }

    let mut compact = text.chars().take(LIMIT).collect::<String>();
    compact.push_str("…[truncated]");
    compact
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_realtime_protection_is_high_priority() {
        let source = json!({
            "status": {
                "AMRunningMode": "Normal",
                "AntivirusEnabled": true,
                "AntispywareEnabled": true,
                "RealTimeProtectionEnabled": false,
                "BehaviorMonitorEnabled": true
            },
            "operational_events": []
        });

        let report = build_report(&source, 100, 500);

        assert_eq!(report["summary"]["current_protection_gaps"], 1);
        assert_eq!(
            report["current_protection_findings"][0]["control"],
            "RealTimeProtectionEnabled"
        );
        assert_eq!(report["current_protection_findings"][0]["priority"], "high");
    }

    #[test]
    fn exclusion_change_requires_review_without_claiming_tampering() {
        let source = json!({
            "status": {},
            "operational_events": [{
                "id": 5007,
                "time_created": "2026-09-08T00:00:00Z",
                "message": "Microsoft Defender changed ExclusionPath from empty to C:\\\\Temp"
            }]
        });

        let report = build_report(&source, 100, 500);

        assert_eq!(report["tampering_confirmed"], false);
        assert_eq!(report["summary"]["sensitive_configuration_changes"], 1);
        assert_eq!(
            report["sensitive_configuration_changes"][0]["classification"],
            "defender_exclusion_change_requires_review"
        );
    }

    #[test]
    fn routine_5007_event_is_not_promoted() {
        let source = json!({
            "status": {},
            "operational_events": [{
                "id": 5007,
                "message": "Defender Diagnostics Platform RollbackMethod updated"
            }]
        });

        let report = build_report(&source, 100, 500);

        assert_eq!(report["summary"]["routine_configuration_events"], 1);
        assert_eq!(report["summary"]["sensitive_configuration_changes"], 0);
    }

    #[test]
    fn failed_defender_evidence_is_rejected() {
        assert!(validate_defender_evidence(&json!({"success": false})).is_err());
        assert!(validate_defender_evidence(&json!({})).is_err());
        assert!(validate_defender_evidence(&json!({"success": true})).is_ok());
    }
}
