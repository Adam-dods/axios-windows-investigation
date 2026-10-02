use anyhow::Result;
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-collection-integrity-review")]
struct Options {
    #[arg(long)]
    processes: PathBuf,
    #[arg(long)]
    memory: PathBuf,
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    defender: Option<PathBuf>,
    #[arg(long)]
    network: PathBuf,
    #[arg(long)]
    persistence: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    let defender = match options.defender {
        Some(path) => json_file::read_value(path)?,
        None => json!({
            "success": true,
            "collection_status": "defender_evidence_not_yet_available"
        }),
    };

    let reports = vec![
        ("processes", json_file::read_value(&options.processes)?),
        ("memory", json_file::read_value(&options.memory)?),
        ("kernel", json_file::read_value(&options.kernel)?),
        ("defender", defender),
        ("network", json_file::read_value(&options.network)?),
        ("persistence", json_file::read_value(&options.persistence)?),
    ];

    let report = build_report(&reports);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn report_succeeded(name: &str, report: &Value) -> bool {
    if name == "persistence" {
        return ["registry", "extended", "coverage"]
            .iter()
            .all(|component| {
                report
                    .get(*component)
                    .and_then(|item| item.get("success"))
                    .and_then(Value::as_bool)
                    == Some(true)
            });
    }

    report.get("success").and_then(Value::as_bool) == Some(true)
}

fn build_report(reports: &[(&str, Value)]) -> Value {
    let get = |name: &str| {
        reports
            .iter()
            .find(|(report_name, _)| *report_name == name)
            .map(|(_, report)| report)
            .unwrap()
    };

    let processes = get("processes");
    let memory = get("memory");
    let kernel = get("kernel");
    let defender = get("defender");
    let network = get("network");
    let persistence = get("persistence");

    let mut findings = Vec::new();

    for (name, report) in reports {
        if !report_succeeded(name, report) {
            findings.push(json!({
                "priority": "medium",
                "classification": "collection_failure",
                "id": format!("{name}_collector_failed"),
                "reason": "a required evidence source reported failure"
            }));
        }
    }

    let limited_processes = memory
        .pointer("/summary/visibility_limited_processes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let memory_scan_truncated_processes = memory
        .pointer("/summary/scan_truncated_processes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let process_inventory_truncated = processes
        .pointer("/limits/processes_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if limited_processes > 0 {
        findings.push(json!({
            "priority": "context",
            "classification": "visibility_limited",
            "id": "protected_process_memory_visibility_limited",
            "evidence": { "process_count": limited_processes },
            "reason": "some protected processes could not be memory-enumerated; this is not clean evidence and not malware proof"
        }));
    }

    if memory_scan_truncated_processes > 0 {
        findings.push(json!({
            "priority": "context",
            "classification": "visibility_limited",
            "id": "memory_region_scan_truncated",
            "evidence": { "process_count": memory_scan_truncated_processes },
            "reason": "one or more process memory enumerations reached their bounded region limit; unexamined regions remain a visibility limitation"
        }));
    }

    if process_inventory_truncated {
        findings.push(json!({
            "priority": "context",
            "classification": "visibility_limited",
            "id": "process_inventory_truncated",
            "reason": "the process inventory reached its configured reporting limit; processes outside that limit were not evaluated"
        }));
    }

    let defender_event_cap = defender
        .pointer("/summary/event_cap_reached")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if defender_event_cap {
        findings.push(json!({
            "priority": "context",
            "classification": "history_limited",
            "id": "defender_event_history_capped",
            "reason": "Defender event review was bounded; older historical evidence may not be included"
        }));
    }

    let defender_tampering = defender
        .pointer("/summary/tampering_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || defender
            .get("tampering_confirmed")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    if defender_tampering {
        findings.push(json!({
            "priority": "high",
            "classification": "defender_tampering_confirmed",
            "id": "defender_tamper_signal",
            "reason": "Defender evidence reported confirmed tampering; independently verify from trusted offline or enterprise telemetry"
        }));
    }

    let network_error = network
        .get("collection_error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(error) = network_error {
        findings.push(json!({
            "priority": "medium",
            "classification": "network_visibility_limited",
            "id": "network_collection_error",
            "evidence": { "error": error },
            "reason": "network conclusions are incomplete because collection failed or was partial"
        }));
    }

    let network_collection_limited = network
        .pointer("/summary/collection_limited")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if network_collection_limited {
        findings.push(json!({
            "priority": "context",
            "classification": "network_visibility_limited",
            "id": "network_connection_inventory_truncated",
            "reason": "the network identity review reached its bounded connection limit; connections outside the selected evidence set were not evaluated"
        }));
    }

    let process_count = processes
        .get("artifacts")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    let memory_scanned = memory
        .pointer("/summary/processes_scanned")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    if process_count > 0 && memory_scanned == 0 {
        findings.push(json!({
            "priority": "medium",
            "classification": "cross_source_contradiction",
            "id": "processes_present_memory_scan_empty",
            "evidence": {
                "process_integrity_artifacts": process_count,
                "memory_processes_scanned": memory_scanned
            },
            "reason": "process inventory exists but memory layer did not scan any process"
        }));
    }

    let kernel_rootkit = kernel
        .get("rootkit_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if kernel_rootkit {
        findings.push(json!({
            "priority": "high",
            "classification": "invalid_confidence_claim",
            "id": "kernel_report_claimed_rootkit_confirmation",
            "reason": "AXIOS policy forbids confirming a rootkit solely from local Windows evidence"
        }));
    }

    let persistence_available = report_succeeded("persistence", persistence);

    if !persistence_available {
        findings.push(json!({
            "priority": "medium",
            "classification": "persistence_visibility_limited",
            "id": "persistence_evidence_unavailable",
            "reason": "startup and persistence correlation is incomplete"
        }));
    }

    let high = findings
        .iter()
        .filter(|item| item["priority"] == "high")
        .count();
    let medium = findings
        .iter()
        .filter(|item| item["priority"] == "medium")
        .count();
    let context = findings
        .iter()
        .filter(|item| item["priority"] == "context")
        .count();

    let confidence = if high > 0 || medium > 0 {
        "limited"
    } else if limited_processes > 0
        || memory_scan_truncated_processes > 0
        || process_inventory_truncated
        || defender_event_cap
        || network_collection_limited
    {
        "partial"
    } else {
        "normal_local_visibility"
    };

    json!({
        "success": true,
        "collector": "axios_collection_integrity_review",
        "read_only": true,
        "database_used": false,
        "local_os_evidence_only": true,
        "rootkit_confirmed": false,
        "firmware_backdoor_confirmed": false,
        "zero_day_confirmed": false,
        "collection_confidence": confidence,
        "policy": {
            "collector_failure": "not_clean",
            "access_denied": "visibility_limited",
            "cross_source_contradiction": "requires_review",
            "local_windows_only": "cannot_definitively_rule_out_kernel_or_firmware_compromise"
        },
        "summary": {
            "high_priority_integrity_findings": high,
            "medium_priority_integrity_findings": medium,
            "context_visibility_notes": context,
            "processes_observed": process_count,
            "memory_processes_scanned": memory_scanned,
            "memory_visibility_limited_processes": limited_processes
        },
        "findings": findings
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_memory_visibility_is_not_clean_or_malware() {
        let reports = vec![
            (
                "processes",
                json!({"success": true, "artifacts": [{"pid": 1}]}),
            ),
            (
                "memory",
                json!({"success": true, "summary": {"processes_scanned": 1, "visibility_limited_processes": 2}}),
            ),
            (
                "kernel",
                json!({"success": true, "rootkit_confirmed": false}),
            ),
            (
                "defender",
                json!({"success": true, "summary": {"event_cap_reached": false}}),
            ),
            (
                "network",
                json!({"success": true, "collection_error": null}),
            ),
            (
                "persistence",
                json!({
                    "collector": "persistence-combined",
                    "registry": {"success": true},
                    "extended": {"success": true},
                    "coverage": {"success": true}
                }),
            ),
        ];

        let report = build_report(&reports);

        assert_eq!(report["collection_confidence"], "partial");
        assert_eq!(report["rootkit_confirmed"], false);
    }

    #[test]
    fn incomplete_or_failed_combined_persistence_is_not_clean() {
        assert!(report_succeeded(
            "persistence",
            &json!({
                "registry": {"success": true},
                "extended": {"success": true},
                "coverage": {"success": true}
            })
        ));

        assert!(!report_succeeded(
            "persistence",
            &json!({
                "registry": {"success": true},
                "extended": {"success": false},
                "coverage": {"success": true}
            })
        ));

        assert!(!report_succeeded("processes", &json!({})));
    }

    #[test]
    fn collector_failure_reduces_confidence() {
        let reports = vec![
            ("processes", json!({"success": false})),
            ("memory", json!({"success": true, "summary": {}})),
            ("kernel", json!({"success": true})),
            ("defender", json!({"success": true, "summary": {}})),
            ("network", json!({"success": true})),
            (
                "persistence",
                json!({
                    "collector": "persistence-combined",
                    "registry": {"success": true},
                    "extended": {"success": true},
                    "coverage": {"success": true}
                }),
            ),
        ];

        let report = build_report(&reports);

        assert_eq!(report["collection_confidence"], "limited");
        assert_eq!(report["summary"]["medium_priority_integrity_findings"], 1);
    }

    #[test]
    fn network_connection_limit_reduces_confidence() {
        let reports = vec![
            ("processes", json!({"success": true})),
            ("memory", json!({"success": true, "summary": {}})),
            ("kernel", json!({"success": true})),
            ("defender", json!({"success": true, "summary": {}})),
            (
                "network",
                json!({"success": true, "summary": {"collection_limited": true}}),
            ),
            (
                "persistence",
                json!({
                    "registry": {"success": true},
                    "extended": {"success": true},
                    "coverage": {"success": true}
                }),
            ),
        ];

        let report = build_report(&reports);
        assert_eq!(report["collection_confidence"], "partial");
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["id"] == "network_connection_inventory_truncated" }));
    }

    #[test]
    fn process_and_memory_limits_reduce_confidence() {
        let reports = vec![
            (
                "processes",
                json!({"success": true, "limits": {"processes_truncated": true}}),
            ),
            (
                "memory",
                json!({"success": true, "summary": {"scan_truncated_processes": 1}}),
            ),
            ("kernel", json!({"success": true})),
            ("defender", json!({"success": true, "summary": {}})),
            ("network", json!({"success": true})),
            (
                "persistence",
                json!({
                    "registry": {"success": true},
                    "extended": {"success": true},
                    "coverage": {"success": true}
                }),
            ),
        ];

        let report = build_report(&reports);
        assert_eq!(report["collection_confidence"], "partial");
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["id"] == "process_inventory_truncated" }));
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["id"] == "memory_region_scan_truncated" }));
    }
}
