use anyhow::{bail, Result};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "axios-evidence-review")]
struct Options {
    #[arg(long)]
    audit: PathBuf,
    #[arg(long)]
    processes: PathBuf,
    #[arg(long)]
    network: PathBuf,
    #[arg(long)]
    response_plan: PathBuf,
    #[arg(long)]
    correlation: PathBuf,
    #[arg(long, default_value_t = 25)]
    max_items: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    if options.max_items == 0 || options.max_items > 100 {
        bail!("max-items must be between 1 and 100");
    }

    let audit = read_success(&options.audit, "audit")?;
    let processes = read_success(&options.processes, "processes")?;
    let network = read_success(&options.network, "network")?;
    let response_plan = read_success(&options.response_plan, "response plan")?;
    let correlation = read_success(&options.correlation, "correlation")?;

    let file_findings = enrich_file_findings_with_correlation(
        review_entries(
            &audit,
            "artifacts",
            options.max_items,
            &[
                "path",
                "classification",
                "reason",
                "classification_evidence",
                "sha256",
                "signature_status",
                "mark_of_the_web",
            ],
        ),
        &correlation,
    );
    let file_scan_groups = build_file_scan_groups(&file_findings);
    let process_findings = review_entries(
        &processes,
        "artifacts",
        options.max_items,
        &[
            "process_id",
            "name",
            "executable_path",
            "classification",
            "reason",
            "sha256",
            "command_signals",
            "signature",
            "parent_mismatch",
            "user_writable_location",
        ],
    );
    let network_findings = review_entries(
        &network,
        "artifacts",
        options.max_items,
        &[
            "risk_level",
            "classification",
            "protocol",
            "local_address",
            "local_port",
            "service_role",
            "reason",
            "process",
            "evidence",
            "matching_inbound_allow_rules",
        ],
    );

    let report = json!({
        "schema_version": 1,
        "collector": "axios_evidence_review",
        "success": true,
        "summary": {
            "file_findings": file_findings.len(),
            "file_scan_groups": file_scan_groups.len(),
            "correlated_file_findings": file_findings.iter()
                .filter(|item| item.get("correlation").is_some())
                .count(),
            "process_findings": process_findings.len(),
            "network_findings": network_findings.len(),
            "posture_observations": response_plan.pointer("/summary/posture_observations")
                .and_then(Value::as_u64).unwrap_or(0)
        },
        "posture_observations": response_plan.get("posture_observations")
            .cloned().unwrap_or_else(|| json!([])),
        "file_findings": file_findings,
        "file_scan_groups": file_scan_groups,
        "process_findings": process_findings,
        "network_findings": network_findings,
        "limits": {
            "max_items_per_category": options.max_items,
            "fast_audit_truncated": audit.pointer("/scan_scope/truncated")
                .and_then(Value::as_bool).unwrap_or(false),
            "audit_artifacts_observed": audit.pointer("/summary/artifacts")
                .and_then(Value::as_u64).unwrap_or(0)
        }
    });

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

fn read_success(path: &PathBuf, name: &str) -> Result<Value> {
    let report = json_file::read_value(path)?;
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report is not successful");
    }
    Ok(report)
}

fn review_entries(report: &Value, key: &str, max: usize, fields: &[&str]) -> Vec<Value> {
    review_entries_with_actions(report, key, max, fields, false)
}

fn review_entries_with_actions(
    report: &Value,
    key: &str,
    max: usize,
    fields: &[&str],
    include_defender_action: bool,
) -> Vec<Value> {
    report
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("classification").and_then(Value::as_str) == Some("needs_review"))
        .take(max)
        .map(|entry| {
            let mut selected = Map::new();
            for field in fields {
                if let Some(value) = entry.get(*field) {
                    selected.insert((*field).to_string(), value.clone());
                }
            }

            if selected
                .get("reason")
                .and_then(Value::as_str)
                .map(str::is_empty)
                .unwrap_or(true)
            {
                selected.insert("reason".to_string(), json!(fallback_reason(entry)));
            }

            if include_defender_action {
                if let Some(path) = entry.get("path").and_then(Value::as_str) {
                    selected.insert(
                        "recommended_defender_scan".to_string(),
                        json!({
                            "scan_kind": "custom",
                            "path": path,
                            "requires_explicit_approval": true
                        }),
                    );
                }
            }

            Value::Object(selected)
        })
        .collect()
}

fn fallback_reason(entry: &Value) -> String {
    if let Some(evidence) = entry
        .get("classification_evidence")
        .and_then(Value::as_array)
        .filter(|evidence| !evidence.is_empty())
    {
        let items = evidence
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        if !items.is_empty() {
            return items.join("; ");
        }
    }

    if let Some(status) = entry.get("signature_status").and_then(Value::as_str) {
        return format!("classified_needs_review; signature_status={status}");
    }

    "classified_needs_review; source collector did not provide a more specific reason".to_string()
}

fn normalize_windows_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_matches('"')
        .to_ascii_lowercase()
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn enrich_file_findings_with_correlation(
    mut file_findings: Vec<Value>,
    correlation: &Value,
) -> Vec<Value> {
    let mut by_path = BTreeMap::new();

    for finding in correlation
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(path) = finding.get("path").and_then(Value::as_str) {
            by_path.insert(normalize_windows_path(path), finding);
        }
    }

    for file_finding in &mut file_findings {
        let Some(path) = file_finding.get("path").and_then(Value::as_str) else {
            continue;
        };

        let Some(correlation_finding) = by_path.get(&normalize_windows_path(path)) else {
            if let Some(object) = file_finding.as_object_mut() {
                object.insert("review_priority".to_string(), json!("medium"));
            }
            continue;
        };

        let persistence_matches = correlation_finding
            .get("persistence_matches")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let live_activity_matches = correlation_finding
            .get("live_activity_matches")
            .cloned()
            .unwrap_or_else(|| json!([]));

        let persistence_count = persistence_matches.as_array().map_or(0, Vec::len);
        let live_activity_count = live_activity_matches.as_array().map_or(0, Vec::len);
        let priority = if persistence_count > 0 || live_activity_count > 0 {
            "high"
        } else {
            "medium"
        };

        if let Some(object) = file_finding.as_object_mut() {
            object.insert("review_priority".to_string(), json!(priority));
            object.insert(
                "correlation".to_string(),
                json!({
                    "classification": correlation_finding.get("classification")
                        .cloned().unwrap_or(Value::Null),
                    "persistence_matches": persistence_matches,
                    "live_activity_matches": live_activity_matches
                }),
            );
        }
    }

    file_findings.sort_by(|left, right| {
        let left_priority = left
            .get("review_priority")
            .and_then(Value::as_str)
            .unwrap_or("low");
        let right_priority = right
            .get("review_priority")
            .and_then(Value::as_str)
            .unwrap_or("low");

        priority_rank(right_priority)
            .cmp(&priority_rank(left_priority))
            .then_with(|| {
                left.get("path")
                    .and_then(Value::as_str)
                    .cmp(&right.get("path").and_then(Value::as_str))
            })
    });

    file_findings
}

fn scan_target_for_path(path: &str) -> Option<String> {
    let last_separator = path.rfind(['\\', '/'])?;
    let directory = path[..last_separator].trim_end_matches(['\\', '/']);
    (!directory.is_empty()).then(|| directory.to_string())
}

fn build_file_scan_groups(file_findings: &[Value]) -> Vec<Value> {
    let mut groups: BTreeMap<String, (String, Vec<&Value>)> = BTreeMap::new();

    for finding in file_findings {
        let Some(path) = finding.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(target) = scan_target_for_path(path) else {
            continue;
        };

        groups
            .entry(target.to_ascii_lowercase())
            .or_insert_with(|| (target, Vec::new()))
            .1
            .push(finding);
    }

    groups
        .into_values()
        .map(|(scan_target, findings)| {
            let defender_scan_target = scan_target.clone();
            let sample_files = findings
                .iter()
                .take(5)
                .map(|finding| {
                    json!({
                        "path": finding.get("path").cloned().unwrap_or(Value::Null),
                        "sha256": finding.get("sha256").cloned().unwrap_or(Value::Null),
                        "reason": finding.get("reason").cloned().unwrap_or(Value::Null)
                    })
                })
                .collect::<Vec<_>>();

            json!({
                "scan_target": scan_target,
                "finding_count": findings.len(),
                "reason": if findings.len() > 1 {
                    "multiple needs_review files share this directory; one explicit custom scan is recommended"
                } else {
                    "one needs_review file is in this directory; an explicit custom scan is recommended"
                },
                "sample_files": sample_files,
                "recommended_defender_scan": {
                    "scan_kind": "custom",
                    "path": defender_scan_target,
                    "requires_explicit_approval": true
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn review_keeps_only_findings_that_need_review() {
        let report = json!({"artifacts": [
            {"path": "a.exe", "classification": "needs_review", "reason": "test"},
            {"path": "b.exe", "classification": "trusted"}
        ]});
        let entries = review_entries(&report, "artifacts", 25, &["path", "reason"]);

        assert_eq!(entries[0]["path"], "a.exe");
        assert!(entries[0].get("recommended_defender_scan").is_none());
    }

    #[test]
    fn file_scan_groups_deduplicate_directory_recommendations() {
        let findings = vec![
            json!({
                "path": r"C:\Users\Test\.minecraft\runtime\bin\java.exe",
                "sha256": "one",
                "reason": "needs review"
            }),
            json!({
                "path": r"C:\Users\Test\.minecraft\runtime\bin\awt.dll",
                "sha256": "two",
                "reason": "needs review"
            }),
        ];

        let groups = build_file_scan_groups(&findings);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["finding_count"], 2);
        assert_eq!(
            groups[0]["recommended_defender_scan"]["path"],
            r"C:\Users\Test\.minecraft\runtime\bin"
        );
        assert_eq!(
            groups[0]["recommended_defender_scan"]["requires_explicit_approval"],
            true
        );
    }

    #[test]
    fn fallback_reason_uses_audit_classification_evidence() {
        let entry = json!({
            "classification_evidence": [
                "executable_in_user_writable_location",
                "authenticode_status:NotSigned"
            ],
            "signature_status": "NotSigned"
        });

        assert_eq!(
            fallback_reason(&entry),
            "executable_in_user_writable_location; authenticode_status:NotSigned"
        );
    }
}
