use anyhow::{bail, Result};
use axios_core::storage::json_file;
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use std::{collections::BTreeMap, env, path::PathBuf};

#[derive(Debug)]
struct Options {
    state: PathBuf,
    audit: PathBuf,
    correlation: PathBuf,
    reasoning: PathBuf,
    summary: Option<PathBuf>,
    output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ResponsePlan {
    schema_version: u32,
    collector: &'static str,
    success: bool,
    summary: PlanSummary,
    items: Vec<ResponsePlanItem>,
    posture_observations: Vec<PostureObservation>,
}

#[derive(Debug, Serialize)]
struct PlanSummary {
    new_findings_considered: usize,
    high_priority_items: usize,
    medium_priority_items: usize,
    system_changes_requested: bool,
    posture_observations: usize,
}

#[derive(Debug, Serialize)]
struct ResponsePlanItem {
    finding_id: String,
    path: String,
    priority: String,
    evidence: Vec<String>,
    proposed_actions: Vec<ProposedAction>,
}

#[derive(Debug, Serialize)]
struct PostureObservation {
    id: String,
    priority: String,
    title: String,
    evidence: Vec<String>,
    proposed_actions: Vec<ProposedAction>,
}

#[derive(Debug, Serialize)]
struct ProposedAction {
    action: String,
    requires_explicit_approval: bool,
    description: String,
}

fn main() -> Result<()> {
    let Some(options) = parse_options(env::args().skip(1))? else {
        print_usage();
        return Ok(());
    };

    let state = json_file::read_value(&options.state)?;
    let audit = json_file::read_value(&options.audit)?;
    let correlation = json_file::read_value(&options.correlation)?;
    let reasoning = json_file::read_value(&options.reasoning)?;
    let summary = options
        .summary
        .as_ref()
        .map(json_file::read_value)
        .transpose()?;

    validate_report(&state, "state")?;
    validate_report(&audit, "audit")?;
    validate_report(&correlation, "correlation")?;
    validate_report(&reasoning, "reasoning")?;

    if let Some(summary) = &summary {
        validate_report(summary, "summary")?;
    }

    let plan =
        build_plan_with_reasoning(&state, &audit, &correlation, summary.as_ref(), &reasoning);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &plan)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    }

    Ok(())
}

fn parse_options<I, S>(arguments: I) -> Result<Option<Options>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut values = BTreeMap::<String, PathBuf>::new();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--state" | "--audit" | "--correlation" | "--reasoning" | "--summary" | "--output" => {
                if values.contains_key(&argument) {
                    bail!("{argument} was provided more than once");
                }

                let value = arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{argument} requires a path"))?;

                values.insert(argument, PathBuf::from(value));
            }
            "--help" | "-h" => return Ok(None),
            _ => bail!("unknown argument: {argument}"),
        }
    }

    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };

    Ok(Some(Options {
        state: required("--state")?,
        audit: required("--audit")?,
        correlation: required("--correlation")?,
        reasoning: required("--reasoning")?,
        summary: values.remove("--summary"),
        output: values.remove("--output"),
    }))
}

fn print_usage() {
    println!(
        "Usage:\n\
         axios-response-plan.exe \\\n\
           --state <STATE.json> \\\n\
           --audit <AUDIT.json> \\\n\
           --correlation <CORRELATION.json> \\\n\
           [--output <PLAN.json>]"
    );
}

fn validate_report(value: &Value, name: &str) -> Result<()> {
    if !value.is_object() {
        bail!("{name} report must be a JSON object");
    }

    if value.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }

    Ok(())
}

#[cfg(test)]
fn build_plan(state: &Value, audit: &Value, correlation: &Value) -> ResponsePlan {
    build_plan_with_summary(state, audit, correlation, None)
}

fn build_plan_with_summary(
    state: &Value,
    audit: &Value,
    correlation: &Value,
    summary: Option<&Value>,
) -> ResponsePlan {
    let correlation_paths = correlation_paths(correlation);
    let audit_artifacts = audit_artifacts(audit);

    let mut items = state
        .pointer("/finding_changes/new_samples")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|finding| build_plan_item(finding, &audit_artifacts, &correlation_paths))
        .collect::<Vec<_>>();

    items.sort_by(|left, right| {
        priority_rank(&right.priority)
            .cmp(&priority_rank(&left.priority))
            .then_with(|| left.path.cmp(&right.path))
    });

    let posture_observations = summary
        .map(collect_posture_observations)
        .unwrap_or_default();

    let high_priority_items = items.iter().filter(|item| item.priority == "high").count()
        + posture_observations
            .iter()
            .filter(|item| item.priority == "high")
            .count();

    let medium_priority_items = items
        .iter()
        .filter(|item| item.priority == "medium")
        .count()
        + posture_observations
            .iter()
            .filter(|item| item.priority == "medium")
            .count();

    ResponsePlan {
        schema_version: 1,
        collector: "axios_response_plan",
        success: true,
        summary: PlanSummary {
            new_findings_considered: items.len(),
            high_priority_items,
            medium_priority_items,
            system_changes_requested: false,
            posture_observations: posture_observations.len(),
        },
        items,
        posture_observations,
    }
}

fn build_plan_with_reasoning(
    state: &Value,
    audit: &Value,
    correlation: &Value,
    summary: Option<&Value>,
    reasoning: &Value,
) -> ResponsePlan {
    let mut plan = build_plan_with_summary(state, audit, correlation, summary);
    let planned_actions = reasoning
        .get("investigation_plan")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some((
                item.get("triggered_by")?.as_str()?.to_string(),
                item.get("action")?.as_str()?.to_string(),
            ))
        })
        .collect::<BTreeMap<_, _>>();

    for conclusion in reasoning
        .get("conclusions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if conclusion.get("classification").and_then(Value::as_str) == Some("pipeline_integrity") {
            continue;
        }
        let Some(id) = conclusion.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(title) = conclusion.get("title").and_then(Value::as_str) else {
            continue;
        };
        let priority = match conclusion
            .get("confidence")
            .and_then(Value::as_str)
            .unwrap_or("context")
        {
            "high" => "high",
            "medium" => "medium",
            _ => "context",
        };
        let evidence = conclusion
            .get("evidence_paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect();
        let action = planned_actions
            .get(id)
            .map(String::as_str)
            .unwrap_or("Preserve the linked evidence and review it before any system change.");
        plan.posture_observations.push(PostureObservation {
            id: format!("reasoning:{id}"),
            priority: priority.to_string(),
            title: title.to_string(),
            evidence,
            proposed_actions: vec![review_action("follow_reasoning_check", action)],
        });
    }
    plan.posture_observations
        .sort_by(|left, right| left.id.cmp(&right.id));
    plan.summary.high_priority_items = plan
        .items
        .iter()
        .filter(|item| item.priority == "high")
        .count()
        + plan
            .posture_observations
            .iter()
            .filter(|item| item.priority == "high")
            .count();
    plan.summary.medium_priority_items = plan
        .items
        .iter()
        .filter(|item| item.priority == "medium")
        .count()
        + plan
            .posture_observations
            .iter()
            .filter(|item| item.priority == "medium")
            .count();
    plan.summary.posture_observations = plan.posture_observations.len();
    plan
}

fn build_plan_item(
    finding: &Value,
    artifacts: &BTreeMap<String, Value>,
    correlation_paths: &BTreeMap<String, Value>,
) -> Option<ResponsePlanItem> {
    let path = finding.get("path")?.as_str()?.to_string();
    let finding_id = finding
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let mut evidence = string_array(finding, "signals");
    let signature_status = finding
        .get("signature_status")
        .and_then(Value::as_str)
        .unwrap_or("NotChecked");

    if signature_status != "NotChecked" {
        evidence.push(format!("signature_status:{signature_status}"));
    }

    if artifacts.contains_key(&normalize_path(&path)) {
        evidence.push("audit_artifact_present".to_string());
    }

    if correlation_paths.contains_key(&normalize_path(&path)) {
        evidence.push("persistence_or_live_correlation".to_string());
    }

    evidence.sort();
    evidence.dedup();

    let high_priority = evidence
        .iter()
        .any(|value| value == "persistence_or_live_correlation")
        || matches!(
            signature_status,
            "BadDigest" | "ExplicitDistrust" | "SecuritySettingsBlocked" | "CertificateRevoked"
        );

    let priority = if high_priority { "high" } else { "medium" }.to_string();

    let mut proposed_actions = vec![
        ProposedAction {
            action: "preserve_evidence".to_string(),
            requires_explicit_approval: false,
            description: "Keep the report, file hash, signature status, and related telemetry."
                .to_string(),
        },
        ProposedAction {
            action: "defender_custom_scan".to_string(),
            requires_explicit_approval: true,
            description: "Request a Microsoft Defender custom scan for the file directory."
                .to_string(),
        },
    ];

    if high_priority {
        proposed_actions.push(ProposedAction {
            action: "review_persistence_reference".to_string(),
            requires_explicit_approval: false,
            description:
                "Inspect the registry, task, service, or startup reference before any change."
                    .to_string(),
        });
    }

    Some(ResponsePlanItem {
        finding_id,
        path,
        priority,
        evidence,
        proposed_actions,
    })
}

fn summary_count(summary: &Value, pointer: &str) -> u64 {
    summary
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn review_action(action: &str, description: &str) -> ProposedAction {
    ProposedAction {
        action: action.to_string(),
        requires_explicit_approval: false,
        description: description.to_string(),
    }
}

fn collect_posture_observations(summary: &Value) -> Vec<PostureObservation> {
    let mut observations = Vec::new();

    if summary
        .pointer("/hardware_trust/secure_boot/enabled")
        .and_then(Value::as_bool)
        == Some(false)
    {
        observations.push(PostureObservation {
            id: "secure_boot_disabled".to_string(),
            priority: "high".to_string(),
            title: "Secure Boot is disabled".to_string(),
            evidence: vec![
                "hardware_trust.secure_boot.enabled:false".to_string(),
                "firmware_boot_protection_reduced".to_string(),
            ],
            proposed_actions: vec![review_action(
                "review_secure_boot_configuration",
                "Review UEFI support and the current boot configuration before enabling Secure Boot.",
            )],
        });
    }

    let whql_events = summary_count(summary, "/kernel_posture/whql_enforcement_disabled_events");
    if whql_events > 0 {
        observations.push(PostureObservation {
            id: "code_integrity_whql_events".to_string(),
            priority: "medium".to_string(),
            title: "Code Integrity reported WHQL enforcement events".to_string(),
            evidence: vec![format!("kernel_posture.whql_enforcement_disabled_events:{whql_events}")],
            proposed_actions: vec![review_action(
                "review_code_integrity_events",
                "Review the related Code Integrity events and driver policy before changing enforcement settings.",
            )],
        });
    }

    let listeners = summary_count(summary, "/network_service_review/needs_review");
    if listeners > 0 {
        observations.push(PostureObservation {
            id: "inbound_listener_rules_require_review".to_string(),
            priority: "medium".to_string(),
            title: "Listening endpoints have matching inbound allow rules".to_string(),
            evidence: vec![format!("network_service_review.needs_review:{listeners}")],
            proposed_actions: vec![review_action(
                "review_inbound_firewall_rules",
                "Review each listener, its process owner, and its matching inbound allow rule before disabling anything.",
            )],
        });
    }

    let processes = summary_count(summary, "/process_integrity/needs_review");
    if processes > 0 {
        observations.push(PostureObservation {
            id: "process_integrity_findings".to_string(),
            priority: "medium".to_string(),
            title: "Process integrity findings require evidence review".to_string(),
            evidence: vec![format!("process_integrity.needs_review:{processes}")],
            proposed_actions: vec![review_action(
                "review_process_integrity_findings",
                "Review process path, signer, parent process, command signals, and network activity.",
            )],
        });
    }

    let files = summary_count(summary, "/audit_summary/needs_review");
    if files > 0 {
        observations.push(PostureObservation {
            id: "file_audit_findings".to_string(),
            priority: "medium".to_string(),
            title: "File audit findings require evidence review".to_string(),
            evidence: vec![format!("audit_summary.needs_review:{files}")],
            proposed_actions: vec![review_action(
                "review_file_audit_findings",
                "Review file hash, signature result, path, Mark-of-the-Web, and related persistence or process evidence.",
            )],
        });
    }

    observations
}

fn audit_artifacts(audit: &Value) -> BTreeMap<String, Value> {
    audit
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|artifact| {
            let path = artifact.get("path")?.as_str()?;
            Some((normalize_path(path), artifact.clone()))
        })
        .collect()
}

fn correlation_paths(correlation: &Value) -> BTreeMap<String, Value> {
    correlation
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|finding| {
            finding.get("classification").and_then(Value::as_str) == Some("needs_review")
        })
        .filter_map(|finding| {
            let path = finding.get("path")?.as_str()?;
            Some((normalize_path(path), finding.clone()))
        })
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_option_is_rejected() {
        assert!(parse_options([
            "--state",
            "a.json",
            "--state",
            "b.json",
            "--audit",
            "audit.json",
            "--correlation",
            "correlation.json",
        ])
        .is_err());
    }

    #[test]
    fn persistent_bad_digest_is_high_priority() {
        let state = json!({
            "finding_changes": {
                "new_samples": [{
                    "id": "sha256:abc",
                    "path": r"C:\Users\TestUser\AppData\Local\Temp\loader.exe",
                    "signature_status": "BadDigest",
                    "signals": ["user_writable_location"]
                }]
            }
        });
        let audit = json!({
            "artifacts": [{
                "path": r"C:\Users\TestUser\AppData\Local\Temp\loader.exe"
            }]
        });
        let correlation = json!({
            "findings": [{
                "path": r"C:\Users\TestUser\AppData\Local\Temp\loader.exe",
                "classification": "needs_review"
            }]
        });

        let plan = build_plan(&state, &audit, &correlation);

        assert_eq!(plan.summary.high_priority_items, 1);
        assert!(!plan.summary.system_changes_requested);
        assert!(plan.items[0]
            .proposed_actions
            .iter()
            .any(|action| action.action == "defender_custom_scan"));
    }

    #[test]
    fn posture_observations_explain_existing_security_posture() {
        let summary = json!({
            "hardware_trust": {
                "secure_boot": { "enabled": false }
            },
            "kernel_posture": {
                "whql_enforcement_disabled_events": 2
            },
            "network_service_review": {
                "needs_review": 3
            },
            "process_integrity": {
                "needs_review": 4
            },
            "audit_summary": {
                "needs_review": 5
            }
        });

        let plan = build_plan_with_summary(
            &json!({"finding_changes": {"new_samples": []}}),
            &json!({}),
            &json!({}),
            Some(&summary),
        );

        assert_eq!(plan.items.len(), 0);
        assert_eq!(plan.summary.posture_observations, 5);
        assert_eq!(plan.summary.high_priority_items, 1);
        assert_eq!(plan.summary.medium_priority_items, 4);
        assert!(plan
            .posture_observations
            .iter()
            .any(|item| item.id == "secure_boot_disabled"));
    }

    #[test]
    fn no_new_findings_produces_empty_plan() {
        let plan = build_plan(
            &json!({"finding_changes": {"new_samples": []}}),
            &json!({}),
            &json!({}),
        );

        assert!(plan.items.is_empty());
    }
    #[test]
    fn report_without_explicit_success_is_rejected() {
        assert!(validate_report(&json!({}), "audit").is_err());
        assert!(validate_report(&json!({"success": false}), "audit").is_err());
        assert!(validate_report(&json!({"success": true}), "audit").is_ok());
    }
}
