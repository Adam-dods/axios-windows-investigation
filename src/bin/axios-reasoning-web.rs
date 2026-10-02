use anyhow::{bail, Context, Result};
use axios_core::{
    reasoning::{
        build_proof_traces, evaluate_hypotheses, graph::match_artifact_identities,
        plan_utility_score, rank_checks, ArtifactIdentity, BranchEvidence, BranchState,
        HypothesisInput, HypothesisKind, IdentityMatchStrength, InferenceLimits,
        InvestigationCheck, ObservedFact, ReasoningBranch, Score,
    },
    storage::json_file,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
};

const REQUIRED_INPUTS: [&str; 20] = [
    "summary",
    "score",
    "behavior",
    "persistence",
    "memory-execution",
    "collection-integrity",
    "observation",
    "network",
    "network-deep",
    "kernel",
    "state",
    "security-controls",
    "defender-tamper",
    "remote-access",
    "telemetry-integrity",
    "execution-policy",
    "identity-access",
    "updates",
    "admin-exposure",
    "context",
];

const INPUT_SUCCESS_FACTS: [&str; 20] = [
    "input.summary.success",
    "input.score.success",
    "input.behavior.success",
    "input.persistence.success",
    "input.memory-execution.success",
    "input.collection-integrity.success",
    "input.observation.success",
    "input.network.success",
    "input.network-deep.success",
    "input.kernel.success",
    "input.state.success",
    "input.security-controls.success",
    "input.defender-tamper.success",
    "input.remote-access.success",
    "input.telemetry-integrity.success",
    "input.execution-policy.success",
    "input.identity-access.success",
    "input.updates.success",
    "input.admin-exposure.success",
    "input.context.success",
];

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    premises: &'static [&'static str],
    conclusion: &'static str,
    classification: &'static str,
    confidence: &'static str,
    title: &'static str,
    explanation: &'static str,
    next_check: &'static str,
    information_gain: u8,
    collection_cost: u8,
}

fn main() -> Result<()> {
    let paths = options()?;
    let reports = load_reports(&paths)?;
    let report = build_report(&reports);

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn options() -> Result<BTreeMap<String, PathBuf>> {
    options_from(env::args().skip(1))
}

fn options_from<I, S>(arguments: I) -> Result<BTreeMap<String, PathBuf>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = arguments.into_iter().map(Into::into);
    let mut paths = BTreeMap::new();

    while let Some(flag) = args.next() {
        let name = flag.strip_prefix("--").context("invalid argument")?;

        if !REQUIRED_INPUTS.contains(&name) {
            bail!("unknown argument: {flag}");
        }

        let value = PathBuf::from(args.next().context(format!("{flag} needs a file"))?);

        if paths.insert(name.to_string(), value).is_some() {
            bail!("{flag} was supplied more than once");
        }
    }

    for name in REQUIRED_INPUTS {
        if !paths.contains_key(name) {
            bail!("--{name} is required");
        }
    }

    Ok(paths)
}

fn load_reports(paths: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Value>> {
    let mut reports = BTreeMap::new();

    for (name, path) in paths {
        let report = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;

        if report.get("success").and_then(Value::as_bool) != Some(true) {
            bail!("{name} report must explicitly declare success=true");
        }

        reports.insert(name.clone(), report);
    }

    Ok(reports)
}

fn add_fact(facts: &mut BTreeMap<String, Value>, id: &str, source: &str, value: Value) {
    let fact = ObservedFact::new(source, value);
    let value = serde_json::to_value(fact).expect("ObservedFact serialization cannot fail");
    facts.insert(id.to_string(), value);
}

fn positive_number(report: &Value, pointer: &str) -> Option<u64> {
    report
        .pointer(pointer)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
}

fn nonempty_array_count(report: &Value, pointer: &str) -> Option<usize> {
    report
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::len)
        .filter(|value| *value > 0)
}

fn text_at<'a>(report: &'a Value, pointer: &str) -> Option<&'a str> {
    report.pointer(pointer).and_then(Value::as_str)
}

fn finding_with_id(report: &Value, id: &str) -> Option<Value> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|finding| finding.get("id").and_then(Value::as_str) == Some(id))
        .cloned()
}

fn pending_update_severity_count(report: &Value, severity: &str) -> usize {
    report
        .get("pending_software_updates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|update| {
            update
                .get("severity")
                .and_then(Value::as_str)
                .map(|value| value.eq_ignore_ascii_case(severity))
                .unwrap_or(false)
        })
        .count()
}

fn plan_score(rule: &Rule) -> u8 {
    plan_utility_score(rule.information_gain, rule.collection_cost)
}

fn priority(score: u8) -> &'static str {
    match score {
        70..=u8::MAX => "high",
        40..=69 => "medium",
        _ => "context",
    }
}

fn confidence_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn hypothesis_for_classification(classification: &str) -> HypothesisKind {
    match classification {
        "evidence_chain" | "network_execution_exposure" | "potential_exploit_behavior" => {
            HypothesisKind::SuspiciousExecutionChain
        }
        "credential_control_disabled"
        | "critical_security_updates_pending"
        | "legacy_network_protocol_enabled"
        | "remote_desktop_without_nla"
        | "security_weakening"
        | "servicing_completion_required"
        | "smb_integrity_control_weakened" => HypothesisKind::SecurityMisconfiguration,
        "local_account_exposure"
        | "network_reachability"
        | "privilege_escalation_exposure"
        | "remote_access_exposure" => HypothesisKind::AdministrativeActivity,
        "detection_coverage_gap_with_artifact_evidence"
        | "identity_conflict"
        | "identity_verification_required"
        | "needs_review" => HypothesisKind::PotentiallyUnwantedSoftware,
        "execution_visibility_gap"
        | "limited_visibility_with_artifact_evidence"
        | "pipeline_integrity"
        | "visibility_context"
        | "visibility_failure"
        | "visibility_limitation"
        | "visibility_limited" => HypothesisKind::VisibilityLimited,
        _ => HypothesisKind::LegitimateActivity,
    }
}

fn independence_group(evidence_path: &str) -> String {
    let prefix = evidence_path.split('.').next().unwrap_or("unknown");

    match prefix {
        "behavior" | "memory" | "process" => "windows_process_execution",
        "network" => "windows_network_snapshot",
        "persistence" => "windows_persistence_configuration",
        "security" | "defender" => "windows_security_configuration",
        "kernel" | "boot" | "driver" => "windows_kernel_trust",
        "identity" | "admin" => "windows_identity_configuration",
        "updates" => "windows_servicing",
        "telemetry" | "observation" | "collection" => "collection_visibility",
        "input" => "pipeline_validation",
        other => other,
    }
    .to_string()
}

fn hypothesis_inputs(conclusions: &[Value]) -> Vec<HypothesisInput> {
    let mut inputs = Vec::new();

    for conclusion in conclusions {
        let Some(id) = conclusion.get("id").and_then(Value::as_str) else {
            continue;
        };
        let classification = conclusion
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("visibility_limited");
        let confidence = conclusion
            .get("confidence")
            .and_then(Value::as_str)
            .unwrap_or("context");
        let strength = match confidence {
            "high" => 8_500,
            "medium" => 6_500,
            "low" => 4_000,
            _ => 2_500,
        };
        let hypothesis = hypothesis_for_classification(classification);
        let unknowns = if hypothesis == HypothesisKind::VisibilityLimited {
            vec![format!("visibility:{id}")]
        } else {
            Vec::new()
        };

        let mut supports = conclusion
            .get("evidence_paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|evidence_path| BranchEvidence {
                id: format!("{id}:{evidence_path}"),
                strength: Score::new(strength),
                independence_group: Some(independence_group(evidence_path)),
            })
            .collect::<Vec<_>>();
        if supports.is_empty() {
            supports.push(BranchEvidence {
                id: id.to_string(),
                strength: Score::new(strength),
                independence_group: None,
            });
        }

        inputs.push(HypothesisInput {
            hypothesis,
            supports,
            contradictions: Vec::new(),
            unknowns,
        });

        if classification == "identity_conflict" {
            inputs.push(HypothesisInput {
                hypothesis: HypothesisKind::SuspiciousExecutionChain,
                supports: Vec::new(),
                contradictions: vec![BranchEvidence {
                    id: format!("identity_conflict:{id}"),
                    strength: Score::new(strength),
                    independence_group: Some("artifact_identity".to_string()),
                }],
                unknowns: vec![format!("shared_artifact_identity:{id}")],
            });
        }
    }

    inputs
}

fn planner_checks(plan: &[Value], branches: &[ReasoningBranch]) -> Vec<InvestigationCheck> {
    plan.iter()
        .filter_map(|item| {
            let triggered_by = item.get("triggered_by")?.as_str()?;
            let action = item.get("action")?.as_str()?;
            let information_gain = item
                .get("expected_information_gain")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .min(10);
            let collection_cost = item
                .get("estimated_collection_cost")
                .and_then(Value::as_u64)
                .unwrap_or(5)
                .clamp(1, 10);
            let distinguishes = branches
                .iter()
                .filter(|branch| {
                    branch
                        .supports
                        .iter()
                        .any(|evidence| evidence.id.starts_with(triggered_by))
                        || branch
                            .unknowns
                            .iter()
                            .any(|unknown| unknown.contains(triggered_by))
                })
                .map(|branch| branch.id.clone())
                .collect::<Vec<_>>();
            let discrimination = if distinguishes.len() > 1 {
                8_000
            } else {
                5_000
            };

            Some(InvestigationCheck {
                id: format!("check.{triggered_by}"),
                action: action.to_string(),
                resolves: vec![triggered_by.to_string()],
                distinguishes,
                information_gain: Score::new((information_gain * 1_000) as u16),
                discrimination: Score::new(discrimination),
                safety: Score::MAX,
                cost: Score::new((collection_cost * 1_000) as u16),
                runtime: Score::new(5_000),
                intrusiveness: Score::new(2_000),
                read_only: true,
            })
        })
        .collect()
}

fn normalize_artifact_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace("/", "\\")
        .to_ascii_lowercase()
}

fn high_priority_artifacts_by_path(report: &Value) -> BTreeMap<String, Value> {
    report
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("priority").and_then(Value::as_str) == Some("high"))
        .filter_map(|item| {
            item.get("path")
                .and_then(Value::as_str)
                .map(|path| (normalize_artifact_path(path), item.clone()))
        })
        .collect()
}

fn high_priority_network_artifacts_by_path(report: &Value) -> BTreeMap<String, Value> {
    report
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("priority").and_then(Value::as_str) == Some("high"))
        .filter_map(|item| {
            item.get("process")
                .and_then(|process| process.get("executable_path"))
                .and_then(Value::as_str)
                .map(|path| (normalize_artifact_path(path), item.clone()))
        })
        .collect()
}

fn path_is_within(exclusion: &str, artifact: &str) -> bool {
    let root = normalize_artifact_path(exclusion)
        .trim_end_matches(char::from(92u8))
        .to_string();
    let candidate = normalize_artifact_path(artifact);

    !root.is_empty()
        && (candidate == root
            || (candidate.starts_with(&root) && candidate.as_bytes().get(root.len()) == Some(&92)))
}

fn artifact_identity(artifact: &Value, network_shape: bool) -> ArtifactIdentity {
    let identity = artifact.get("identity").unwrap_or(&Value::Null);
    let process = artifact.get("process").unwrap_or(&Value::Null);

    let path = identity
        .get("normalized_path")
        .and_then(Value::as_str)
        .or_else(|| {
            if network_shape {
                process.get("executable_path").and_then(Value::as_str)
            } else {
                artifact.get("path").and_then(Value::as_str)
            }
        });
    let sha256 = identity
        .get("sha256")
        .and_then(Value::as_str)
        .or_else(|| artifact.get("sha256").and_then(Value::as_str))
        .or_else(|| process.get("sha256").and_then(Value::as_str));
    let pid = identity
        .get("pid")
        .and_then(Value::as_u64)
        .or_else(|| artifact.get("pid").and_then(Value::as_u64));
    let start_time = identity
        .get("start_time")
        .and_then(Value::as_str)
        .or_else(|| process.get("creation_date").and_then(Value::as_str));

    ArtifactIdentity::normalized(path, sha256, pid, start_time)
}

fn build_report(reports: &BTreeMap<String, Value>) -> Value {
    let mut facts = BTreeMap::<String, Value>::new();
    let mut source_reports = Vec::new();

    for name in REQUIRED_INPUTS {
        let report = &reports[name];

        add_fact(
            &mut facts,
            &format!("input.{name}.success"),
            &format!("{name}.success"),
            json!(true),
        );

        source_reports.push(json!({
            "name": name,
            "collector": report.get("collector").and_then(Value::as_str),
            "success": true
        }));
    }

    let score = &reports["score"];
    let behavior = &reports["behavior"];
    let persistence = &reports["persistence"];
    let memory = &reports["memory-execution"];
    let collection = &reports["collection-integrity"];
    let observation = &reports["observation"];
    let network = &reports["network"];
    let network_deep = &reports["network-deep"];
    let kernel = &reports["kernel"];
    let security_controls = &reports["security-controls"];
    let defender_tamper = &reports["defender-tamper"];
    let remote_access = &reports["remote-access"];
    let telemetry = &reports["telemetry-integrity"];
    let execution_policy = &reports["execution-policy"];
    let identity_access = &reports["identity-access"];
    let updates = &reports["updates"];
    let admin_exposure = &reports["admin-exposure"];
    let context = &reports["context"];

    if let Some(value) = text_at(context, "/time/timezone/Id") {
        add_fact(
            &mut facts,
            "context.timezone",
            "context-posture.time.timezone.Id",
            json!(value),
        );
    }

    if let Some(value) = text_at(context, "/time/synchronization_state") {
        add_fact(
            &mut facts,
            "context.time_synchronization_state",
            "context-posture.time.synchronization_state",
            json!(value),
        );
    }

    if let Some(value) = text_at(context, "/locale/culture/Name") {
        add_fact(
            &mut facts,
            "context.culture",
            "context-posture.locale.culture.Name",
            json!(value),
        );
    }

    if let Some(value) = positive_number(context, "/network_context/public_profiles") {
        add_fact(
            &mut facts,
            "context.public_network_profiles",
            "context-posture.network_context.public_profiles",
            json!(value),
        );
    }

    if let Some(value) = positive_number(score, "/summary/high_priority") {
        add_fact(
            &mut facts,
            "score.high_priority_artifacts",
            "correlation-score.summary.high_priority",
            json!(value),
        );
    }

    if let Some(value) = positive_number(behavior, "/summary/high_priority_execution_chains") {
        add_fact(
            &mut facts,
            "behavior.high_priority_evidence",
            "behavior-hunt.summary.high_priority_execution_chains",
            json!(value),
        );
    }

    if let Some(value) = positive_number(persistence, "/summary/high_priority") {
        add_fact(
            &mut facts,
            "persistence.high_priority_evidence",
            "persistence-execution-review.summary.high_priority",
            json!(value),
        );
    }

    if let Some(value) = positive_number(memory, "/summary/high_priority_findings") {
        add_fact(
            &mut facts,
            "memory.high_priority_execution_evidence",
            "memory-execution-review.summary.high_priority_findings",
            json!(value),
        );
    }

    if let Some(value) = positive_number(network, "/summary/high_priority_connections") {
        add_fact(
            &mut facts,
            "network.high_priority_egress_evidence",
            "network-identity-review.summary.high_priority_connections",
            json!(value),
        );
    }

    if let Some(value) = positive_number(network_deep, "/summary/findings") {
        add_fact(
            &mut facts,
            "network_deep.execution_exposure_findings",
            "network-deep-review.summary.findings",
            json!(value),
        );
    }

    if let Some(value) = positive_number(network_deep, "/summary/target_open_ports") {
        add_fact(
            &mut facts,
            "network_deep.explicit_target_open_ports",
            "network-deep-review.summary.target_open_ports",
            json!(value),
        );
    }

    if text_at(network_deep, "/collection_status") == Some("partial") {
        add_fact(
            &mut facts,
            "network_deep.collection_visibility_limited",
            "network-deep-review.collection_status",
            json!("partial"),
        );
    }

    if let Some(value) = nonempty_array_count(kernel, "/artifacts") {
        add_fact(
            &mut facts,
            "kernel.findings_present",
            "kernel-runtime-integrity.artifacts",
            json!(value),
        );
    }

    if let Some(value) = positive_number(observation, "/summary/cross_source_contradictions") {
        add_fact(
            &mut facts,
            "observation.same_window_source_difference",
            "observation-integrity.summary.cross_source_contradictions",
            json!(value),
        );
    }

    if let Some(confidence) = text_at(collection, "/collection_confidence") {
        if !matches!(confidence, "complete" | "full") {
            add_fact(
                &mut facts,
                "collection.visibility_limited",
                "collection-integrity.collection_confidence",
                json!(confidence),
            );
        }
    }

    if let Some(finding) = finding_with_id(security_controls, "defender_user_writable_exclusion") {
        add_fact(
            &mut facts,
            "security.defender_user_writable_exclusion",
            "security-controls-review.findings.defender_user_writable_exclusion",
            finding,
        );
    }

    if let Some(value) = nonempty_array_count(defender_tamper, "/findings") {
        add_fact(
            &mut facts,
            "security.defender_tamper_review_findings",
            "defender-tamper-review.findings",
            json!(value),
        );
    }

    if let Some(finding) = finding_with_id(remote_access, "smb1_enabled") {
        add_fact(
            &mut facts,
            "remote.smb1_enabled",
            "remote-access-review.findings.smb1_enabled",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(remote_access, "remote_desktop_enabled") {
        let classification = finding
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("remote_access_exposure");

        let fact_id = if classification == "remote_desktop_without_nla" {
            "remote.rdp_without_nla"
        } else {
            "remote.rdp_with_nla"
        };

        add_fact(
            &mut facts,
            fact_id,
            "remote-access-review.findings.remote_desktop_enabled",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(remote_access, "smb_signing_not_required") {
        add_fact(
            &mut facts,
            "remote.smb_signing_not_required",
            "remote-access-review.findings.smb_signing_not_required",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(telemetry, "channel_disabled:Security") {
        add_fact(
            &mut facts,
            "telemetry.security_event_log_disabled",
            "telemetry-integrity-review.findings.channel_disabled:Security",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(telemetry, "windows_eventlog_service_not_running") {
        add_fact(
            &mut facts,
            "telemetry.windows_eventlog_service_not_running",
            "telemetry-integrity-review.findings.windows_eventlog_service_not_running",
            finding,
        );
    }

    if let Some(finding) =
        finding_with_id(execution_policy, "powershell_script_block_logging_disabled")
    {
        add_fact(
            &mut facts,
            "execution.powershell_script_block_logging_disabled",
            "execution-policy-review.findings.powershell_script_block_logging_disabled",
            finding,
        );
    }

    if let Some(finding) =
        finding_with_id(execution_policy, "process_command_line_auditing_disabled")
    {
        add_fact(
            &mut facts,
            "execution.process_command_line_auditing_disabled",
            "execution-policy-review.findings.process_command_line_auditing_disabled",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(identity_access, "guest_account_enabled") {
        add_fact(
            &mut facts,
            "identity.guest_account_enabled",
            "identity-access-review.findings.guest_account_enabled",
            finding,
        );
    }

    if let Some(finding) = finding_with_id(
        identity_access,
        "blank_password_network_restriction_disabled",
    ) {
        add_fact(
            &mut facts,
            "identity.blank_password_network_restriction_disabled",
            "identity-access-review.findings.blank_password_network_restriction_disabled",
            finding,
        );
    }

    let critical_pending_updates = pending_update_severity_count(updates, "critical");

    if critical_pending_updates > 0 {
        add_fact(
            &mut facts,
            "updates.critical_security_updates_pending",
            "update-exposure.pending_software_updates.severity=critical",
            json!(critical_pending_updates),
        );
    }

    if updates.pointer("/reboot/required").and_then(Value::as_bool) == Some(true) {
        add_fact(
            &mut facts,
            "updates.reboot_required",
            "update-exposure.reboot.required",
            json!(true),
        );
    }

    if text_at(updates, "/collection_status") == Some("partial") {
        add_fact(
            &mut facts,
            "updates.visibility_limited",
            "update-exposure.collection_status",
            json!("partial"),
        );
    }

    let admin_high_findings = admin_exposure
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|finding| finding.get("priority").and_then(Value::as_str) == Some("high"))
        .count();

    if admin_high_findings > 0 {
        add_fact(
            &mut facts,
            "admin.system_wide_high_exposure_findings",
            "administrator-exposure-audit.findings.priority=high",
            json!(admin_high_findings),
        );
    }

    if text_at(admin_exposure, "/collection_status") == Some("partial") {
        add_fact(
            &mut facts,
            "admin.system_wide_visibility_limited",
            "administrator-exposure-audit.collection_status",
            json!("partial"),
        );
    }

    let score_artifacts = high_priority_artifacts_by_path(score);
    let mut defender_exclusion_artifact_matches = Vec::new();

    for exclusion in security_controls
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|finding| {
            finding.get("id").and_then(Value::as_str) == Some("defender_user_writable_exclusion")
        })
    {
        let Some(exclusion_path) = exclusion.get("path").and_then(Value::as_str) else {
            continue;
        };

        for (artifact_path, artifact) in &score_artifacts {
            if path_is_within(exclusion_path, artifact_path) {
                defender_exclusion_artifact_matches.push(json!({
                    "defender_exclusion": exclusion,
                    "artifact_path": artifact_path,
                    "high_priority_artifact": artifact
                }));
            }
        }
    }

    if !defender_exclusion_artifact_matches.is_empty() {
        add_fact(
            &mut facts,
            "evidence.defender_exclusion_covers_high_priority_artifact",
            "security-controls-review.findings.defender_user_writable_exclusion.path + correlation-score.artifacts.path",
            json!({ "matches": defender_exclusion_artifact_matches }),
        );
    }

    let memory_artifacts = high_priority_artifacts_by_path(memory);
    let behavior_artifacts = high_priority_artifacts_by_path(behavior);
    let network_artifacts = high_priority_network_artifacts_by_path(network);
    let mut artifact_specific_matches = Vec::new();
    let mut artifact_identity_partial_matches = Vec::new();
    let mut artifact_identity_conflicts = Vec::new();

    for (path, memory_artifact) in memory_artifacts {
        let (Some(behavior_artifact), Some(network_artifact)) =
            (behavior_artifacts.get(&path), network_artifacts.get(&path))
        else {
            continue;
        };

        let identity_match = match_artifact_identities(&[
            artifact_identity(&memory_artifact, false),
            artifact_identity(behavior_artifact, false),
            artifact_identity(network_artifact, true),
        ]);
        let match_strength = identity_match.strength;
        let match_record = json!({
            "normalized_path": path,
            "identity_match": identity_match,
            "memory_execution": memory_artifact,
            "behavior": behavior_artifact,
            "network": network_artifact
        });

        match match_strength {
            IdentityMatchStrength::Strong => artifact_specific_matches.push(match_record),
            IdentityMatchStrength::Partial => artifact_identity_partial_matches.push(match_record),
            IdentityMatchStrength::Conflict => artifact_identity_conflicts.push(match_record),
        }
    }

    if !artifact_specific_matches.is_empty() {
        add_fact(
            &mut facts,
            "evidence.artifact_specific_memory_behavior_network_chain",
            "memory-execution-review.artifacts.path + behavior-hunt.artifacts.path + network-identity-review.artifacts.process.executable_path",
            json!({ "matches": artifact_specific_matches }),
        );
    }

    if !artifact_identity_partial_matches.is_empty() {
        add_fact(
            &mut facts,
            "evidence.artifact_path_cooccurrence_requires_identity_verification",
            "memory-execution + behavior-hunt + network-identity-review identity fields",
            json!({ "matches": artifact_identity_partial_matches }),
        );
    }

    if !artifact_identity_conflicts.is_empty() {
        add_fact(
            &mut facts,
            "integrity.artifact_identity_conflict",
            "memory-execution + behavior-hunt + network-identity-review identity fields",
            json!({ "conflicts": artifact_identity_conflicts }),
        );
    }

    let observed_fact_count = facts.len();

    let rules = [
        Rule {
            id: "validate_reasoning_inputs",
            premises: &INPUT_SUCCESS_FACTS,
            conclusion: "integrity.reasoning_inputs_verified",
            classification: "pipeline_integrity",
            confidence: "context",
            title: "Reasoning inputs verified",
            explanation: "Every required input explicitly reported success=true before AXIOS Reasoning Web used it.",
            next_check: "Use only evidence paths produced by successful collectors; do not treat this input validation as threat evidence.",
            information_gain: 1,
            collection_cost: 1,
        },
        Rule {
            id: "surface_system_wide_exposure_review",
            premises: &["admin.system_wide_high_exposure_findings"],
            conclusion: "security.system_wide_privilege_escalation_exposure_requires_review",
            classification: "privilege_escalation_exposure",
            confidence: "high",
            title: "System-wide privilege escalation exposure requires review",
            explanation: "The administrator exposure audit found one or more high-priority service, task, driver, boot, or permission exposures. This is a configuration and integrity review signal, not proof of exploitation, persistence, malware, or intrusion.",
            next_check: "Verify the exact executable, registry, task, driver, or boot evidence; confirm effective permissions and ownership; preserve evidence before approved remediation.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "review_deep_network_execution_exposure",
            premises: &["network_deep.execution_exposure_findings"],
            conclusion: "security.deep_network_execution_exposure_requires_review",
            classification: "network_execution_exposure",
            confidence: "medium",
            title: "Deep network execution evidence requires review",
            explanation: "The deep network collector correlated a user-writable executable path with a listener or public connection. This is an investigation signal, not proof of malware, intrusion, service identity, or exploitation.",
            next_check: "Verify the exact executable hash, Authenticode state, parent process, destination ownership, persistence evidence, firewall scope, and expected application behavior.",
            information_gain: 4,
            collection_cost: 2,
        },
        Rule {
            id: "record_explicit_target_reachability",
            premises: &["network_deep.explicit_target_open_ports"],
            conclusion: "network.explicit_target_reachability_observed",
            classification: "network_reachability",
            confidence: "context",
            title: "Explicit target reachability was observed",
            explanation: "A bounded user-requested TCP connection succeeded. This proves reachability only; it does not prove service identity, vulnerability, exploitation, or unauthorized access.",
            next_check: "Validate the service through an authorized protocol-aware check and compare it with the expected network inventory.",
            information_gain: 2,
            collection_cost: 2,
        },
        Rule {
            id: "record_deep_network_visibility_limit",
            premises: &["network_deep.collection_visibility_limited"],
            conclusion: "visibility.deep_network_collection_is_partial",
            classification: "visibility_limited",
            confidence: "context",
            title: "Deep network collection visibility is partial",
            explanation: "One or more network evidence sources were unavailable, denied, or truncated. Missing evidence must not be interpreted as a clean network state.",
            next_check: "Review collection_errors and truncation, then repeat with the required privilege or an independent trusted network source.",
            information_gain: 3,
            collection_cost: 1,
        },
        Rule {
            id: "derive_artifact_correlation",
            premises: &["score.high_priority_artifacts"],
            conclusion: "evidence.cross_layer_artifact_correlation",
            classification: "evidence_chain",
            confidence: "high",
            title: "Cross-layer artifact correlation exists",
            explanation: "Correlation scoring found artifact-specific evidence supported by independent layers.",
            next_check: "Inspect the exact artifact path, parent process, persistence entry, signature state, and associated network activity.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "derive_execution_chain_review",
            premises: &["evidence.cross_layer_artifact_correlation"],
            conclusion: "investigation.execution_chain_requires_verification",
            classification: "needs_review",
            confidence: "high",
            title: "Execution chain requires verification",
            explanation: "An evidence chain exists, but AXIOS requires artifact-specific runtime or memory verification before any malware or intrusion claim.",
            next_check: "Verify the artifact-specific process tree and an independent runtime or memory signal before any containment decision.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "corroborate_behavior_with_artifact_correlation",
            premises: &[
                "score.high_priority_artifacts",
                "behavior.high_priority_evidence",
            ],
            conclusion: "evidence.behavior_and_artifact_corroborated",
            classification: "evidence_chain",
            confidence: "high",
            title: "Behavior and artifact evidence are corroborated",
            explanation: "Behavioral and artifact-specific correlation both produced high-priority evidence. This is still not a malware verdict.",
            next_check: "Compare timestamps, executable paths, process identifiers, and network destinations to confirm they refer to the same chain.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "corroborate_persistence_with_artifact_correlation",
            premises: &[
                "score.high_priority_artifacts",
                "persistence.high_priority_evidence",
            ],
            conclusion: "evidence.persistence_and_artifact_corroborated",
            classification: "evidence_chain",
            confidence: "high",
            title: "Persistence and artifact evidence are corroborated",
            explanation: "Persistence execution evidence overlaps high-priority artifact correlation and requires direct path and process verification.",
            next_check: "Verify that the persistence target resolves to the same artifact and that the target was observed executing.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "derive_defender_exclusion_artifact_review",
            premises: &["evidence.defender_exclusion_covers_high_priority_artifact"],
            conclusion: "evidence.defender_exclusion_covers_high_priority_artifact_requires_urgent_review",
            classification: "detection_coverage_gap_with_artifact_evidence",
            confidence: "high",
            title: "Defender exclusion covers a high-priority artifact",
            explanation: "A user-writable Defender exclusion contains the same path as a high-priority artifact-specific correlation result. This weakens detection coverage around an artifact that already requires investigation; it is not a malware or intrusion verdict.",
            next_check: "Preserve the excluded path, artifact hash, signer state, process tree, timestamps, and any network or persistence evidence. Verify the exclusion owner and change source before changing protection settings or containing the artifact.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "derive_memory_execution_review",
            premises: &["memory.high_priority_execution_evidence"],
            conclusion: "evidence.memory_backed_execution_chain_requires_verification",
            classification: "evidence_chain",
            confidence: "high",
            title: "Memory-backed execution chain requires verification",
            explanation: "The memory review found a high-priority execution chain. That collector requires an execution-memory signal, a suspicious process, and persistence/startup or network context. This is not a malware verdict.",
            next_check: "Preserve the exact process identifier, executable path, memory-region evidence, persistence target, and network context; verify they belong to the same artifact before containment.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "derive_memory_behavior_network_exploit_review",
            premises: &["evidence.artifact_specific_memory_behavior_network_chain"],
            conclusion: "evidence.memory_behavior_network_chain_requires_urgent_verification",
            classification: "potential_exploit_behavior",
            confidence: "high",
            title: "Artifact-specific memory, behavior, and network chain requires urgent verification",
            explanation: "The same normalized executable path appears in high-priority memory execution, behavioral execution, and suspicious public network evidence. This is a strong investigation signal, not a malware, intrusion, or zero-day verdict.",
            next_check: "Preserve the exact process identifiers, executable paths, memory-region evidence, timestamps, persistence/startup context, and remote endpoints; verify they describe the same artifact using an independent source before containment.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "review_partial_artifact_identity",
            premises: &["evidence.artifact_path_cooccurrence_requires_identity_verification"],
            conclusion: "investigation.artifact_path_identity_requires_verification",
            classification: "identity_verification_required",
            confidence: "medium",
            title: "Cross-layer artifact path requires identity verification",
            explanation: "The same normalized path appears across memory, behavior, and network evidence, but hash or process-instance identity is incomplete. Path reuse or file replacement remains possible.",
            next_check: "Collect and compare SHA-256, process start time, PID, and signer identity before treating the observations as one execution chain.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "surface_artifact_identity_conflict",
            premises: &["integrity.artifact_identity_conflict"],
            conclusion: "integrity.conflicting_artifact_identity_requires_review",
            classification: "identity_conflict",
            confidence: "high",
            title: "Cross-layer artifact identity conflict requires review",
            explanation: "Evidence sources reported the same path with conflicting file hashes or incompatible identity values. AXIOS did not merge them into one artifact.",
            next_check: "Preserve each source record and compare collection time, SHA-256, process start time, signer, and file replacement history.",
            information_gain: 5,
            collection_cost: 2,
        },
        Rule {
            id: "surface_critical_pending_updates",
            premises: &["updates.critical_security_updates_pending"],
            conclusion: "security.critical_windows_updates_pending_requires_review",
            classification: "critical_security_updates_pending",
            confidence: "high",
            title: "Critical Windows security updates are pending",
            explanation: "Windows Update reported one or more pending updates with severity Critical. This is a patch exposure that requires maintenance review; AXIOS does not infer a specific CVE, exploit, intrusion, or zero-day from this state.",
            next_check: "Record the KB identifiers and update titles, verify applicability and maintenance ownership, then install the approved updates through the normal Windows servicing process.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_pending_reboot_after_servicing",
            premises: &["updates.reboot_required"],
            conclusion: "security.windows_servicing_reboot_required_requires_review",
            classification: "servicing_completion_required",
            confidence: "medium",
            title: "Windows servicing restart is required",
            explanation: "Windows reports a pending servicing restart. This can leave installed updates or system changes incomplete, but does not prove compromise.",
            next_check: "Review the reported reboot reasons, confirm an approved maintenance window, and restart the device when it is safe to complete servicing.",
            information_gain: 3,
            collection_cost: 1,
        },
        Rule {
            id: "surface_update_collection_visibility_limit",
            premises: &["updates.visibility_limited"],
            conclusion: "integrity.windows_update_visibility_limited_requires_review",
            classification: "visibility_limited",
            confidence: "context",
            title: "Windows Update visibility is limited",
            explanation: "The Windows Update collector completed only partially. Missing update data is not evidence that the system is current.",
            next_check: "Review the collection error and independently verify pending updates before treating update exposure as known.",
            information_gain: 3,
            collection_cost: 1,
        },
        Rule {
            id: "derive_kernel_review",
            premises: &["kernel.findings_present"],
            conclusion: "investigation.kernel_or_boot_posture_requires_review",
            classification: "needs_review",
            confidence: "medium",
            title: "Kernel or boot posture requires review",
            explanation: "Kernel findings can be policy or configuration related. They require signed-driver, boot-chain, and firmware evidence correlation.",
            next_check: "Review affected driver paths, signatures, boot evidence, firmware identity, and any collection limitations.",
            information_gain: 4,
            collection_cost: 3,
        },
        Rule {
            id: "derive_limited_visibility_artifact_chain_review",
            premises: &[
                "evidence.artifact_specific_memory_behavior_network_chain",
                "collection.visibility_limited",
            ],
            conclusion: "integrity.artifact_specific_exploit_evidence_with_limited_visibility_requires_independent_verification",
            classification: "limited_visibility_with_artifact_evidence",
            confidence: "high",
            title: "Artifact-specific execution evidence requires independent verification",
            explanation: "The same artifact has high-priority memory, behavioral, and network evidence, while one or more collection sources have limited visibility. Local evidence is strong enough for urgent preservation and verification, but not for a malware, intrusion, or zero-day claim.",
            next_check: "Preserve the artifact path, hash, process identifiers, memory-region metadata, and network endpoints. Obtain an independent source such as protected endpoint telemetry, offline evidence collection, or a trusted external scanner before containment.",
            information_gain: 5,
            collection_cost: 3,
        },
        Rule {
            id: "surface_visibility_limit",
            premises: &["collection.visibility_limited"],
            conclusion: "integrity.visibility_limit_requires_caution",
            classification: "visibility_limitation",
            confidence: "medium",
            title: "Collection visibility is limited",
            explanation: "One or more evidence sources were incomplete or constrained. AXIOS must not interpret this as clean, malware, or intrusion proof.",
            next_check: "Review the affected collector limitations and obtain an independent source only where it would materially change the conclusion.",
            information_gain: 4,
            collection_cost: 1,
        },
        Rule {
            id: "surface_same_window_difference",
            premises: &["observation.same_window_source_difference"],
            conclusion: "integrity.independent_source_difference_observed",
            classification: "visibility_context",
            confidence: "medium",
            title: "Independent process sources differ",
            explanation: "CIM and .NET observations differed in the same collection window. This is a visibility and timing signal, not malware proof.",
            next_check: "Preserve the source difference and correlate it with timing, permissions, and repeated same-window observations.",
            information_gain: 3,
            collection_cost: 1,
        },
        Rule {
            id: "surface_smb1_exposure",
            premises: &["remote.smb1_enabled"],
            conclusion: "security.smb1_enabled_requires_review",
            classification: "legacy_network_protocol_enabled",
            confidence: "high",
            title: "SMBv1 is enabled",
            explanation: "SMBv1 is a legacy protocol with a materially larger attack surface. Its presence is a configuration exposure, not proof of intrusion.",
            next_check: "Confirm whether SMBv1 is required, identify affected systems and firewall exposure, then plan a controlled disablement if it is not required.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_rdp_without_nla",
            premises: &["remote.rdp_without_nla"],
            conclusion: "security.rdp_without_nla_requires_review",
            classification: "remote_desktop_without_nla",
            confidence: "high",
            title: "Remote Desktop is enabled without Network Level Authentication",
            explanation: "RDP without NLA increases remote access exposure. This is not proof that the system was accessed or compromised.",
            next_check: "Confirm the listener and firewall scope, identify authorized users, then require NLA or disable RDP where it is unnecessary.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_rdp_with_nla",
            premises: &["remote.rdp_with_nla"],
            conclusion: "security.rdp_enabled_requires_exposure_review",
            classification: "remote_access_exposure",
            confidence: "medium",
            title: "Remote Desktop is enabled",
            explanation: "RDP is enabled with NLA. It requires exposure and authorization review, but is not an intrusion claim.",
            next_check: "Review firewall scope, authorized RDP users, sign-in evidence, and whether the service is required for this device.",
            information_gain: 4,
            collection_cost: 1,
        },
        Rule {
            id: "surface_guest_account_enabled",
            premises: &["identity.guest_account_enabled"],
            conclusion: "security.guest_account_enabled_requires_review",
            classification: "local_account_exposure",
            confidence: "high",
            title: "Built-in Guest account is enabled",
            explanation: "The built-in Guest account is enabled. This increases local account exposure but does not prove unauthorized access.",
            next_check: "Verify whether the account is required, review recent sign-in evidence and local policy ownership, then disable it if it has no approved use.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_blank_password_network_restriction_disabled",
            premises: &["identity.blank_password_network_restriction_disabled"],
            conclusion: "security.blank_password_network_restriction_disabled_requires_review",
            classification: "credential_control_disabled",
            confidence: "high",
            title: "Blank-password network restriction is disabled",
            explanation: "Local accounts with blank passwords are not restricted to console logon by observed configuration. This is an exposure, not evidence of compromise.",
            next_check: "Verify account policy ownership, identify affected local accounts, and restore the network restriction where it is appropriate.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_powershell_script_block_logging_disabled",
            premises: &["execution.powershell_script_block_logging_disabled"],
            conclusion: "integrity.powershell_script_block_logging_disabled_requires_review",
            classification: "execution_visibility_gap",
            confidence: "medium",
            title: "PowerShell Script Block Logging is disabled",
            explanation: "PowerShell Script Block Logging is explicitly disabled. This reduces script execution visibility but does not prove tampering or malicious activity.",
            next_check: "Verify the effective policy, Group Policy ownership, change source, and independent endpoint telemetry before restoring the required logging setting.",
            information_gain: 4,
            collection_cost: 1,
        },
        Rule {
            id: "surface_process_command_line_auditing_disabled",
            premises: &["execution.process_command_line_auditing_disabled"],
            conclusion: "integrity.process_command_line_auditing_disabled_requires_review",
            classification: "execution_visibility_gap",
            confidence: "medium",
            title: "Process command-line auditing is disabled",
            explanation: "Process command-line auditing is explicitly disabled. This reduces investigation context but does not prove an attacker changed the setting.",
            next_check: "Verify the effective audit policy, policy owner, change history, and independent process telemetry before restoring the expected audit setting.",
            information_gain: 4,
            collection_cost: 1,
        },
        Rule {
            id: "surface_security_event_log_disabled",
            premises: &["telemetry.security_event_log_disabled"],
            conclusion: "integrity.security_event_log_disabled_requires_review",
            classification: "visibility_failure",
            confidence: "high",
            title: "Windows Security event logging is disabled",
            explanation: "The Security event channel is explicitly disabled. This materially reduces local investigation visibility, but does not itself prove log tampering or intrusion.",
            next_check: "Verify the effective audit policy, Event Log channel configuration, change source, and any independent security telemetry before restoring the required logging configuration.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_eventlog_service_not_running",
            premises: &["telemetry.windows_eventlog_service_not_running"],
            conclusion: "integrity.windows_eventlog_service_not_running_requires_review",
            classification: "visibility_failure",
            confidence: "high",
            title: "Windows Event Log service is not running",
            explanation: "The Windows Event Log service is not running, which materially reduces event visibility. This is not proof of attacker activity.",
            next_check: "Verify service configuration, recent service-control events, policy ownership, and independent telemetry before restoring the expected service state.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_smb_signing_gap",
            premises: &["remote.smb_signing_not_required"],
            conclusion: "security.smb_signing_not_required_requires_review",
            classification: "smb_integrity_control_weakened",
            confidence: "medium",
            title: "SMB signing is not required",
            explanation: "SMB signing is not required on one or more observed sides. This weakens integrity protections but does not prove interception, lateral movement, or intrusion.",
            next_check: "Confirm the affected client and server sides, identify systems that require legacy compatibility, then plan a controlled policy change to require SMB signing where supported.",
            information_gain: 4,
            collection_cost: 1,
        },
        Rule {
            id: "surface_defender_user_writable_exclusion",
            premises: &["security.defender_user_writable_exclusion"],
            conclusion: "security.defender_user_writable_exclusion_requires_review",
            classification: "security_weakening",
            confidence: "high",
            title: "Defender excludes a user-writable location",
            explanation: "A Defender exclusion covers a location writable by a standard user. This weakens detection coverage but does not itself prove malware or intrusion.",
            next_check: "Review the exact excluded path, its owner, recent writes, and the change source before changing the exclusion.",
            information_gain: 5,
            collection_cost: 1,
        },
        Rule {
            id: "surface_defender_tamper_review",
            premises: &["security.defender_tamper_review_findings"],
            conclusion: "security.defender_configuration_requires_review",
            classification: "security_weakening",
            confidence: "medium",
            title: "Defender configuration changes require review",
            explanation: "Defender evidence contains configuration-related findings. They require evidence review and are not, by themselves, tampering or intrusion proof.",
            next_check: "Review the specific Defender evidence, change times, and responsible configuration source before any remediation.",
            information_gain: 4,
            collection_cost: 1,
        },
    ];

    let mut applied = BTreeSet::new();
    let mut conclusions = Vec::new();
    let mut plan = Vec::new();
    let mut inference_passes = 0usize;

    loop {
        let mut changed = false;

        for rule in &rules {
            if applied.contains(rule.id)
                || !rule
                    .premises
                    .iter()
                    .all(|premise| facts.contains_key(*premise))
            {
                continue;
            }

            let evidence_paths = rule
                .premises
                .iter()
                .map(|premise| (*premise).to_string())
                .collect::<Vec<_>>();

            facts.insert(
                rule.conclusion.to_string(),
                json!({
                    "kind": "derived",
                    "rule_id": rule.id,
                    "evidence_paths": evidence_paths
                }),
            );

            let score = plan_score(rule);

            conclusions.push(json!({
                "id": rule.conclusion,
                "rule_id": rule.id,
                "classification": rule.classification,
                "confidence": rule.confidence,
                "title": rule.title,
                "evidence_paths": rule.premises,
                "explanation": rule.explanation
            }));

            plan.push(json!({
                "triggered_by": rule.conclusion,
                "priority": priority(score),
                "priority_score": score,
                "expected_information_gain": rule.information_gain,
                "estimated_collection_cost": rule.collection_cost,
                "action": rule.next_check,
                "automatic_remediation": false
            }));

            applied.insert(rule.id);
            changed = true;
        }

        if !changed {
            break;
        }

        inference_passes += 1;
        if inference_passes >= rules.len() {
            break;
        }
    }

    conclusions.sort_by(|left, right| {
        confidence_rank(right["confidence"].as_str().unwrap_or("context"))
            .cmp(&confidence_rank(
                left["confidence"].as_str().unwrap_or("context"),
            ))
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });

    plan.sort_by(|left, right| {
        right["priority_score"]
            .as_u64()
            .cmp(&left["priority_score"].as_u64())
            .then_with(|| {
                left["triggered_by"]
                    .as_str()
                    .cmp(&right["triggered_by"].as_str())
            })
    });

    let branch_evaluation = evaluate_hypotheses(
        hypothesis_inputs(&conclusions),
        InferenceLimits::default().max_branches,
    );
    let active_branches = branch_evaluation
        .branches
        .iter()
        .filter(|branch| branch.state == BranchState::Active)
        .cloned()
        .collect::<Vec<_>>();
    let leading_hypothesis = active_branches.first().cloned();
    let alternative_hypotheses = active_branches.iter().skip(1).cloned().collect::<Vec<_>>();
    let limits = InferenceLimits::default();
    let proof_traces = build_proof_traces(&active_branches, limits.max_proof_depth);
    let next_best_checks = rank_checks(planner_checks(&plan, &active_branches), 5);

    json!({
        "schema_version": 1,
        "collector": "axios_reasoning_web",
        "success": true,
        "read_only": true,
        "database_used": false,
        "machine_learning_used": false,
        "persistent_state_used": false,
        "method": {
            "fact_normalization": "successful AXIOS reports are converted to traceable facts",
            "inference": "bounded forward chaining with rule prerequisites",
            "contradictions": "visibility and source differences remain context, not compromise proof",
            "planner": "expected information gain divided by estimated collection cost",
            "pipeline_integrity": "every required input must explicitly declare success=true"
        },
        "summary": {
            "input_reports_verified": source_reports.len(),
            "observed_facts": observed_fact_count,
            "total_facts": facts.len(),
            "derived_conclusions": conclusions.len(),
            "planned_checks": plan.len(),
            "inference_passes": inference_passes
        },
        "intelligence": {
            "engine": "deterministic_symbolic_reasoning",
            "branches_created": branch_evaluation.branches_created,
            "branches_merged": branch_evaluation.branches_merged,
            "branches_retained": branch_evaluation.branches_retained,
            "branches_pruned": branch_evaluation.branches_pruned,
            "stability_reached": inference_passes < rules.len(),
            "inference_passes": inference_passes
        },
        "leading_hypothesis": leading_hypothesis,
        "alternative_hypotheses": alternative_hypotheses,
        "proof_traces": proof_traces,
        "next_best_checks": next_best_checks,
        "source_reports": source_reports,
        "facts": facts.into_iter().map(|(id, detail)| {
            json!({ "id": id, "detail": detail })
        }).collect::<Vec<_>>(),
        "conclusions": conclusions,
        "investigation_plan": plan,
        "claim_policy": {
            "malware_confirmed": false,
            "intrusion_confirmed": false,
            "zero_day_confirmed": false,
            "automatic_remediation": false,
            "artifact_specific_evidence_required": true,
            "limited_visibility_is_not_clean": true
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn successful_reports() -> BTreeMap<String, Value> {
        REQUIRED_INPUTS
            .iter()
            .map(|name| {
                (
                    (*name).to_string(),
                    json!({
                        "success": true,
                        "collector": format!("test_{name}")
                    }),
                )
            })
            .collect()
    }

    fn strong_process_identity(path: &str, pid: u32) -> Value {
        json!({
            "pid": pid,
            "start_time": "20260915010101.000000+000",
            "normalized_path": normalize_artifact_path(path),
            "sha256": "aabbcc",
            "identity_quality": "strong"
        })
    }

    #[test]
    fn duplicate_input_is_rejected() {
        let result = options_from([
            "--summary",
            "one.json",
            "--summary",
            "two.json",
            "--score",
            "score.json",
            "--behavior",
            "behavior.json",
            "--persistence",
            "persistence.json",
            "--collection-integrity",
            "collection.json",
            "--observation",
            "observation.json",
            "--network",
            "network.json",
            "--kernel",
            "kernel.json",
            "--state",
            "state.json",
            "--security-controls",
            "security.json",
            "--defender-tamper",
            "defender-tamper.json",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn reasoning_web_chains_artifact_evidence_and_plans_verification() {
        let mut reports = successful_reports();
        reports.insert(
            "score".to_string(),
            json!({"success": true, "summary": {"high_priority": 1}}),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert!(conclusions.iter().any(|item| {
            item["id"].as_str() == Some("investigation.execution_chain_requires_verification")
        }));
        assert_eq!(report["database_used"], false);
        assert_eq!(report["machine_learning_used"], false);
        assert!(report["investigation_plan"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["priority_score"].as_u64().unwrap_or(0) > 0));
    }

    #[test]
    fn visibility_limits_are_not_clean_or_malware_claims() {
        let mut reports = successful_reports();
        reports.insert(
            "collection-integrity".to_string(),
            json!({
                "success": true,
                "collection_confidence": "partial"
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert!(conclusions.iter().any(|item| {
            item["id"].as_str() == Some("integrity.visibility_limit_requires_caution")
        }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
    }

    #[test]
    fn high_priority_memory_execution_requires_artifact_verification() {
        let mut reports = successful_reports();
        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_findings": 1 }
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(conclusions.iter().any(|item| {
            item["id"].as_str()
                == Some("evidence.memory_backed_execution_chain_requires_verification")
                && item["confidence"].as_str() == Some("high")
        }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
    }

    #[test]
    fn remote_access_findings_become_proportionate_security_reviews() {
        let mut reports = successful_reports();
        reports.insert(
            "remote-access".to_string(),
            json!({
                "success": true,
                "findings": [
                    { "id": "smb1_enabled", "priority": "high" },
                    {
                        "id": "remote_desktop_enabled",
                        "classification": "remote_desktop_without_nla",
                        "priority": "high"
                    }
                ]
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(conclusions.iter().any(|item| {
            item["id"].as_str() == Some("security.smb1_enabled_requires_review")
                && item["confidence"].as_str() == Some("high")
        }));
        assert!(conclusions.iter().any(|item| {
            item["id"].as_str() == Some("security.rdp_without_nla_requires_review")
                && item["confidence"].as_str() == Some("high")
        }));
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn defender_exclusion_covering_high_priority_artifact_requires_urgent_review() {
        let path = r"C:\Users\Test\AppData\Local\Temp\files\loader.exe";
        let mut reports = successful_reports();

        reports.insert(
            "score".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority": 1 },
                "artifacts": [{
                    "priority": "high",
                    "path": path,
                    "evidence": {
                        "artifact_specific_suspicious_evidence": true
                    }
                }]
            }),
        );
        reports.insert(
            "security-controls".to_string(),
            json!({
                "success": true,
                "findings": [{
                    "id": "defender_user_writable_exclusion",
                    "priority": "high",
                    "path": r"C:\Users\Test\AppData\Local\Temp\files"
                }]
            }),
        );

        let report = build_report(&reports);

        assert!(report["conclusions"].as_array().unwrap().iter().any(|item| {
            item["id"].as_str()
                == Some("evidence.defender_exclusion_covers_high_priority_artifact_requires_urgent_review")
                && item["confidence"].as_str() == Some("high")
        }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn defender_exclusion_boundary_does_not_match_similar_path() {
        let mut reports = successful_reports();

        reports.insert(
            "score".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority": 1 },
                "artifacts": [{
                    "priority": "high",
                    "path": r"C:\Users\Test\AppData\Local\Tempest\loader.exe"
                }]
            }),
        );
        reports.insert(
            "security-controls".to_string(),
            json!({
                "success": true,
                "findings": [{
                    "id": "defender_user_writable_exclusion",
                    "priority": "high",
                    "path": r"C:\Users\Test\AppData\Local\Temp"
                }]
            }),
        );

        let report = build_report(&reports);

        assert!(!report["conclusions"].as_array().unwrap().iter().any(|item| {
            item["id"].as_str()
                == Some("evidence.defender_exclusion_covers_high_priority_artifact_requires_urgent_review")
        }));
    }

    #[test]
    fn artifact_specific_chain_with_limited_visibility_requires_independent_verification() {
        let path = r"C:\Users\Test\AppData\Local\Temp\sample.exe";
        let mut reports = successful_reports();

        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_findings": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 4242,
                    "path": path,
                    "sha256": "aabbcc",
                    "identity": strong_process_identity(path, 4242)
                }]
            }),
        );
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_execution_chains": 1 },
                "artifacts": [{
                    "priority": "high",
                    "path": path,
                    "sha256": "aabbcc"
                }]
            }),
        );
        reports.insert(
            "network".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_connections": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 4242,
                    "remote_address": "1.1.1.1",
                    "identity": strong_process_identity(path, 4242),
                    "process": {
                        "executable_path": path,
                        "sha256": "aabbcc",
                        "creation_date": "20260915010101.000000+000"
                    }
                }]
            }),
        );
        reports.insert(
            "collection-integrity".to_string(),
            json!({
                "success": true,
                "collection_confidence": "partial"
            }),
        );

        let report = build_report(&reports);

        assert!(report["conclusions"].as_array().unwrap().iter().any(|item| {
            item["id"].as_str()
                == Some("integrity.artifact_specific_exploit_evidence_with_limited_visibility_requires_independent_verification")
                && item["confidence"].as_str() == Some("high")
        }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
        assert_eq!(report["claim_policy"]["zero_day_confirmed"], false);
    }

    #[test]
    fn critical_pending_updates_and_reboot_require_proportionate_reviews() {
        let mut reports = successful_reports();
        reports.insert(
            "updates".to_string(),
            json!({
                "success": true,
                "reboot": {
                    "required": true,
                    "reasons": ["windows_update"]
                },
                "pending_software_updates": [{
                    "title": "Security Update for Windows",
                    "kb_articles": ["9999999"],
                    "severity": "Critical",
                    "mandatory": true
                }]
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(conclusions.iter().any(|item| {
            item["id"].as_str() == Some("security.critical_windows_updates_pending_requires_review")
                && item["confidence"].as_str() == Some("high")
        }));
        assert!(conclusions.iter().any(|item| {
            item["id"].as_str()
                == Some("security.windows_servicing_reboot_required_requires_review")
                && item["confidence"].as_str() == Some("medium")
        }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["zero_day_confirmed"], false);
    }

    #[test]
    fn memory_behavior_and_network_chain_requires_urgent_verification() {
        let path = r"C:\Users\Test\AppData\Local\Temp\sample.exe";
        let mut reports = successful_reports();

        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_findings": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 4242,
                    "path": path,
                    "sha256": "aabbcc",
                    "identity": strong_process_identity(path, 4242)
                }]
            }),
        );
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_execution_chains": 1 },
                "artifacts": [{
                    "priority": "high",
                    "path": path,
                    "sha256": "aabbcc"
                }]
            }),
        );
        reports.insert(
            "network".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_connections": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 4242,
                    "remote_address": "1.1.1.1",
                    "identity": strong_process_identity(path, 4242),
                    "process": {
                        "executable_path": path,
                        "sha256": "aabbcc",
                        "creation_date": "20260915010101.000000+000"
                    }
                }]
            }),
        );

        let report = build_report(&reports);

        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("evidence.memory_behavior_network_chain_requires_urgent_verification")
            }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["zero_day_confirmed"], false);
    }

    #[test]
    fn mismatched_high_priority_artifacts_do_not_trigger_exploit_chain() {
        let mut reports = successful_reports();

        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_findings": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 4242,
                    "path": r"C:\Users\Test\AppData\Local\Temp\memory.exe"
                }]
            }),
        );
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_execution_chains": 1 },
                "artifacts": [{
                    "priority": "high",
                    "path": r"C:\Users\Test\AppData\Local\Temp\behavior.exe"
                }]
            }),
        );
        reports.insert(
            "network".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_connections": 1 },
                "artifacts": [{
                    "priority": "high",
                    "pid": 9999,
                    "remote_address": "1.1.1.1",
                    "process": {
                        "executable_path": r"C:\Users\Test\AppData\Local\Temp\network.exe"
                    }
                }]
            }),
        );

        let report = build_report(&reports);

        assert!(!report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("evidence.memory_behavior_network_chain_requires_urgent_verification")
            }));
    }

    #[test]
    fn path_only_cooccurrence_requires_identity_verification() {
        let path = r"C:\Users\Test\AppData\Local\Temp\sample.exe";
        let mut reports = successful_reports();

        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "artifacts": [{"priority": "high", "pid": 42, "path": path}]
            }),
        );
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "artifacts": [{"priority": "high", "path": path}]
            }),
        );
        reports.insert(
            "network".to_string(),
            json!({
                "success": true,
                "artifacts": [{
                    "priority": "high",
                    "pid": 42,
                    "process": {"executable_path": path}
                }]
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert!(conclusions.iter().any(|item| {
            item["id"] == "investigation.artifact_path_identity_requires_verification"
                && item["confidence"] == "medium"
        }));
        assert!(!conclusions.iter().any(|item| {
            item["id"] == "evidence.memory_behavior_network_chain_requires_urgent_verification"
        }));
    }

    #[test]
    fn conflicting_hashes_are_not_merged_into_one_execution_chain() {
        let path = r"C:\Users\Test\AppData\Local\Temp\sample.exe";
        let mut reports = successful_reports();

        reports.insert(
            "memory-execution".to_string(),
            json!({
                "success": true,
                "artifacts": [{
                    "priority": "high",
                    "pid": 42,
                    "path": path,
                    "sha256": "aaaa",
                    "identity": {
                        "pid": 42,
                        "start_time": "100",
                        "normalized_path": path,
                        "sha256": "aaaa"
                    }
                }]
            }),
        );
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "artifacts": [{"priority": "high", "path": path, "sha256": "bbbb"}]
            }),
        );
        reports.insert(
            "network".to_string(),
            json!({
                "success": true,
                "artifacts": [{
                    "priority": "high",
                    "pid": 42,
                    "identity": {
                        "pid": 42,
                        "start_time": "100",
                        "normalized_path": path,
                        "sha256": "aaaa"
                    },
                    "process": {"executable_path": path, "sha256": "aaaa"}
                }]
            }),
        );

        let report = build_report(&reports);
        let conclusions = report["conclusions"].as_array().unwrap();

        assert!(conclusions
            .iter()
            .any(|item| item["id"] == "integrity.conflicting_artifact_identity_requires_review"));
        assert!(!conclusions.iter().any(|item| {
            item["id"] == "evidence.memory_behavior_network_chain_requires_urgent_verification"
        }));
    }

    #[test]
    fn behavior_high_priority_execution_chains_becomes_traceable_fact() {
        let mut reports = successful_reports();
        reports.insert(
            "behavior".to_string(),
            json!({
                "success": true,
                "summary": { "high_priority_execution_chains": 1 }
            }),
        );

        let report = build_report(&reports);
        let facts = report["facts"].as_array().expect("facts must be an array");

        assert!(facts
            .iter()
            .any(|item| { item["id"].as_str() == Some("behavior.high_priority_evidence") }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["zero_day_confirmed"], false);
    }

    #[test]
    fn identity_exposures_become_high_security_reviews() {
        let mut reports = successful_reports();
        reports.insert(
            "identity-access".to_string(),
            json!({
                "success": true,
                "findings": [
                    { "id": "guest_account_enabled", "priority": "high" },
                    { "id": "blank_password_network_restriction_disabled", "priority": "high" }
                ]
            }),
        );

        let report = build_report(&reports);
        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str() == Some("security.guest_account_enabled_requires_review")
                    && item["confidence"].as_str() == Some("high")
            }));
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("security.blank_password_network_restriction_disabled_requires_review")
                    && item["confidence"].as_str() == Some("high")
            }));
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn execution_visibility_gaps_become_medium_reviews() {
        let mut reports = successful_reports();
        reports.insert(
            "execution-policy".to_string(),
            json!({
                "success": true,
                "findings": [
                    { "id": "powershell_script_block_logging_disabled", "priority": "medium" },
                    { "id": "process_command_line_auditing_disabled", "priority": "medium" }
                ]
            }),
        );

        let report = build_report(&reports);
        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("integrity.powershell_script_block_logging_disabled_requires_review")
                    && item["confidence"].as_str() == Some("medium")
            }));
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("integrity.process_command_line_auditing_disabled_requires_review")
                    && item["confidence"].as_str() == Some("medium")
            }));
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn disabled_security_log_becomes_a_high_visibility_review() {
        let mut reports = successful_reports();
        reports.insert(
            "telemetry-integrity".to_string(),
            json!({
                "success": true,
                "findings": [{
                    "id": "channel_disabled:Security",
                    "priority": "high"
                }]
            }),
        );

        let report = build_report(&reports);
        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str() == Some("integrity.security_event_log_disabled_requires_review")
                    && item["confidence"].as_str() == Some("high")
            }));
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn smb_signing_gap_becomes_a_medium_security_review() {
        let mut reports = successful_reports();
        reports.insert(
            "remote-access".to_string(),
            json!({
                "success": true,
                "findings": [{
                    "id": "smb_signing_not_required",
                    "affected_sides": ["server", "client"],
                    "priority": "medium"
                }]
            }),
        );

        let report = build_report(&reports);
        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str() == Some("security.smb_signing_not_required_requires_review")
                    && item["confidence"].as_str() == Some("medium")
            }));
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }

    #[test]
    fn defender_user_writable_exclusion_becomes_a_high_security_review() {
        let mut reports = successful_reports();
        reports.insert(
            "security-controls".to_string(),
            json!({
                "success": true,
                "findings": [{
                    "id": "defender_user_writable_exclusion",
                    "path": r"C:\\Users\\Test\\AppData\\Local\\Temp",
                    "priority": "high"
                }]
            }),
        );

        let report = build_report(&reports);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("security.defender_user_writable_exclusion_requires_review")
                    && item["confidence"].as_str() == Some("high")
            }));
    }

    #[test]
    fn administrator_exposure_findings_become_high_security_reviews() {
        let mut reports = successful_reports();

        reports.insert(
            "admin-exposure".to_string(),
            json!({
                "success": true,
                "collection_status": "complete",
                "findings": [{
                    "priority": "high",
                    "classification": "privilege_escalation_exposure",
                    "title": "System service has a potentially broad write permission"
                }]
            }),
        );

        let report = build_report(&reports);

        assert_eq!(report["summary"]["input_reports_verified"], 20);
        assert!(report["conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["id"].as_str()
                    == Some("security.system_wide_privilege_escalation_exposure_requires_review")
                    && item["confidence"].as_str() == Some("high")
            }));
        assert_eq!(report["claim_policy"]["malware_confirmed"], false);
        assert_eq!(report["claim_policy"]["intrusion_confirmed"], false);
    }
}
