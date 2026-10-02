use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use chrono::Utc;
use serde::{Deserialize, Serialize};

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn delta(current: &Counts, previous: &Counts) -> CountsDelta {
    CountsDelta {
        needs_review: current.needs_review as i64 - previous.needs_review as i64,
        unknown: current.unknown as i64 - previous.unknown as i64,
        signed: current.signed as i64 - previous.signed as i64,
        errors: current.errors as i64 - previous.errors as i64,
        correlated_artifacts: current.correlated_artifacts as i64
            - previous.correlated_artifacts as i64,
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .with_context(|| format!("Could not read report for hashing: {}", path.display()))?;

    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
struct Options {
    summary: PathBuf,
    audit: PathBuf,
    applications: PathBuf,
    correlation: PathBuf,
    state_dir: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Counts {
    needs_review: u64,
    unknown: u64,
    signed: u64,
    errors: u64,
    correlated_artifacts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrackedFinding {
    id: String,
    #[serde(default)]
    group_key: String,
    path: String,
    classification: String,
    signature_status: String,
    #[serde(default)]
    artifact_count: usize,
    signals: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredInvestigation {
    schema_version: u32,
    collector: String,
    run_id: String,
    recorded_at: String,
    source_files: BTreeMap<String, String>,
    source_sha256: BTreeMap<String, String>,
    counts: Counts,
    #[serde(default)]
    findings: Vec<TrackedFinding>,
}

#[derive(Debug, Serialize)]
struct StateReport {
    schema_version: u32,
    collector: &'static str,
    success: bool,
    run_id: String,
    state_directory: String,
    stored_record: String,
    previous_run_id: Option<String>,
    counts: Counts,
    delta_from_previous: CountsDelta,
    finding_changes: FindingChanges,
}

#[derive(Debug, Serialize)]
struct CountsDelta {
    needs_review: i64,
    unknown: i64,
    signed: i64,
    errors: i64,
    correlated_artifacts: i64,
}

#[derive(Debug, Serialize)]
struct FindingChanges {
    tracked_findings: usize,
    new_findings: usize,
    resolved_findings: usize,
    unchanged_findings: usize,
    new_samples: Vec<TrackedFinding>,
    resolved_samples: Vec<TrackedFinding>,
}

fn main() -> Result<()> {
    let Some(options) = parse_options(env::args().skip(1))? else {
        print_usage();
        return Ok(());
    };

    let summary = json_file::read_value(&options.summary)?;
    let audit = json_file::read_value(&options.audit)?;
    let applications = json_file::read_value(&options.applications)?;
    let correlation = json_file::read_value(&options.correlation)?;

    validate_report(&summary, "summary")?;
    validate_report(&audit, "audit")?;
    validate_report(&applications, "applications")?;
    validate_report(&correlation, "correlation")?;

    fs::create_dir_all(&options.state_dir).with_context(|| {
        format!(
            "Could not create investigation state directory: {}",
            options.state_dir.display()
        )
    })?;

    let previous = json_file::read_value(options.state_dir.join("latest.json"))
        .ok()
        .and_then(|value| serde_json::from_value::<StoredInvestigation>(value).ok());

    let run_id = summary_run_id(&summary)?;
    let recorded_at = Utc::now();

    let source_files = BTreeMap::from([
        ("summary".to_string(), options.summary.display().to_string()),
        ("audit".to_string(), options.audit.display().to_string()),
        (
            "applications".to_string(),
            options.applications.display().to_string(),
        ),
        (
            "correlation".to_string(),
            options.correlation.display().to_string(),
        ),
    ]);

    let source_sha256 = BTreeMap::from([
        ("summary".to_string(), sha256_file(&options.summary)?),
        ("audit".to_string(), sha256_file(&options.audit)?),
        (
            "applications".to_string(),
            sha256_file(&options.applications)?,
        ),
        (
            "correlation".to_string(),
            sha256_file(&options.correlation)?,
        ),
    ]);

    let counts = collect_counts(&audit, &applications, &correlation);
    let findings = collect_findings(&audit, &correlation);
    let previous_counts = previous
        .as_ref()
        .map(|record| record.counts.clone())
        .unwrap_or_default();
    let finding_changes = compare_findings(
        &findings,
        previous
            .as_ref()
            .map(|record| record.findings.as_slice())
            .unwrap_or_default(),
    );

    let record = StoredInvestigation {
        schema_version: 2,
        collector: "axios_investigation_state".to_string(),
        run_id: run_id.clone(),
        recorded_at: recorded_at.to_rfc3339(),
        source_files,
        source_sha256,
        counts: counts.clone(),
        findings,
    };

    let record_path = options.state_dir.join(format!("{run_id}.json"));
    json_file::write_pretty(&record_path, &record)?;
    json_file::write_pretty(options.state_dir.join("latest.json"), &record)?;

    let report = StateReport {
        schema_version: 2,
        collector: "axios_investigation_state",
        success: true,
        run_id,
        state_directory: options.state_dir.display().to_string(),
        stored_record: record_path.display().to_string(),
        previous_run_id: previous.map(|record| record.run_id),
        counts: counts.clone(),
        delta_from_previous: delta(&counts, &previous_counts),
        finding_changes,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
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
            "--summary" | "--audit" | "--applications" | "--correlation" | "--state-dir" => {
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
        summary: required("--summary")?,
        audit: required("--audit")?,
        applications: required("--applications")?,
        correlation: required("--correlation")?,
        state_dir: values
            .remove("--state-dir")
            .unwrap_or_else(default_state_directory),
    }))
}

fn default_state_directory() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(program_data) = env::var_os("ProgramData") {
            return PathBuf::from(program_data)
                .join("AXIOS")
                .join("investigations");
        }
    }

    PathBuf::from("axios-investigations")
}

fn print_usage() {
    println!(
        "Usage:\n\
         axios-investigation-state.exe \\\n\
           --summary <SUMMARY.json> \\\n\
           --audit <AUDIT.json> \\\n\
           --applications <APPLICATIONS.json> \\\n\
           --correlation <CORRELATION.json> \\\n\
           [--state-dir <DIRECTORY>]"
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

fn summary_run_id(summary: &Value) -> Result<String> {
    let run_id = summary
        .get("run_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|run_id| !run_id.is_empty())
        .ok_or_else(|| anyhow::anyhow!("summary report is missing a non-empty run_id"))?;

    if run_id.len() > 128
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!(
            "summary run_id must contain only ASCII letters, digits, '-' or '_', up to 128 bytes"
        );
    }

    Ok(run_id.to_string())
}

fn collect_counts(audit: &Value, applications: &Value, correlation: &Value) -> Counts {
    let audit_summary = audit.get("summary").unwrap_or(&Value::Null);
    let application_summary = applications.get("summary").unwrap_or(&Value::Null);
    let correlation_summary = correlation.get("summary").unwrap_or(&Value::Null);

    Counts {
        needs_review: number(audit_summary, "needs_review")
            + number(application_summary, "needs_review")
            + number(correlation_summary, "needs_review"),
        unknown: number(audit_summary, "unknown") + number(application_summary, "unknown"),
        signed: number(audit_summary, "signed") + number(application_summary, "signed"),
        errors: number(audit_summary, "errors"),
        correlated_artifacts: number(correlation_summary, "correlated_artifacts"),
    }
}

fn collect_findings(audit: &Value, correlation: &Value) -> Vec<TrackedFinding> {
    let mut findings = BTreeMap::<String, TrackedFinding>::new();

    for artifact in audit
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let classification = artifact
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        if !classification.eq_ignore_ascii_case("needs_review") {
            continue;
        }

        let path = artifact
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if path.is_empty() {
            continue;
        }

        let group_key = application_group_key(&path);
        let signature_status = artifact
            .get("signature_status")
            .and_then(Value::as_str)
            .unwrap_or("NotChecked")
            .to_string();

        let mut signals = string_array(artifact, "script_indicators");
        signals.extend(string_array(artifact, "candidate_sources"));

        if artifact
            .get("zone_identifier_present")
            .and_then(Value::as_bool)
            == Some(true)
        {
            signals.push("zone_identifier".to_string());
        }

        if artifact
            .get("user_writable_location")
            .and_then(Value::as_bool)
            == Some(true)
        {
            signals.push("user_writable_location".to_string());
        }

        signals.sort();
        signals.dedup();

        let entry = findings
            .entry(group_key.clone())
            .or_insert_with(|| TrackedFinding {
                id: stable_group_id(&group_key),
                group_key: group_key.clone(),
                path: group_key.clone(),
                classification: "needs_review".to_string(),
                signature_status: signature_status.clone(),
                artifact_count: 0,
                signals: Vec::new(),
            });

        entry.artifact_count += 1;

        if signature_rank(&signature_status) > signature_rank(&entry.signature_status) {
            entry.signature_status = signature_status;
        }

        entry.signals.extend(signals);
        entry.signals.sort();
        entry.signals.dedup();
    }

    for finding in correlation
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if finding.get("classification").and_then(Value::as_str) != Some("needs_review") {
            continue;
        }

        let path = finding
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if path.is_empty() {
            continue;
        }

        let group_key = application_group_key(&path);
        let signature_status = finding
            .get("signature_status")
            .and_then(Value::as_str)
            .unwrap_or("NotChecked")
            .to_string();

        let entry = findings
            .entry(group_key.clone())
            .or_insert_with(|| TrackedFinding {
                id: stable_group_id(&group_key),
                group_key: group_key.clone(),
                path: group_key.clone(),
                classification: "needs_review".to_string(),
                signature_status: signature_status.clone(),
                artifact_count: 0,
                signals: Vec::new(),
            });

        if entry.artifact_count == 0 {
            entry.artifact_count = 1;
        }

        if signature_rank(&signature_status) > signature_rank(&entry.signature_status) {
            entry.signature_status = signature_status;
        }

        entry
            .signals
            .push("persistence_or_live_correlation".to_string());
        entry.signals.sort();
        entry.signals.dedup();
    }

    findings.into_values().collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn application_group_key(path: &str) -> String {
    let normalized = normalize_path(path);
    let parts = normalized.split('\\').collect::<Vec<_>>();

    let group_after = |marker: &str, children: usize| {
        parts
            .iter()
            .position(|part| *part == marker)
            .and_then(|index| {
                let end = index.saturating_add(children).min(parts.len());

                (end > index + 1).then(|| parts[..end].join("\\"))
            })
    };

    if let Some(group) = group_after(".minecraft", 3) {
        let suffix = parts
            .iter()
            .position(|part| *part == ".minecraft")
            .and_then(|index| parts.get(index + 1))
            .copied()
            .unwrap_or_default();

        if suffix == "runtime" || suffix == "versions" {
            return group;
        }
    }

    if let Some(group) = group_after("desktop", 2) {
        return group;
    }

    if let Some(group) = group_after("downloads", 2) {
        return group;
    }

    normalized
        .rsplit_once('\\')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or(normalized)
}

fn stable_group_id(group_key: &str) -> String {
    format!(
        "application:{}",
        hex::encode(Sha256::digest(group_key.as_bytes()))
    )
}

fn signature_rank(status: &str) -> u8 {
    match status {
        "BadDigest" | "ExplicitDistrust" | "SecuritySettingsBlocked" | "CertificateRevoked" => 4,
        "NotSigned" => 3,
        "NotChecked" => 2,
        "Valid" => 1,
        _ => 0,
    }
}

fn tracking_key(finding: &TrackedFinding) -> String {
    if finding.group_key.trim().is_empty() {
        application_group_key(&finding.path)
    } else {
        finding.group_key.clone()
    }
}

fn compare_findings(current: &[TrackedFinding], previous: &[TrackedFinding]) -> FindingChanges {
    let current_by_key = current
        .iter()
        .map(|finding| (tracking_key(finding), finding))
        .collect::<BTreeMap<_, _>>();

    let previous_by_key = previous
        .iter()
        .map(|finding| (tracking_key(finding), finding))
        .collect::<BTreeMap<_, _>>();

    let new_samples = current_by_key
        .iter()
        .filter(|(key, _)| !previous_by_key.contains_key(*key))
        .map(|(_, finding)| (*finding).clone())
        .take(20)
        .collect::<Vec<_>>();

    let resolved_samples = previous_by_key
        .iter()
        .filter(|(key, _)| !current_by_key.contains_key(*key))
        .map(|(_, finding)| (*finding).clone())
        .take(20)
        .collect::<Vec<_>>();

    FindingChanges {
        tracked_findings: current_by_key.len(),
        new_findings: current_by_key
            .keys()
            .filter(|key| !previous_by_key.contains_key(*key))
            .count(),
        resolved_findings: previous_by_key
            .keys()
            .filter(|key| !current_by_key.contains_key(*key))
            .count(),
        unchanged_findings: current_by_key
            .keys()
            .filter(|key| previous_by_key.contains_key(*key))
            .count(),
        new_samples,
        resolved_samples,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_require_all_input_reports() {
        assert!(parse_options(["--summary", "summary.json"]).is_err());
    }

    #[test]
    fn duplicate_option_is_rejected() {
        assert!(parse_options([
            "--summary",
            "a.json",
            "--summary",
            "b.json",
            "--audit",
            "audit.json",
            "--applications",
            "applications.json",
            "--correlation",
            "correlation.json",
        ])
        .is_err());
    }

    #[test]
    fn delta_tracks_new_review_items() {
        let delta = delta(
            &Counts {
                needs_review: 5,
                unknown: 3,
                signed: 10,
                errors: 1,
                correlated_artifacts: 2,
            },
            &Counts {
                needs_review: 2,
                unknown: 4,
                signed: 8,
                errors: 0,
                correlated_artifacts: 1,
            },
        );

        assert_eq!(delta.needs_review, 3);
        assert_eq!(delta.unknown, -1);
        assert_eq!(delta.signed, 2);
        assert_eq!(delta.errors, 1);
        assert_eq!(delta.correlated_artifacts, 1);
    }

    #[test]
    fn minecraft_runtime_is_grouped_as_one_application() {
        assert_eq!(
            application_group_key(
                r"C:\Users\TestUser\AppData\Roaming\.minecraft\runtime\java-runtime\bin\javaw.exe"
            ),
            r"c:\users\testuser\appdata\roaming\.minecraft\runtime\java-runtime"
        );
    }

    #[test]
    fn finding_changes_detect_new_and_resolved() {
        let previous = vec![TrackedFinding {
            id: "old".to_string(),
            group_key: r"c:\old".to_string(),
            path: r"C:\old.exe".to_string(),
            classification: "needs_review".to_string(),
            signature_status: "NotSigned".to_string(),
            artifact_count: 1,
            signals: Vec::new(),
        }];

        let current = vec![TrackedFinding {
            id: "new".to_string(),
            group_key: r"c:\new".to_string(),
            path: r"C:\new.exe".to_string(),
            classification: "needs_review".to_string(),
            signature_status: "BadDigest".to_string(),
            artifact_count: 1,
            signals: vec!["persistence_or_live_correlation".to_string()],
        }];

        let changes = compare_findings(&current, &previous);

        assert_eq!(changes.new_findings, 1);
        assert_eq!(changes.resolved_findings, 1);
        assert_eq!(changes.unchanged_findings, 0);
    }

    #[test]
    fn finding_collection_keeps_reviewed_artifacts() {
        let audit = json!({
            "artifacts": [{
                "path": r"C:\Users\TestUser\AppData\Local\Temp\loader.exe",
                "classification": "needs_review",
                "signature_status": "NotSigned",
                "sha256": "abc",
                "script_indicators": ["download_file"],
                "candidate_sources": ["selective_root"],
                "zone_identifier_present": true,
                "user_writable_location": true
            }]
        });

        let findings = collect_findings(&audit, &json!({}));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.starts_with("application:"));
        assert!(findings[0].signals.contains(&"zone_identifier".to_string()));
    }

    #[test]
    fn state_uses_the_summary_run_id_as_evidence_identity() {
        let summary = serde_json::json!({
            "run_id": "20260902-161736-309"
        });

        assert_eq!(summary_run_id(&summary).unwrap(), "20260902-161736-309");
    }

    #[test]
    fn state_rejects_a_missing_or_empty_summary_run_id() {
        assert!(summary_run_id(&serde_json::json!({})).is_err());
        assert!(summary_run_id(&serde_json::json!({"run_id": "   "})).is_err());
    }

    #[test]
    fn state_rejects_run_ids_that_can_escape_the_state_directory() {
        for run_id in [
            "../outside",
            "..\\outside",
            "C:\\outside",
            "a/b",
            "a.b",
            "x\ny",
        ] {
            assert!(
                summary_run_id(&json!({"run_id": run_id})).is_err(),
                "{run_id:?}"
            );
        }
        assert!(summary_run_id(&json!({"run_id": "a".repeat(129)})).is_err());
        assert_eq!(
            summary_run_id(&json!({"run_id": "20260916-032057_01"})).unwrap(),
            "20260916-032057_01"
        );
    }
    #[test]
    fn report_without_explicit_success_is_rejected() {
        assert!(validate_report(&json!({}), "audit").is_err());
        assert!(validate_report(&json!({"success": false}), "audit").is_err());
        assert!(validate_report(&json!({"success": true}), "audit").is_ok());
    }
}
