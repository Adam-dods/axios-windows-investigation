use anyhow::{bail, Result};
use axios_core::{
    storage::json_file,
    system::universal_file_audit::{collect, DEFAULT_MAX_ARTIFACTS},
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Options {
    max_files: usize,
    audit_path: Option<String>,
    output_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApplicationReport {
    application: String,
    classification: String,
    confidence: String,
    artifact_count: usize,
    signed_artifacts: usize,
    unknown_artifacts: usize,
    needs_review_artifacts: usize,
    signals: Vec<String>,
    sample_paths: Vec<String>,
}

fn main() -> Result<()> {
    let Some(options) = parse_options(std::env::args().skip(1))? else {
        print_usage();
        return Ok(());
    };

    let reused_file_audit = options.audit_path.is_some();

    let audit = match options.audit_path.as_deref() {
        Some(path) => json_file::read_value(path)?,
        None => collect(options.max_files)?,
    };

    validate_success(&audit, "universal file audit")?;

    let report = build_document(&audit, reused_file_audit);

    if let Some(path) = options.output_path {
        json_file::write_pretty(path, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn parse_options<I, S>(arguments: I) -> Result<Option<Options>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut max_files = DEFAULT_MAX_ARTIFACTS;
    let mut max_files_explicit = false;
    let mut audit_path = None;
    let mut output_path = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--max-files" => {
                if max_files_explicit {
                    bail!("--max-files was provided more than once");
                }

                let value = arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-files requires a value"))?;

                max_files = value
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("--max-files must be a non-negative integer"))?;

                max_files_explicit = true;
            }
            "--audit" => {
                if audit_path.is_some() {
                    bail!("--audit was provided more than once");
                }

                audit_path = Some(
                    arguments
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--audit requires a JSON file path"))?,
                );
            }
            "--output" => {
                if output_path.is_some() {
                    bail!("--output was provided more than once");
                }

                output_path = Some(
                    arguments
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--output requires a file path"))?,
                );
            }
            "--help" | "-h" => return Ok(None),
            _ => bail!("unknown argument: {argument}"),
        }
    }

    if audit_path.is_some() && max_files_explicit {
        bail!("--audit and --max-files cannot be used together");
    }

    Ok(Some(Options {
        max_files,
        audit_path,
        output_path,
    }))
}

fn print_usage() {
    println!(
        "Usage:\n\
         axios-application-investigation.exe [--max-files <COUNT>] [--output <FILE>]\n\
         axios-application-investigation.exe --audit <FILE> [--output <FILE>]\n\n\
         --audit reuses an existing AXIOS Universal File Audit.\n\
         --output writes the investigation report directly as UTF-8 JSON."
    );
}

fn build_document(audit: &Value, reused_file_audit: bool) -> Value {
    let reports = build_reports(audit);

    let summary = json!({
        "applications": reports.len(),
        "needs_review": reports
            .iter()
            .filter(|report| report.classification == "needs_review")
            .count(),
        "unknown": reports
            .iter()
            .filter(|report| report.classification == "unknown")
            .count(),
        "signed": reports
            .iter()
            .filter(|report| report.classification == "signed")
            .count(),
    });

    json!({
        "schema_version": 1,
        "collector": "axios_application_investigation",
        "success": true,
        "reused_file_audit": reused_file_audit,
        "file_audit_scope": audit
            .get("scan_scope")
            .cloned()
            .unwrap_or(Value::Null),
        "file_audit_summary": audit
            .get("summary")
            .cloned()
            .unwrap_or(Value::Null),
        "summary": summary,
        "applications": reports,
    })
}

fn build_reports(audit: &Value) -> Vec<ApplicationReport> {
    let mut reports: BTreeMap<String, ApplicationReport> = BTreeMap::new();

    for artifact in audit
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let path = artifact
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if path.is_empty() {
            continue;
        }

        let application = application_name(artifact, path);
        let classification = classify_artifact(artifact, path);

        let report = reports
            .entry(application.clone())
            .or_insert_with(|| ApplicationReport {
                application,
                classification: "signed".to_string(),
                confidence: "high".to_string(),
                artifact_count: 0,
                signed_artifacts: 0,
                unknown_artifacts: 0,
                needs_review_artifacts: 0,
                signals: Vec::new(),
                sample_paths: Vec::new(),
            });

        report.artifact_count += 1;

        match classification.as_str() {
            "needs_review" => {
                report.needs_review_artifacts += 1;
                report.classification = "needs_review".to_string();
                report.confidence = "medium".to_string();
            }
            "unknown" => {
                report.unknown_artifacts += 1;

                if report.classification != "needs_review" {
                    report.classification = "unknown".to_string();
                    report.confidence = "low".to_string();
                }
            }
            _ => report.signed_artifacts += 1,
        }

        if report.sample_paths.len() < 5 {
            report.sample_paths.push(path.to_string());
        }

        for signal in artifact_signals(artifact, path) {
            if !report.signals.contains(&signal) {
                report.signals.push(signal);
            }
        }
    }

    reports.into_values().collect()
}

fn application_name(artifact: &Value, path: &str) -> String {
    artifact
        .get("product_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            artifact
                .get("file_description")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .map(str::to_string)
        .unwrap_or_else(|| parent_directory(path))
}

fn parent_directory(path: &str) -> String {
    path.rsplit_once('\\')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| path.to_string())
}

fn high_confidence_signature_failure(status: &str) -> bool {
    [
        "BadDigest",
        "ExplicitDistrust",
        "SecuritySettingsBlocked",
        "CertificateRevoked",
    ]
    .iter()
    .any(|value| status.eq_ignore_ascii_case(value))
}

fn classify_artifact(artifact: &Value, path: &str) -> String {
    let audit_classification = artifact
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    if audit_classification.eq_ignore_ascii_case("needs_review") {
        return "needs_review".to_string();
    }

    if audit_classification.eq_ignore_ascii_case("signed") {
        return "signed".to_string();
    }

    let signature = artifact
        .get("signature_status")
        .and_then(Value::as_str)
        .unwrap_or("NotChecked");

    if signature.eq_ignore_ascii_case("Valid") {
        return "signed".to_string();
    }

    if high_confidence_signature_failure(signature) {
        return "needs_review".to_string();
    }

    if is_user_writable_path(path)
        && is_executable_artifact(artifact)
        && signature.eq_ignore_ascii_case("NotSigned")
    {
        return "needs_review".to_string();
    }

    "unknown".to_string()
}

fn artifact_signals(artifact: &Value, path: &str) -> Vec<String> {
    let mut signals = BTreeSet::new();

    let signature = artifact
        .get("signature_status")
        .and_then(Value::as_str)
        .unwrap_or("NotChecked");

    if !["Valid", "NotChecked", "Unavailable", "Unknown"]
        .iter()
        .any(|value| signature.eq_ignore_ascii_case(value))
    {
        signals.insert(format!("signature_status:{signature}"));
    }

    if artifact
        .get("zone_identifier_present")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        signals.insert("mark_of_the_web_present".to_string());
    }

    if is_user_writable_path(path) {
        signals.insert("user_writable_location".to_string());
    }

    if let Some(indicators) = artifact.get("script_indicators").and_then(Value::as_array) {
        for indicator in indicators.iter().filter_map(Value::as_str) {
            signals.insert(format!("script_indicator:{indicator}"));
        }
    }

    signals.into_iter().collect()
}

fn is_executable_artifact(artifact: &Value) -> bool {
    matches!(
        artifact.get("extension").and_then(Value::as_str),
        Some(".exe" | ".dll" | ".sys" | ".scr" | ".com" | ".cpl" | ".msi" | ".msp")
    )
}

fn is_user_writable_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();

    normalized.contains("\\users\\")
        && (normalized.contains("\\appdata\\")
            || normalized.contains("\\downloads\\")
            || normalized.contains("\\desktop\\")
            || normalized.contains("\\documents\\")
            || normalized.contains("\\pictures\\")
            || normalized.contains("\\videos\\")
            || normalized.contains("\\music\\")
            || normalized.contains("\\temp\\"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_document, build_reports, classify_artifact, is_user_writable_path, parse_options,
    };
    use serde_json::json;

    #[test]
    fn user_writable_locations_are_detected() {
        assert!(is_user_writable_path(
            r"C:\Users\TestUser\AppData\Local\Temp\sample.exe"
        ));

        assert!(is_user_writable_path(
            r"C:\Users\TestUser\Documents\sample.exe"
        ));

        assert!(!is_user_writable_path(
            r"C:\Program Files\Vendor\sample.exe"
        ));
    }

    #[test]
    fn unsigned_executable_in_temp_requires_review() {
        let artifact = json!({
            "classification": "unknown",
            "extension": ".exe",
            "signature_status": "NotSigned"
        });

        assert_eq!(
            classify_artifact(
                &artifact,
                r"C:\Users\TestUser\AppData\Local\Temp\sample.exe"
            ),
            "needs_review"
        );
    }

    #[test]
    fn existing_audit_is_grouped_without_rescanning() {
        let audit = json!({
            "summary": {
                "artifacts": 2
            },
            "artifacts": [
                {
                    "path": r"C:\Program Files\Vendor\app.exe",
                    "product_name": "Vendor Application",
                    "classification": "signed",
                    "extension": ".exe",
                    "signature_status": "Valid"
                },
                {
                    "path": r"C:\Program Files\Vendor\helper.dll",
                    "product_name": "Vendor Application",
                    "classification": "signed",
                    "extension": ".dll",
                    "signature_status": "Valid"
                }
            ]
        });

        let reports = build_reports(&audit);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].application, "Vendor Application");
        assert_eq!(reports[0].artifact_count, 2);
        assert_eq!(reports[0].classification, "signed");

        let document = build_document(&audit, true);
        assert_eq!(document["reused_file_audit"], true);
    }

    #[test]
    fn audit_and_max_files_are_mutually_exclusive() {
        let result = parse_options(["--audit", "audit.json", "--max-files", "100"]);

        assert!(result.is_err());
    }

    #[test]
    fn missing_output_value_is_rejected() {
        let result = parse_options(["--output"]);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod conservative_application_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn not_checked_user_executable_is_unknown() {
        let artifact = json!({
            "classification": "unknown",
            "extension": ".exe",
            "signature_status": "NotChecked"
        });

        assert_eq!(
            classify_artifact(
                &artifact,
                r"C:\Users\TestUser\AppData\Local\Temp\sample.exe"
            ),
            "unknown"
        );
    }

    #[test]
    fn failed_audit_input_is_rejected() {
        assert!(validate_success(&json!({"success": false}), "audit").is_err());
        assert!(validate_success(&json!({}), "audit").is_err());
        assert!(validate_success(&json!({"success": true}), "audit").is_ok());
    }

    #[test]
    fn not_checked_is_not_a_signature_signal() {
        let artifact = json!({
            "classification": "unknown",
            "extension": ".exe",
            "signature_status": "NotChecked",
            "zone_identifier_present": false,
            "script_indicators": []
        });

        let signals = artifact_signals(&artifact, r"C:\Program Files\Vendor\sample.exe");

        assert!(!signals
            .iter()
            .any(|signal| { signal == "signature_status:NotChecked" }));
    }

    #[test]
    fn valid_audit_classification_is_preserved() {
        let artifact = json!({
            "classification": "signed",
            "extension": ".exe",
            "signature_status": "Valid"
        });

        assert_eq!(
            classify_artifact(&artifact, r"C:\Program Files\Vendor\sample.exe"),
            "signed"
        );
    }

    #[test]
    fn audit_review_classification_is_preserved() {
        let artifact = json!({
            "classification": "needs_review",
            "extension": ".exe",
            "signature_status": "NotChecked"
        });

        assert_eq!(
            classify_artifact(&artifact, r"C:\Program Files\Vendor\sample.exe"),
            "needs_review"
        );
    }

    #[test]
    fn unsigned_user_executable_still_requires_review() {
        let artifact = json!({
            "classification": "unknown",
            "extension": ".exe",
            "signature_status": "NotSigned"
        });

        assert_eq!(
            classify_artifact(
                &artifact,
                r"C:\Users\TestUser\AppData\Local\Temp\sample.exe"
            ),
            "needs_review"
        );
    }

    #[test]
    fn damaged_signature_requires_review() {
        let artifact = json!({
            "classification": "unknown",
            "extension": ".exe",
            "signature_status": "BadDigest"
        });

        assert_eq!(
            classify_artifact(&artifact, r"C:\Program Files\Vendor\sample.exe"),
            "needs_review"
        );
    }
}
