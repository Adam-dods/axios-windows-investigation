use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug)]
struct Options {
    audit_path: String,
    persistence_path: Option<String>,
    live_activity_path: Option<String>,
    output_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct CorrelationFinding {
    path: String,
    sha256: Option<String>,
    created_utc: Option<String>,
    modified_utc: Option<String>,
    extension: String,
    audit_classification: String,
    classification: String,
    signature_status: String,
    signer: Option<String>,
    persistence_matches: Vec<String>,
    live_activity_matches: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CorrelationSummary {
    artifacts_examined: usize,
    correlated_artifacts: usize,
    context: usize,
    needs_review: usize,
}

#[derive(Debug, Serialize)]
struct CorrelationReport {
    schema_version: u32,
    collector: &'static str,
    success: bool,
    summary: CorrelationSummary,
    findings: Vec<CorrelationFinding>,
}

fn main() -> Result<()> {
    let Some(options) = parse_options(std::env::args().skip(1))? else {
        print_usage();
        return Ok(());
    };

    let audit = json_file::read_value(&options.audit_path)?;
    validate_input_success("audit", &audit)?;

    let persistence = options
        .persistence_path
        .as_deref()
        .map(json_file::read_value)
        .transpose()?
        .unwrap_or(Value::Null);

    let live_activity = options
        .live_activity_path
        .as_deref()
        .map(json_file::read_value)
        .transpose()?
        .unwrap_or(Value::Null);

    if !persistence.is_null() {
        validate_input_success("persistence", &persistence)?;
    }
    if !live_activity.is_null() {
        validate_input_success("live activity", &live_activity)?;
    }

    let report = correlate_evidence(&audit, &persistence, &live_activity)?;

    if let Some(path) = options.output_path {
        json_file::write_pretty(path, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn parse_options<I, S>(arguments: I) -> Result<Option<Options>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut audit_path = None;
    let mut persistence_path = None;
    let mut live_activity_path = None;
    let mut output_path = None;

    while let Some(argument) = arguments.next() {
        let destination = match argument.as_str() {
            "--audit" => &mut audit_path,
            "--persistence" => &mut persistence_path,
            "--live-activity" => &mut live_activity_path,
            "--output" => &mut output_path,
            "--help" | "-h" => return Ok(None),
            _ => bail!("unknown argument: {argument}"),
        };

        if destination.is_some() {
            bail!("{argument} was provided more than once");
        }

        *destination = Some(
            arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("{argument} requires a value"))?,
        );
    }

    let audit_path = audit_path.context("--audit <universal-file-audit.json> is required")?;

    Ok(Some(Options {
        audit_path,
        persistence_path,
        live_activity_path,
        output_path,
    }))
}

fn print_usage() {
    println!(
        "Usage:\n\
         axios-audit-correlate.exe --audit <FILE>\n\
         [--persistence <FILE>]\n\
         [--live-activity <FILE>]\n\
         [--output <FILE>]"
    );
}

fn validate_input_success(name: &str, report: &Value) -> Result<()> {
    let successful = if name == "persistence" {
        ["registry", "extended", "coverage"]
            .iter()
            .all(|component| {
                report
                    .pointer(&format!("/{component}/success"))
                    .and_then(Value::as_bool)
                    == Some(true)
            })
    } else {
        report.get("success").and_then(Value::as_bool) == Some(true)
    };

    if !successful {
        anyhow::bail!("{name} report is not successful");
    }

    Ok(())
}

fn correlate_evidence(
    audit: &Value,
    persistence: &Value,
    live_activity: &Value,
) -> Result<CorrelationReport> {
    let persistence_strings = collect_strings(persistence, 8_000);
    let live_activity_strings = collect_strings(live_activity, 8_000);

    let artifacts = audit
        .get("artifacts")
        .and_then(Value::as_array)
        .context("Audit report does not contain an artifacts array")?;

    let mut findings = Vec::new();
    let mut context = 0usize;
    let mut needs_review = 0usize;

    for artifact in artifacts {
        let Some(path) = artifact.get("path").and_then(Value::as_str) else {
            continue;
        };

        let normalized_path = normalize_path(path);

        if normalized_path.len() < 6 {
            continue;
        }

        let persistence_matches = matching_sources(&normalized_path, &persistence_strings, 8);

        let live_activity_matches = matching_sources(&normalized_path, &live_activity_strings, 8);

        if persistence_matches.is_empty() && live_activity_matches.is_empty() {
            continue;
        }

        let audit_classification = artifact
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        let signature_status = artifact
            .get("signature_status")
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string();

        let classification = if correlation_requires_review(
            &audit_classification,
            &signature_status,
            !persistence_matches.is_empty(),
        ) {
            needs_review += 1;
            "needs_review"
        } else {
            context += 1;
            "context"
        }
        .to_string();

        findings.push(CorrelationFinding {
            path: path.to_string(),
            sha256: artifact
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase),
            created_utc: artifact
                .get("created_utc")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            modified_utc: artifact
                .get("modified_utc")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            extension: artifact
                .get("extension")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            audit_classification,
            classification,
            signature_status,
            signer: artifact
                .get("signer")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            persistence_matches,
            live_activity_matches,
        });
    }

    findings.sort_by(|left, right| {
        right
            .classification
            .cmp(&left.classification)
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok(CorrelationReport {
        schema_version: 1,
        collector: "axios_audit_correlation",
        success: true,
        summary: CorrelationSummary {
            artifacts_examined: artifacts.len(),
            correlated_artifacts: findings.len(),
            context,
            needs_review,
        },
        findings,
    })
}

fn collect_strings(value: &Value, maximum: usize) -> Vec<String> {
    let mut results = Vec::new();
    collect_strings_inner(value, maximum, &mut results);
    results
}

fn collect_strings_inner(value: &Value, maximum: usize, results: &mut Vec<String>) {
    if results.len() >= maximum {
        return;
    }

    match value {
        Value::String(text) => results.push(text.clone()),
        Value::Array(values) => {
            for value in values {
                collect_strings_inner(value, maximum, results);

                if results.len() >= maximum {
                    return;
                }
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_strings_inner(value, maximum, results);

                if results.len() >= maximum {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn normalize_path(value: &str) -> String {
    value
        .trim_matches(|character| character == '"' || character == '\'')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn matching_sources(path: &str, sources: &[String], maximum: usize) -> Vec<String> {
    let mut matches = Vec::new();

    for source in sources {
        let normalized_source = normalize_path(source);

        let path_matches = normalized_source.match_indices(path).any(|(start, _)| {
            let before = normalized_source[..start].chars().next_back();
            let after = normalized_source[start + path.len()..].chars().next();
            let boundary =
                |character: char| character.is_whitespace() || matches!(character, '"' | '\'');
            before.is_none_or(boundary) && after.is_none_or(boundary)
        });

        if path_matches {
            matches.push(source.clone());
        }

        if matches.len() >= maximum {
            break;
        }
    }

    matches
}

fn correlation_requires_review(
    audit_classification: &str,
    signature_status: &str,
    has_persistence_match: bool,
) -> bool {
    if audit_classification.eq_ignore_ascii_case("needs_review") {
        return true;
    }

    if !has_persistence_match {
        return false;
    }

    if audit_classification.eq_ignore_ascii_case("signed") {
        return false;
    }

    if audit_classification.eq_ignore_ascii_case("needs_review") {
        return true;
    }

    [
        "NotSigned",
        "BadDigest",
        "ExplicitDistrust",
        "SecuritySettingsBlocked",
        "CertificateRevoked",
    ]
    .iter()
    .any(|status| signature_status.eq_ignore_ascii_case(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_matching_is_case_insensitive() {
        let matches = matching_sources(
            r"c:\users\testuser\downloads\tool.exe",
            &[r#""C:\Users\TestUser\Downloads\Tool.exe" --background"#.to_string()],
            8,
        );

        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn unsigned_persistent_artifact_requires_review() {
        let audit = serde_json::json!({
            "artifacts": [{
                "path": r"C:\Users\TestUser\AppData\Local\Temp\loader.exe",
                "extension": ".exe",
                "classification": "unknown",
                "signature_status": "NotSigned",
                "sha256": "AABBCC"
            }]
        });

        let persistence = serde_json::json!({
            "entries": [{
                "command": r#""C:\Users\TestUser\AppData\Local\Temp\loader.exe" /silent"#
            }]
        });

        let report = correlate_evidence(&audit, &persistence, &Value::Null).unwrap();

        assert!(report.success);
        assert_eq!(report.summary.correlated_artifacts, 1);
        assert_eq!(report.summary.needs_review, 1);
        assert_eq!(report.findings[0].classification, "needs_review");
        assert_eq!(report.findings[0].sha256.as_deref(), Some("aabbcc"));
    }

    #[test]
    fn missing_audit_argument_is_rejected() {
        let result = parse_options(["--persistence", "persistence.json"]);

        assert!(result.is_err());
    }

    #[test]
    fn duplicate_argument_is_rejected() {
        let result = parse_options(["--audit", "first.json", "--audit", "second.json"]);

        assert!(result.is_err());
    }

    #[test]
    fn failed_correlation_inputs_are_rejected() {
        assert!(validate_input_success("audit", &json!({"success": false})).is_err());
        assert!(validate_input_success("live activity", &json!({})).is_err());

        assert!(validate_input_success(
            "persistence",
            &json!({
                "registry": {"success": true},
                "extended": {"success": true},
                "coverage": {"success": true}
            })
        )
        .is_ok());

        assert!(validate_input_success(
            "persistence",
            &json!({
                "registry": {"success": true},
                "extended": {"success": false},
                "coverage": {"success": true}
            })
        )
        .is_err());
    }
}

#[cfg(test)]
mod conservative_correlation_tests {
    use super::*;

    #[test]
    fn unknown_not_checked_persistence_is_context() {
        assert!(!correlation_requires_review("unknown", "NotChecked", true,));
    }

    #[test]
    fn unknown_unsigned_persistence_requires_review() {
        assert!(correlation_requires_review("unknown", "NotSigned", true,));
    }

    #[test]
    fn explicit_review_with_persistence_requires_review() {
        assert!(correlation_requires_review(
            "needs_review",
            "NotChecked",
            true,
        ));
    }

    #[test]
    fn signed_persistence_is_context() {
        assert!(!correlation_requires_review("signed", "Valid", true,));
    }

    #[test]
    fn bad_digest_persistence_requires_review() {
        assert!(correlation_requires_review("unknown", "BadDigest", true,));
    }

    #[test]
    fn unsigned_without_persistence_is_context() {
        assert!(!correlation_requires_review("unknown", "NotSigned", false,));
    }

    #[test]
    fn signed_classification_has_priority() {
        assert!(!correlation_requires_review("signed", "NotSigned", true,));
    }
}
