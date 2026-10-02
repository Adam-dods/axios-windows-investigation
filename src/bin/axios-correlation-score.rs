use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
};

fn main() -> Result<()> {
    let inputs = options()?;
    let reports = load(&inputs)?;
    let correlation = required_report(&reports, "correlation")?;
    let processes = required_report(&reports, "processes")?;
    let network = required_report(&reports, "network")?;
    let kernel = required_report(&reports, "kernel")?;
    let hardware = required_report(&reports, "hardware")?;

    let process_paths = executable_paths(processes);
    let suspicious_processes = suspicious_process_evidence(processes);
    let network_paths = executable_paths(network);
    let kernel_findings = kernel
        .get("findings")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let secure_boot_disabled = hardware
        .pointer("/secure_boot/enabled")
        .and_then(Value::as_bool)
        == Some(false);

    let findings = correlation["findings"]
        .as_array()
        .context("correlation findings missing")?;
    let mut scored = Vec::new();

    for finding in findings {
        let path = finding["path"].as_str().unwrap_or("");
        if path.is_empty() {
            continue;
        }

        let key = normalize_path(path);
        let persistence = finding["persistence_matches"]
            .as_array()
            .map(|x| !x.is_empty())
            .unwrap_or(false);
        let live = finding["live_activity_matches"]
            .as_array()
            .map(|x| !x.is_empty())
            .unwrap_or(false);
        let process = process_paths.contains(&key);
        let network = network_paths.contains(&key);
        let artifact_signals = suspicious_processes.get(&key).cloned().unwrap_or_default();
        let artifact_specific_suspicion = !artifact_signals.is_empty();

        let (priority, coverage_score, risk_score) = classify(
            persistence,
            live,
            process,
            network,
            artifact_specific_suspicion,
        );

        scored.push(json!({
            "path": path,
            "sha256": finding.get("sha256").cloned().unwrap_or(Value::Null),
            "signer": finding.get("signer").cloned().unwrap_or(Value::Null),
            "created_utc": finding.get("created_utc").cloned().unwrap_or(Value::Null),
            "modified_utc": finding.get("modified_utc").cloned().unwrap_or(Value::Null),
            "score": risk_score,
            "evidence_coverage_score": coverage_score,
            "priority": priority,
            "evidence": {
                "persistence_or_startup": persistence,
                "live_activity": live,
                "process_path_match": process,
                "network_path_match": network,
                "artifact_specific_suspicious_evidence": artifact_specific_suspicion,
                "artifact_specific_signals": artifact_signals,
                "system_posture_context": {
                    "kernel_finding_count": kernel_findings,
                    "secure_boot_disabled": secure_boot_disabled
                }
            },
            "explanation": if priority == "high" {
                "Artifact-specific suspicious process evidence overlaps persistence, process, and live/network activity. Review urgently; this is not a malware verdict."
            } else if priority == "medium" {
                "Artifact-specific suspicious process evidence has partial cross-layer support and needs review."
            } else {
                "Cross-layer activity alone is normal for trusted system services. No artifact-specific suspicious process evidence was found."
            }
        }));
    }

    scored.sort_by(|a, b| {
        b["score"]
            .as_u64()
            .cmp(&a["score"].as_u64())
            .then_with(|| a["path"].as_str().cmp(&b["path"].as_str()))
    });

    let high = scored.iter().filter(|x| x["priority"] == "high").count();
    let medium = scored.iter().filter(|x| x["priority"] == "medium").count();

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "collector": "axios_correlation_score",
            "policy": {
                "high_requires": "artifact_specific_suspicious_evidence AND persistence_or_startup AND process AND (live_activity OR network)",
                "zero_day_claims": false,
                "malware_verdicts": false
            },
            "summary": {
                "artifacts_scored": scored.len(),
                "high_priority": high,
                "medium_priority": medium,
                "context_only": scored.len() - high - medium,
                "kernel_finding_count": kernel_findings,
                "secure_boot_disabled": secure_boot_disabled
            },
            "artifacts": scored
        }))?
    );

    Ok(())
}

fn required_report<'a>(reports: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value> {
    reports
        .get(name)
        .with_context(|| format!("validated input report is missing: {name}"))
}

fn classify(
    persistence: bool,
    live: bool,
    process: bool,
    network: bool,
    artifact_specific_suspicion: bool,
) -> (&'static str, u32, u32) {
    let mut coverage_score = 0u32;
    if persistence {
        coverage_score += 35;
    }
    if live {
        coverage_score += 20;
    }
    if process {
        coverage_score += 25;
    }
    if network {
        coverage_score += 20;
    }

    let risk_score = if artifact_specific_suspicion {
        coverage_score
    } else {
        0
    };

    let priority = if artifact_specific_suspicion && persistence && process && (live || network) {
        "high"
    } else if artifact_specific_suspicion && coverage_score >= 35 {
        "medium"
    } else {
        "context"
    };

    (priority, coverage_score, risk_score)
}

fn suspicious_process_evidence(report: &Value) -> BTreeMap<String, Vec<String>> {
    let mut output = BTreeMap::new();

    for artifact in report["artifacts"].as_array().into_iter().flatten() {
        let Some(path) = artifact.get("executable_path").and_then(Value::as_str) else {
            continue;
        };

        let mut signals = Vec::new();

        if artifact.get("classification").and_then(Value::as_str) == Some("needs_review") {
            signals.push("process_integrity_needs_review".to_string());
        }
        if artifact
            .get("user_writable_location")
            .and_then(Value::as_bool)
            == Some(true)
        {
            signals.push("user_writable_execution".to_string());
        }
        if artifact.get("parent_mismatch").and_then(Value::as_bool) == Some(true) {
            signals.push("unexpected_parent".to_string());
        }
        if artifact
            .get("command_signals")
            .and_then(Value::as_array)
            .map(|items| !items.is_empty())
            .unwrap_or(false)
        {
            signals.push("suspicious_command_signal".to_string());
        }

        if !signals.is_empty() {
            output.insert(normalize_path(path), signals);
        }
    }

    output
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
    let mut result = BTreeMap::new();
    let needed = ["correlation", "processes", "network", "kernel", "hardware"];

    while let Some(flag) = args.next() {
        if flag == "--help" {
            println!("--correlation <json> --processes <json> --network <json> --kernel <json> --hardware <json>");
            std::process::exit(0);
        }
        let name = flag.strip_prefix("--").context("invalid option")?;
        if !needed.contains(&name) {
            bail!("unknown option: {flag}");
        }
        let value = PathBuf::from(args.next().context(format!("{flag} needs a file"))?);

        if result.insert(name.to_string(), value).is_some() {
            bail!("{flag} was supplied more than once");
        }
    }
    for name in needed {
        if !result.contains_key(name) {
            bail!("--{name} is required");
        }
    }
    Ok(result)
}

fn load(inputs: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Value>> {
    let mut output = BTreeMap::new();
    for (name, path) in inputs {
        let value = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;
        if value["success"].as_bool() != Some(true) {
            bail!("{name} report is not successful");
        }
        output.insert(name.clone(), value);
    }
    Ok(output)
}

fn executable_paths(value: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, output: &mut BTreeSet<String>) {
        match value {
            Value::String(text) => {
                let path = normalize_path(text);
                if looks_like_executable_path(&path) {
                    output.insert(path);
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, output);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    walk(value, output);
                }
            }
            _ => {}
        }
    }

    let mut output = BTreeSet::new();
    walk(value, &mut output);
    output
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn looks_like_executable_path(path: &str) -> bool {
    if !path.contains('\\') {
        return false;
    }

    matches!(
        path.rsplit('.').next().unwrap_or_default(),
        "exe" | "dll" | "sys" | "com" | "scr"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_validated_report_returns_error_instead_of_panicking() {
        let reports = BTreeMap::new();
        let error =
            required_report(&reports, "network").expect_err("missing report must return an error");

        assert!(error
            .to_string()
            .contains("validated input report is missing: network"));
    }

    #[test]
    fn trusted_system_service_activity_is_context_not_high() {
        let (priority, coverage_score, risk_score) = classify(true, true, true, true, false);

        assert_eq!(priority, "context");
        assert_eq!(coverage_score, 100);
        assert_eq!(risk_score, 0);
    }

    #[test]
    fn high_requires_artifact_specific_suspicion_and_execution_chain() {
        let (priority, _, _) = classify(true, true, true, false, true);
        assert_eq!(priority, "high");

        let (priority, _, _) = classify(true, true, true, false, false);
        assert_eq!(priority, "context");
    }

    #[test]
    fn process_risk_index_requires_real_process_signal() {
        let evidence = suspicious_process_evidence(&json!({
            "artifacts": [
                {
                    "executable_path": r"C:\Windows\System32\spoolsv.exe",
                    "classification": "trusted",
                    "user_writable_location": false,
                    "parent_mismatch": false,
                    "command_signals": []
                },
                {
                    "executable_path": r"C:\Users\Test\AppData\Local\loader.exe",
                    "classification": "needs_review",
                    "user_writable_location": true,
                    "parent_mismatch": false,
                    "command_signals": ["encoded_powershell"]
                }
            ]
        }));

        assert!(!evidence.contains_key(r"c:\windows\system32\spoolsv.exe"));
        assert_eq!(
            evidence[r"c:\users\test\appdata\local\loader.exe"],
            vec![
                "process_integrity_needs_review",
                "user_writable_execution",
                "suspicious_command_signal"
            ]
        );
    }

    #[test]
    fn executable_path_matching_is_exact_not_substring_based() {
        let paths = executable_paths(&json!({
            "real_process": {
                "path": r"C:\Users\Test\AppData\Local\agent.exe"
            },
            "unrelated_text": r"C:\Users\Test\AppData\Local\agent.exe.old",
            "nested": [
                "the text mentions C:\\Users\\Test\\AppData\\Local\\agent.exe",
                r"C:\Windows\System32\svchost.exe"
            ]
        }));

        assert!(paths.contains(r"c:\users\test\appdata\local\agent.exe"));
        assert!(paths.contains(r"c:\windows\system32\svchost.exe"));
        assert!(!paths.contains(r"c:\users\test\appdata\local\agent.exe.old"));
    }

    #[test]
    fn path_normalization_handles_case_quotes_and_slashes() {
        assert_eq!(
            normalize_path(r#" "C:/Tools/Agent.EXE" "#),
            r"c:\tools\agent.exe"
        );
    }

    #[test]
    fn duplicate_input_is_rejected() {
        let result = options_from([
            "--correlation",
            "a.json",
            "--correlation",
            "b.json",
            "--processes",
            "processes.json",
            "--network",
            "network.json",
            "--kernel",
            "kernel.json",
            "--hardware",
            "hardware.json",
        ]);

        assert!(result.is_err());
    }
}
