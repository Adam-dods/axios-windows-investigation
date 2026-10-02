use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
};

fn main() -> Result<()> {
    let paths = parse_options()?;
    let reports = load_reports(&paths)?;
    let result = hunt(&reports)?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_options() -> Result<BTreeMap<String, PathBuf>> {
    let required = [
        "audit",
        "persistence",
        "live",
        "processes",
        "network",
        "events",
    ];
    let mut args = env::args().skip(1);
    let mut paths = BTreeMap::new();

    while let Some(flag) = args.next() {
        if flag == "--help" {
            println!("Usage: axios-behavior-hunt.exe --audit <json> --persistence <json> --live <json> --processes <json> --network <json> --events <json>");
            std::process::exit(0);
        }

        let key = flag.strip_prefix("--").context("invalid argument")?;
        if !required.contains(&key) {
            bail!("unknown argument: {flag}");
        }
        if paths.contains_key(key) {
            bail!("{flag} was supplied more than once");
        }
        paths.insert(
            key.to_string(),
            PathBuf::from(args.next().context(format!("{flag} needs a file"))?),
        );
    }

    for key in required {
        if !paths.contains_key(key) {
            bail!("--{key} is required");
        }
    }
    Ok(paths)
}

fn persistence_report_succeeded(report: &Value) -> bool {
    ["registry", "extended", "coverage"].iter().all(|name| {
        report
            .get(*name)
            .and_then(|component| component.get("success"))
            .and_then(Value::as_bool)
            == Some(true)
    })
}

fn load_reports(paths: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Value>> {
    let mut reports = BTreeMap::new();

    for (name, path) in paths {
        let report = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;

        let successful = if name == "persistence" {
            persistence_report_succeeded(&report)
        } else {
            report.get("success").and_then(Value::as_bool) == Some(true)
        };

        if !successful {
            bail!("{name} report is not successful");
        }

        reports.insert(name.clone(), report);
    }
    Ok(reports)
}

fn hunt(reports: &BTreeMap<String, Value>) -> Result<Value> {
    let audit = reports["audit"]["artifacts"]
        .as_array()
        .context("audit artifacts are missing")?;

    let persistence_paths = executable_paths(&reports["persistence"]);
    let live_paths = executable_paths(&reports["live"]);
    let process_paths = executable_paths(&reports["processes"]);
    let network_paths = executable_paths(&reports["network"]);
    let event_paths = executable_paths(&reports["events"]);

    let mut artifacts = Vec::new();

    for item in audit {
        let Some(path) = item.get("path").and_then(Value::as_str) else {
            continue;
        };

        if item.get("classification").and_then(Value::as_str) != Some("needs_review") {
            continue;
        }

        let key = normalize(path);
        let persistence = persistence_paths.contains(&key);
        let live = live_paths.contains(&key);
        let process = process_paths.contains(&key);
        let network = network_paths.contains(&key);
        let event = event_paths.contains(&key);

        let (priority, score, explanation) = classify(persistence, live, process, network, event);

        artifacts.push(json!({
            "path": path,
            "sha256": item.get("sha256").cloned().unwrap_or(Value::Null),
            "created_utc": item.get("created_utc").cloned().unwrap_or(Value::Null),
            "modified_utc": item.get("modified_utc").cloned().unwrap_or(Value::Null),
            "audit_reason": item.get("reason").cloned().unwrap_or(Value::Null),
            "signature_status": item.get("signature_status").cloned().unwrap_or(Value::Null),
            "priority": priority,
            "behavior_score": score,
            "evidence": {
                "persistence_or_startup": persistence,
                "live_activity": live,
                "process_integrity": process,
                "network_activity": network,
                "security_event": event
            },
            "explanation": explanation
        }));
    }

    artifacts.sort_by(|left, right| {
        right["behavior_score"]
            .as_u64()
            .cmp(&left["behavior_score"].as_u64())
            .then_with(|| left["path"].as_str().cmp(&right["path"].as_str()))
    });

    let high = artifacts.iter().filter(|x| x["priority"] == "high").count();
    let medium = artifacts
        .iter()
        .filter(|x| x["priority"] == "medium")
        .count();

    Ok(json!({
        "success": true,
        "collector": "axios_behavior_hunt",
        "policy": {
            "high_requires": "persistence_or_startup AND process_integrity AND (network_activity OR security_event OR live_activity)",
            "verdict_policy": "evidence_hypothesis_only",
            "zero_day_confirmed": false,
            "malware_confirmed": false
        },
        "summary": {
            "audit_needs_review_examined": artifacts.len(),
            "high_priority_execution_chains": high,
            "medium_priority_execution_chains": medium,
            "context_only": artifacts.len() - high - medium
        },
        "artifacts": artifacts
    }))
}

fn classify(
    persistence: bool,
    live: bool,
    process: bool,
    network: bool,
    event: bool,
) -> (&'static str, u32, &'static str) {
    let mut score = 0;
    if persistence {
        score += 35;
    }
    if process {
        score += 25;
    }
    if live {
        score += 15;
    }
    if network {
        score += 15;
    }
    if event {
        score += 10;
    }

    if persistence && process && (live || network || event) {
        (
            "high",
            score,
            "Independent persistence, process, and runtime/network/event evidence overlaps. Review urgently; this is not a malware verdict.",
        )
    } else if score >= 35 {
        (
            "medium",
            score,
            "Partial multi-source evidence exists. More evidence is required before high-priority escalation.",
        )
    } else {
        (
            "context",
            score,
            "Insufficient independent evidence for escalation.",
        )
    }
}

fn executable_paths(value: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, output: &mut BTreeSet<String>) {
        match value {
            Value::String(text) if looks_like_executable_path(text) => {
                output.insert(normalize(text));
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, output);
                }
            }
            Value::Object(items) => {
                for item in items.values() {
                    walk(item, output);
                }
            }
            _ => {}
        }
    }

    let mut output = BTreeSet::new();
    walk(value, &mut output);
    output
}

fn looks_like_executable_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.contains(":\\") || lower.starts_with("\\\\"))
        && [
            ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_persistence_requires_every_component_to_succeed() {
        assert!(persistence_report_succeeded(&json!({
            "registry": {"success": true},
            "extended": {"success": true},
            "coverage": {"success": true}
        })));
        assert!(!persistence_report_succeeded(&json!({
            "registry": {"success": true},
            "extended": {"success": false},
            "coverage": {"success": true}
        })));
    }

    #[test]
    fn high_requires_three_independent_layers() {
        let result = classify(true, false, true, true, false);
        assert_eq!(result.0, "high");
        assert_eq!(result.1, 75);
    }

    #[test]
    fn persistence_and_process_without_runtime_evidence_is_medium() {
        let result = classify(true, false, true, false, false);
        assert_eq!(result.0, "medium");
        assert_eq!(result.1, 60);
    }

    #[test]
    fn a_single_network_signal_is_context() {
        let result = classify(false, false, false, true, false);
        assert_eq!(result.0, "context");
    }

    #[test]
    fn only_real_executable_paths_are_collected() {
        let paths = executable_paths(&json!({
            "a": r"C:\Temp\sample.exe",
            "b": "not-a-path.exe",
            "c": r"C:\Windows\System32\driver.sys"
        }));

        assert_eq!(paths.len(), 2);
        assert!(paths.contains(r"c:\temp\sample.exe"));
    }
}
