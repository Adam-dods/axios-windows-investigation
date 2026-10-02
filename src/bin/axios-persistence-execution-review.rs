use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
};

fn main() -> Result<()> {
    let paths = options()?;
    let reports = load_reports(&paths)?;
    let report = review(&reports)?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn options() -> Result<BTreeMap<String, PathBuf>> {
    let required = [
        "persistence",
        "processes",
        "live",
        "network",
        "drivers",
        "code-integrity",
    ];

    let mut args = env::args().skip(1);
    let mut paths = BTreeMap::new();

    while let Some(flag) = args.next() {
        if flag == "--help" {
            println!(
                "Usage: axios-persistence-execution-review.exe --persistence <json> --processes <json> --live <json> --network <json> --drivers <json> --code-integrity <json>"
            );
            std::process::exit(0);
        }

        let name = flag.strip_prefix("--").context("invalid argument")?;
        if !required.contains(&name) {
            bail!("unknown argument: {flag}");
        }
        if paths.contains_key(name) {
            bail!("{flag} was supplied more than once");
        }

        paths.insert(
            name.to_string(),
            PathBuf::from(args.next().context(format!("{flag} needs a file"))?),
        );
    }

    for name in required {
        if !paths.contains_key(name) {
            bail!("--{name} is required");
        }
    }

    Ok(paths)
}

fn load_reports(paths: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Value>> {
    let mut reports = BTreeMap::new();

    for (name, path) in paths {
        let value = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;

        let successful = if name == "persistence" {
            ["registry", "extended", "coverage"]
                .iter()
                .all(|component| {
                    value
                        .pointer(&format!("/{component}/success"))
                        .and_then(Value::as_bool)
                        == Some(true)
                })
        } else {
            value.get("success").and_then(Value::as_bool) == Some(true)
        };

        if !successful {
            bail!("{name} report is not successful");
        }

        reports.insert(name.clone(), value);
    }

    Ok(reports)
}

fn review(reports: &BTreeMap<String, Value>) -> Result<Value> {
    let persistence_paths = paths_in(&reports["persistence"]);
    let process_paths = paths_in(&reports["processes"]);
    let live_paths = paths_in(&reports["live"]);
    let network_paths = paths_in(&reports["network"]);
    let driver_paths = paths_in(&reports["drivers"]);
    let code_integrity_paths = paths_in(&reports["code-integrity"]);

    let mut artifacts = Vec::new();

    for path in &persistence_paths {
        let process_running = process_paths.contains(path);
        let live_activity = live_paths.contains(path);
        let network_activity = network_paths.contains(path);
        let driver_or_kernel_context =
            driver_paths.contains(path) || code_integrity_paths.contains(path);

        let process_record = object_for_path(&reports["processes"], path);
        let user_writable = process_record
            .as_ref()
            .is_some_and(|record| bool_property(record, "user_writable_location"));

        let needs_review = process_record.as_ref().is_some_and(|record| {
            string_property(record, "classification")
                .is_some_and(|value| value.eq_ignore_ascii_case("needs_review"))
                || bool_property(record, "parent_mismatch")
                || record_text(record).contains("notsigned")
                || record_text(record).contains("unsigned")
        });

        let suspicious_execution = user_writable || needs_review;

        if !process_running && !suspicious_execution && !driver_or_kernel_context {
            continue;
        }

        let (priority, score, explanation) = classify(
            process_running,
            live_activity,
            network_activity,
            suspicious_execution,
            driver_or_kernel_context,
        );

        artifacts.push(json!({
            "path": path,
            "priority": priority,
            "execution_score": score,
            "evidence": {
                "persistence_or_startup": true,
                "process_running": process_running,
                "live_activity": live_activity,
                "network_activity": network_activity,
                "user_writable_location": user_writable,
                "process_integrity_needs_review": needs_review,
                "driver_or_code_integrity_context": driver_or_kernel_context
            },
            "process_context": process_record.unwrap_or(Value::Null),
            "explanation": explanation
        }));
    }

    artifacts.sort_by(|left, right| {
        priority_rank(right["priority"].as_str().unwrap_or("context"))
            .cmp(&priority_rank(
                left["priority"].as_str().unwrap_or("context"),
            ))
            .then_with(|| {
                right["execution_score"]
                    .as_u64()
                    .cmp(&left["execution_score"].as_u64())
            })
            .then_with(|| left["path"].as_str().cmp(&right["path"].as_str()))
    });

    let high = artifacts
        .iter()
        .filter(|item| item["priority"] == "high")
        .count();
    let medium = artifacts
        .iter()
        .filter(|item| item["priority"] == "medium")
        .count();
    let observed = artifacts
        .iter()
        .filter(|item| item["priority"] == "observed")
        .count();

    let context_only = artifacts
        .iter()
        .filter(|item| item["priority"] == "context")
        .count();

    artifacts.retain(|item| item["priority"] == "high" || item["priority"] == "medium");

    Ok(json!({
        "success": true,
        "collector": "axios_persistence_execution_review",
        "policy": {
            "high_requires": "persistence_or_startup AND process_running AND (live_activity OR network_activity) AND suspicious_execution",
            "suspicious_execution": "user_writable_location OR process_integrity_needs_review",
            "malware_confirmed": false,
            "zero_day_confirmed": false,
            "remediation_performed": false
        },
        "summary": {
            "persistent_executable_paths_discovered": persistence_paths.len(),
            "persistent_execution_artifacts": artifacts.len(),
            "high_priority_execution_chains": high,
            "medium_priority_execution_chains": medium,
            "observed_non_escalated_chains": observed,
            "context_only_chains": context_only,
            "reported_high_or_medium_chains": artifacts.len()
        },
        "artifacts": artifacts
    }))
}

fn classify(
    process_running: bool,
    live_activity: bool,
    network_activity: bool,
    suspicious_execution: bool,
    driver_or_kernel_context: bool,
) -> (&'static str, u32, &'static str) {
    let mut score = 30u32;

    if process_running {
        score += 30;
    }
    if live_activity {
        score += 15;
    }
    if network_activity {
        score += 15;
    }
    if suspicious_execution {
        score += 20;
    }
    if driver_or_kernel_context {
        score += 10;
    }

    if process_running && (live_activity || network_activity) && suspicious_execution {
        (
            "high",
            score,
            "A persistent executable is running with independent runtime evidence and a suspicious process signal. Review urgently; this is not a malware verdict.",
        )
    } else if suspicious_execution && (process_running || live_activity || network_activity) {
        (
            "medium",
            score,
            "A persistent executable has a suspicious process signal plus partial execution evidence. Review ownership, signer, parent process, and network context.",
        )
    } else if process_running && (live_activity || network_activity) {
        (
            "observed",
            score,
            "A persistent executable is active, but AXIOS found no independent suspicious process signal. Recorded as context, not an alert.",
        )
    } else {
        (
            "context",
            score,
            "Persistence context exists without enough independent runtime evidence for escalation.",
        )
    }
}

fn paths_in(value: &Value) -> BTreeSet<String> {
    fn walk(value: &Value, output: &mut BTreeSet<String>) {
        match value {
            Value::String(text) => output.extend(extract_paths(text)),
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

fn extract_paths(text: &str) -> BTreeSet<String> {
    let mut output = BTreeSet::new();
    let lower = text.to_ascii_lowercase();

    for extension in [
        ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ] {
        let mut offset = 0usize;

        while let Some(relative) = lower[offset..].find(extension) {
            let extension_start = offset + relative;
            let end = extension_start + extension.len();
            let before = &lower[..end];

            if let Some(colon) = before.rfind(":\\") {
                let start = colon.saturating_sub(1);
                let candidate = text[start..end].trim().trim_matches('"').trim_matches('\'');

                if looks_like_path(candidate) {
                    output.insert(normalize(candidate));
                }
            }

            offset = end;
        }
    }

    output
}

fn looks_like_path(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();

    (lower.contains(":\\") || lower.starts_with("\\\\"))
        && [
            ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn object_for_path(value: &Value, target: &str) -> Option<Value> {
    match value {
        Value::Array(items) => items.iter().find_map(|item| object_for_path(item, target)),
        Value::Object(items) => {
            for item in items.values() {
                if let Some(record) = object_for_path(item, target) {
                    return Some(record);
                }
            }

            direct_object_has_path(items, target).then(|| value.clone())
        }
        _ => None,
    }
}

fn direct_object_has_path(items: &Map<String, Value>, target: &str) -> bool {
    items.values().any(|value| {
        value
            .as_str()
            .is_some_and(|text| extract_paths(text).contains(target))
    })
}

fn bool_property(value: &Value, property: &str) -> bool {
    value
        .get(property)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn string_property<'a>(value: &'a Value, property: &str) -> Option<&'a str> {
    value.get(property).and_then(Value::as_str)
}

fn record_text(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 4,
        "medium" => 3,
        "observed" => 2,
        "context" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reports(process: Value, live: Value, network: Value) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "persistence".to_string(),
                json!({
                    "command": r#"C:\Users\Test\AppData\Roaming\sample.exe --silent"#
                }),
            ),
            ("processes".to_string(), process),
            ("live".to_string(), live),
            ("network".to_string(), network),
            ("drivers".to_string(), json!({"success": true})),
            ("code-integrity".to_string(), json!({"success": true})),
        ])
    }

    #[test]
    fn high_requires_persistence_runtime_and_suspicious_process_signal() {
        let path = r"C:\Users\Test\AppData\Roaming\sample.exe";
        let report = review(&reports(
            json!({
                "success": true,
                "artifacts": [{
                    "executable_path": path,
                    "classification": "needs_review",
                    "user_writable_location": true
                }]
            }),
            json!({"success": true, "path": path}),
            json!({"success": true, "path": path}),
        ))
        .unwrap();

        assert_eq!(report["summary"]["high_priority_execution_chains"], 1);
        assert_eq!(report["artifacts"][0]["priority"], "high");
    }

    #[test]
    fn trusted_active_persistence_is_observed_not_escalated() {
        let path = r"C:\Windows\System32\service.exe";
        let mut input = reports(
            json!({
                "success": true,
                "artifacts": [{
                    "executable_path": path,
                    "classification": "trusted",
                    "user_writable_location": false
                }]
            }),
            json!({"success": true, "path": path}),
            json!({"success": true, "path": path}),
        );

        input.insert(
            "persistence".to_string(),
            json!({"command": format!("{path} -service")}),
        );

        let report = review(&input).unwrap();

        assert_eq!(report["summary"]["high_priority_execution_chains"], 0);
        assert_eq!(report["summary"]["observed_non_escalated_chains"], 1);
        assert_eq!(report["summary"]["reported_high_or_medium_chains"], 0);
        assert!(report["artifacts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn executable_path_is_extracted_from_command_line() {
        let paths = extract_paths(r#"C:\Program Files\Example\agent.exe --background --port 443"#);

        assert!(paths.contains(r"c:\program files\example\agent.exe"));
    }

    #[test]
    fn combined_persistence_requires_all_components() {
        let complete = json!({
            "registry": {"success": true},
            "extended": {"success": true},
            "coverage": {"success": true}
        });
        let incomplete = json!({
            "registry": {"success": true},
            "extended": {"success": false},
            "coverage": {"success": true}
        });

        let complete_ok = ["registry", "extended", "coverage"]
            .iter()
            .all(|component| {
                complete
                    .pointer(&format!("/{component}/success"))
                    .and_then(Value::as_bool)
                    == Some(true)
            });
        let incomplete_ok = ["registry", "extended", "coverage"]
            .iter()
            .all(|component| {
                incomplete
                    .pointer(&format!("/{component}/success"))
                    .and_then(Value::as_bool)
                    == Some(true)
            });

        assert!(complete_ok);
        assert!(!incomplete_ok);
    }
}
