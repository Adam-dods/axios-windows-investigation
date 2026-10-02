use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};
use std::{fs, path::PathBuf};

const MAX_MESSAGE_LENGTH: usize = 2048;

#[derive(Parser, Debug)]
#[command(name = "axios-code-integrity-investigation")]
struct Options {
    #[arg(long)]
    kernel_posture: PathBuf,

    #[arg(long)]
    driver_trust: Option<PathBuf>,

    #[arg(long, default_value_t = 100)]
    max_events: usize,
}

fn main() -> Result<()> {
    let options = Options::parse();
    if options.max_events == 0 || options.max_events > 1000 {
        bail!("--max-events must be between 1 and 1000");
    }

    let kernel = read_json(&options.kernel_posture, "kernel posture")?;

    let trusted_driver_paths = options
        .driver_trust
        .as_ref()
        .map(|path| read_json(path, "driver trust"))
        .transpose()?
        .map(driver_paths)
        .unwrap_or_default();

    let mut source_events = Vec::new();
    collect_target_events(&kernel, &mut source_events, options.max_events);

    let mut artifacts = Vec::new();
    let mut blocked_module_events = 0_u64;
    let mut whql_events = 0_u64;

    for event in source_events {
        let event_id = event_id(&event).unwrap_or_default();

        if event_id == 3033 {
            blocked_module_events += 1;
        }

        if event_id == 3085 {
            whql_events += 1;
        }

        let message = bounded(
            first_text(
                &event,
                &[
                    "message",
                    "rendered_message",
                    "description",
                    "data",
                    "details",
                ],
            ),
            MAX_MESSAGE_LENGTH,
        );

        let modules = extract_windows_paths(&message);
        let trusted_driver_matches: Vec<String> = modules
            .iter()
            .filter(|module| {
                let normalized = normalize_path(module);

                trusted_driver_paths
                    .iter()
                    .any(|driver| normalize_path(driver) == normalized)
            })
            .cloned()
            .collect();

        let (classification, confidence, title, reason) = match event_id {
            3085 => (
                "confirmed_security_weakening",
                "high",
                "WHQL driver enforcement disabled",
                "Code Integrity recorded disabled WHQL driver enforcement for a boot session.",
            ),
            3033 => (
                "needs_review",
                "high",
                "Code Integrity blocked module loading",
                "Windows blocked module loading because the module did not meet the required signing level.",
            ),
            _ => continue,
        };

        artifacts.push(json!({
            "event_id": event_id,
            "classification": classification,
            "confidence": confidence,
            "title": title,
            "reason": reason,
            "provider": first_text(&event, &["provider", "provider_name", "log_name"]),
            "timestamp": first_text(&event, &["timestamp", "time_created", "created_at", "time"]),
            "message": message,
            "referenced_modules": modules,
            "trusted_driver_matches": trusted_driver_matches,
            "source_event": event
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "collector": "axios_code_integrity_investigation",
            "success": true,
            "limits": {
                "max_events": options.max_events,
                "max_message_length": MAX_MESSAGE_LENGTH
            },
            "summary": {
                "events_collected": artifacts.len(),
                "blocked_module_events": blocked_module_events,
                "whql_enforcement_disabled_events": whql_events,
                "events_with_module_paths": artifacts.iter()
                    .filter(|artifact| artifact["referenced_modules"].as_array().is_some_and(|modules| !modules.is_empty()))
                    .count(),
                "events_matching_trusted_driver_inventory": artifacts.iter()
                    .filter(|artifact| artifact["trusted_driver_matches"].as_array().is_some_and(|modules| !modules.is_empty()))
                    .count()
            },
            "artifacts": artifacts
        }))?
    );

    Ok(())
}

fn read_json(path: &PathBuf, name: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);

    let report: Value = serde_json::from_slice(bytes)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;

    validate_success(&report, name)?;
    Ok(report)
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn driver_paths(report: Value) -> Vec<String> {
    report["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|artifact| artifact["path"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

fn collect_target_events(value: &Value, output: &mut Vec<Value>, limit: usize) {
    if output.len() >= limit {
        return;
    }

    match value {
        Value::Object(object) => {
            if event_id_from_object(object).is_some_and(|id| id == 3033 || id == 3085) {
                output.push(value.clone());

                if output.len() >= limit {
                    return;
                }
            }

            for child in object.values() {
                collect_target_events(child, output, limit);

                if output.len() >= limit {
                    return;
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_target_events(child, output, limit);

                if output.len() >= limit {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn event_id(value: &Value) -> Option<u64> {
    value.as_object().and_then(event_id_from_object)
}

fn event_id_from_object(object: &Map<String, Value>) -> Option<u64> {
    object.iter().find_map(|(key, value)| {
        let normalized = normalize_key(key);

        if normalized == "eventid" || normalized == "id" {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        } else {
            None
        }
    })
}

fn first_text(value: &Value, keys: &[&str]) -> String {
    let wanted: Vec<String> = keys.iter().map(|key| normalize_key(key)).collect();

    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if wanted
                    .iter()
                    .any(|wanted_key| *wanted_key == normalize_key(key))
                {
                    if let Some(text) = child.as_str() {
                        return text.trim().to_string();
                    }
                }
            }

            for child in object.values() {
                let result = first_text(child, keys);

                if !result.is_empty() {
                    return result;
                }
            }

            String::new()
        }
        Value::Array(values) => values
            .iter()
            .map(|value| first_text(value, keys))
            .find(|value| !value.is_empty())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn extract_windows_paths(message: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    let lower = message.to_ascii_lowercase();
    let extensions = [".sys", ".dll", ".exe", ".ocx", ".drv"];

    let mut offset = 0;

    while offset < lower.len() {
        let remaining = &lower[offset..];

        let start = remaining.char_indices().find_map(|(index, character)| {
            let tail = &remaining[index..];

            let drive_path = character.is_ascii_alphabetic()
                && tail.as_bytes().get(1) == Some(&b':')
                && matches!(tail.as_bytes().get(2), Some(b'\\') | Some(b'/'));

            if drive_path || tail.starts_with(r"\device\") || tail.starts_with(r"\\") {
                Some(index)
            } else {
                None
            }
        });

        let Some(relative_start) = start else {
            break;
        };

        let path_start = offset + relative_start;
        let candidate_lower = &lower[path_start..];

        let path_end = extensions
            .iter()
            .filter_map(|extension| {
                candidate_lower
                    .find(extension)
                    .map(|index| path_start + index + extension.len())
            })
            .min();

        let Some(path_end) = path_end else {
            offset = path_start + 1;
            continue;
        };

        let candidate = message[path_start..path_end]
            .trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\'' | ',' | ';' | '.' | ')' | '(' | '[' | ']' | '{' | '}'
                )
            })
            .replace('/', "\\");

        if !paths
            .iter()
            .any(|path| path.eq_ignore_ascii_case(&candidate))
        {
            paths.push(candidate);
        }

        offset = path_end;
    }

    paths
}

fn bounded(mut value: String, limit: usize) -> String {
    if value.len() > limit {
        value.truncate(limit);
    }

    value
}

fn normalize_path(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_code_integrity_inputs_are_rejected() {
        assert!(validate_success(&json!({"success": false}), "kernel").is_err());
        assert!(validate_success(&json!({}), "drivers").is_err());
        assert!(validate_success(&json!({"success": true}), "kernel").is_ok());
    }

    #[test]
    fn target_events_are_collected_and_bounded() {
        let input = json!({
            "events": [
                { "EventId": 3033, "Message": "blocked" },
                { "event_id": 3085, "message": "whql" },
                { "event_id": 1000, "message": "ignored" }
            ]
        });

        let mut output = Vec::new();
        collect_target_events(&input, &mut output, 1);

        assert_eq!(output.len(), 1);
        assert_eq!(event_id(&output[0]), Some(3033));
    }

    #[test]
    fn windows_paths_are_extracted_without_duplicates() {
        let paths = extract_windows_paths(
            "Module C:\\Program Files\\App\\vulkan-1.dll failed C:\\Program Files\\App\\vulkan-1.dll",
        );

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], r"C:\Program Files\App\vulkan-1.dll");
    }

    #[test]
    fn driver_inventory_paths_are_collected() {
        let report = json!({
            "artifacts": [
                { "path": r"C:\Windows\System32\drivers\good.sys" }
            ]
        });

        assert_eq!(
            driver_paths(report),
            vec![r"C:\Windows\System32\drivers\good.sys"]
        );
    }
}
