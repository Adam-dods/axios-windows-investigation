use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub change_count: usize,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub changes: Vec<Change>,
}

const VOLATILE_PATH_SEGMENTS: &[&str] = &[
    ".timestamp",
    ".generated_at",
    ".collected_at",
    ".started_at",
    ".finished_at",
    ".last_collection",
    ".uptime_seconds",
    ".available_memory_bytes",
    ".used_memory_bytes",
    ".used_swap_bytes",
    ".virtual_memory_bytes",
    ".memory_bytes",
    ".cpu_percent",
    ".ProcessId",
    ".State",
    ".pid",
    ".parent_pid",
    ".runtime_seconds",
    ".FreeSpace",
    ".FreePhysicalMemory",
    ".LastBootUpTime",
    ".thread_count",
    ".handle_count",
];

const VOLATILE_PATH_PREFIXES: &[&str] = &[".processes[", "$.live_activity.", "$.resource_sample."];

pub fn compare(before: &Value, after: &Value) -> Comparison {
    let mut changes = Vec::new();
    compare_value("$", before, after, &mut changes);

    comparison_from_changes(changes)
}

pub fn compare_stable(before: &Value, after: &Value) -> Comparison {
    let mut result = compare(before, after);

    result.changes.retain(|change| {
        !is_volatile_change_path(&change.path)
            && !change.path.starts_with("$.core_snapshot.network")
    });

    comparison_from_changes(result.changes)
}

pub fn is_volatile_change_path(path: &str) -> bool {
    VOLATILE_PATH_PREFIXES
        .iter()
        .any(|prefix| path.contains(prefix))
        || VOLATILE_PATH_SEGMENTS
            .iter()
            .any(|segment| path.contains(segment))
}

fn comparison_from_changes(changes: Vec<Change>) -> Comparison {
    let added = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .count();

    let removed = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Removed)
        .count();

    let modified = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Modified)
        .count();

    Comparison {
        change_count: changes.len(),
        added,
        removed,
        modified,
        changes,
    }
}

pub fn compare_files(
    before_path: impl AsRef<Path>,
    after_path: impl AsRef<Path>,
) -> Result<Comparison> {
    let before_path = before_path.as_ref();
    let after_path = after_path.as_ref();

    let before_data = std::fs::read_to_string(before_path)
        .with_context(|| format!("failed to read {}", before_path.display()))?;

    let after_data = std::fs::read_to_string(after_path)
        .with_context(|| format!("failed to read {}", after_path.display()))?;

    let before: Value = serde_json::from_str(&before_data)
        .with_context(|| format!("invalid JSON in {}", before_path.display()))?;

    let after: Value = serde_json::from_str(&after_data)
        .with_context(|| format!("invalid JSON in {}", after_path.display()))?;

    Ok(compare(&before, &after))
}

fn compare_value(path: &str, before: &Value, after: &Value, changes: &mut Vec<Change>) {
    match (before, after) {
        (Value::Object(before_map), Value::Object(after_map)) => {
            let keys: BTreeSet<&String> = before_map.keys().chain(after_map.keys()).collect();

            for key in keys {
                let child_path = format!("{path}.{}", escape_path_key(key));

                match (before_map.get(key), after_map.get(key)) {
                    (None, Some(new_value)) => changes.push(Change {
                        path: child_path,
                        kind: ChangeKind::Added,
                        before: None,
                        after: Some(new_value.clone()),
                    }),

                    (Some(old_value), None) => changes.push(Change {
                        path: child_path,
                        kind: ChangeKind::Removed,
                        before: Some(old_value.clone()),
                        after: None,
                    }),

                    (Some(old_value), Some(new_value)) => {
                        compare_value(&child_path, old_value, new_value, changes);
                    }

                    (None, None) => {}
                }
            }
        }

        (Value::Array(before_array), Value::Array(after_array)) => {
            let common_length = before_array.len().min(after_array.len());

            for index in 0..common_length {
                compare_value(
                    &format!("{path}[{index}]"),
                    &before_array[index],
                    &after_array[index],
                    changes,
                );
            }

            for (index, value) in before_array.iter().enumerate().skip(common_length) {
                changes.push(Change {
                    path: format!("{path}[{index}]"),
                    kind: ChangeKind::Removed,
                    before: Some(value.clone()),
                    after: None,
                });
            }

            for (index, value) in after_array.iter().enumerate().skip(common_length) {
                changes.push(Change {
                    path: format!("{path}[{index}]"),
                    kind: ChangeKind::Added,
                    before: None,
                    after: Some(value.clone()),
                });
            }
        }

        _ if before != after => changes.push(Change {
            path: path.to_string(),
            kind: ChangeKind::Modified,
            before: Some(before.clone()),
            after: Some(after.clone()),
        }),

        _ => {}
    }
}

fn escape_path_key(key: &str) -> String {
    if key
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        key.to_string()
    } else {
        format!("[{}]", serde_json::to_string(key).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_values_have_no_changes() {
        let value = json!({
            "system": {
                "version": "11",
                "secure_boot": true
            }
        });

        let result = compare(&value, &value);

        assert_eq!(result.change_count, 0);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn detects_added_removed_and_modified_values() {
        let before = json!({
            "service": {
                "state": "stopped",
                "old_setting": true
            }
        });

        let after = json!({
            "service": {
                "state": "running",
                "new_setting": true
            }
        });

        let result = compare(&before, &after);

        assert_eq!(result.change_count, 3);
        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 1);
        assert_eq!(result.modified, 1);
    }

    #[test]
    fn stable_comparison_ignores_runtime_noise() {
        let before = json!({
            "generated_at": "2026-08-01T10:00:00Z",
            "processes": [{"pid": 100, "name": "chrome.exe"}],
            "resources": {"used_memory_bytes": 1000},
            "registry": {"startup_command": "old.exe"}
        });

        let after = json!({
            "generated_at": "2026-08-02T10:00:00Z",
            "processes": [{"pid": 200, "name": "different.exe"}],
            "resources": {"used_memory_bytes": 2000},
            "registry": {"startup_command": "new.exe"}
        });

        let result = compare_stable(&before, &after);

        assert_eq!(result.change_count, 1);
        assert_eq!(result.modified, 1);
        assert_eq!(result.changes[0].path, "$.registry.startup_command");
    }

    #[test]
    fn stable_comparison_ignores_nested_process_lists() {
        let before = json!({
            "core_snapshot": {
                "processes": [{"pid": 10, "name": "old.exe"}]
            },
            "registry_persistence": {
                "entry": "old.exe"
            }
        });

        let after = json!({
            "core_snapshot": {
                "processes": [{"pid": 20, "name": "new.exe"}]
            },
            "registry_persistence": {
                "entry": "new.exe"
            }
        });

        let result = compare_stable(&before, &after);

        assert_eq!(result.change_count, 1);
        assert_eq!(result.changes[0].path, "$.registry_persistence.entry");
    }

    #[test]
    fn detects_array_changes() {
        let before = json!({
            "ports": [80, 443]
        });

        let after = json!({
            "ports": [80, 8080, 9000]
        });

        let result = compare(&before, &after);

        assert_eq!(result.modified, 1);
        assert_eq!(result.added, 1);
        assert_eq!(result.change_count, 2);
    }

    #[test]
    fn stable_comparison_ignores_core_snapshot_network() {
        let before = serde_json::json!({
            "core_snapshot": {
                "network": {
                    "summary": { "tcp_endpoints_returned": 10 },
                    "tcp": [{ "pid": 100, "local_port": 5000 }]
                }
            },
            "security_posture": {
                "uac_enabled": true
            }
        });

        let after = serde_json::json!({
            "core_snapshot": {
                "network": {
                    "summary": { "tcp_endpoints_returned": 25 },
                    "tcp": [{ "pid": 200, "local_port": 6000 }]
                }
            },
            "security_posture": {
                "uac_enabled": false
            }
        });

        let result = compare_stable(&before, &after);

        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "$.security_posture.uac_enabled");
    }
}
