use crate::analysis::diff::{compare_stable, Comparison};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    pub created_at: String,
    pub snapshot_sha256: String,
    pub snapshot: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineVerification {
    pub valid: bool,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub created_at: String,
}

pub fn create_from_snapshot_file(
    snapshot_path: impl AsRef<Path>,
    baseline_path: impl AsRef<Path>,
) -> Result<Baseline> {
    let snapshot_path = snapshot_path.as_ref();
    let baseline_path = baseline_path.as_ref();

    let data = std::fs::read_to_string(snapshot_path)
        .with_context(|| format!("failed to read {}", snapshot_path.display()))?;

    let snapshot: Value = serde_json::from_str(&data)
        .with_context(|| format!("invalid JSON in {}", snapshot_path.display()))?;

    let baseline = create(snapshot);

    std::fs::write(baseline_path, serde_json::to_string_pretty(&baseline)?)
        .with_context(|| format!("failed to write {}", baseline_path.display()))?;

    Ok(baseline)
}

pub fn create(snapshot: Value) -> Baseline {
    Baseline {
        schema_version: 1,
        created_at: Utc::now().to_rfc3339(),
        snapshot_sha256: hash_snapshot(&snapshot),
        snapshot,
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<Baseline> {
    let path = path.as_ref();

    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let baseline: Baseline = serde_json::from_str(&data)
        .with_context(|| format!("invalid baseline {}", path.display()))?;

    if baseline.schema_version != 1 {
        anyhow::bail!(
            "unsupported baseline schema version {}",
            baseline.schema_version
        );
    }

    Ok(baseline)
}

pub fn verify(baseline: &Baseline) -> BaselineVerification {
    let actual_sha256 = hash_snapshot(&baseline.snapshot);

    BaselineVerification {
        valid: actual_sha256 == baseline.snapshot_sha256,
        expected_sha256: baseline.snapshot_sha256.clone(),
        actual_sha256,
        created_at: baseline.created_at.clone(),
    }
}

pub fn verify_file(path: impl AsRef<Path>) -> Result<BaselineVerification> {
    let baseline = load(path)?;
    Ok(verify(&baseline))
}

pub fn compare_baseline_to_snapshot_file(
    baseline_path: impl AsRef<Path>,
    snapshot_path: impl AsRef<Path>,
) -> Result<Comparison> {
    let baseline = load(baseline_path)?;

    let snapshot_data = std::fs::read_to_string(snapshot_path.as_ref())
        .with_context(|| format!("failed to read {}", snapshot_path.as_ref().display()))?;

    let snapshot: Value = serde_json::from_str(&snapshot_data)
        .with_context(|| format!("invalid JSON in {}", snapshot_path.as_ref().display()))?;

    Ok(compare_stable(&baseline.snapshot, &snapshot))
}

pub fn hash_snapshot(snapshot: &Value) -> String {
    let encoded = serde_json::to_vec(snapshot).expect("snapshot serialization failed");

    let mut hasher = Sha256::new();
    hasher.update(encoded);

    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_baseline_verifies() {
        let baseline = create(json!({
            "system": "windows",
            "secure_boot": true
        }));

        assert!(verify(&baseline).valid);
    }

    #[test]
    fn modified_baseline_fails_verification() {
        let mut baseline = create(json!({
            "defender": {
                "enabled": true
            }
        }));

        baseline.snapshot["defender"]["enabled"] = json!(false);

        assert!(!verify(&baseline).valid);
    }

    #[test]
    fn baseline_comparison_ignores_runtime_noise() {
        let before = json!({
            "generated_at": "before",
            "processes": [{"pid": 1}],
            "services": [{"name": "Example", "binary_path": "old.exe"}]
        });

        let after = json!({
            "generated_at": "after",
            "processes": [{"pid": 2}],
            "services": [{"name": "Example", "binary_path": "new.exe"}]
        });

        let result = compare_stable(&before, &after);

        assert_eq!(result.change_count, 1);
        assert_eq!(result.changes[0].path, "$.services[0].binary_path");
    }

    #[test]
    fn hash_is_stable_for_same_snapshot() {
        let snapshot = json!({
            "services": ["A", "B"],
            "system": {
                "version": "11"
            }
        });

        assert_eq!(hash_snapshot(&snapshot), hash_snapshot(&snapshot));
    }
}
