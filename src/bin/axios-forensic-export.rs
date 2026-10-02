use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, io::Write, path::Path, path::PathBuf};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let mut case_id = "axios-local-investigation".to_string();
    let mut output = None;
    let mut evidence = BTreeMap::new();
    let mut case_id_supplied = false;
    let mut output_supplied = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--case-id" => {
                if case_id_supplied {
                    bail!("--case-id was supplied more than once");
                }

                case_id = args.next().context("--case-id needs a value")?;
                if case_id.trim().is_empty() {
                    bail!("--case-id must not be empty");
                }

                case_id_supplied = true;
            }
            "--output" => {
                if output_supplied {
                    bail!("--output was supplied more than once");
                }

                output = Some(PathBuf::from(args.next().context("--output needs a file")?));
                output_supplied = true;
            }
            "--evidence" => {
                let value = args.next().context("--evidence needs role=path")?;
                let (role, path) = value
                    .split_once('=')
                    .context("--evidence format is role=path")?;
                if role.trim().is_empty() || evidence.contains_key(role) {
                    bail!("invalid or duplicate evidence role");
                }
                evidence.insert(role.to_string(), PathBuf::from(path));
            }
            "--help" => {
                println!("Usage: --case-id <id> --output <manifest.json> --evidence role=path [--evidence role=path...]");
                return Ok(());
            }
            _ => bail!("unknown argument: {flag}"),
        }
    }

    let output = output.context("--output is required")?;
    if evidence.is_empty() {
        bail!("at least one --evidence role=path is required");
    }

    let mut artifacts = Vec::new();
    for (role, path) in evidence {
        let bytes =
            fs::read(&path).with_context(|| format!("cannot read evidence: {}", path.display()))?;

        let json_status = match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) => json!({
                "is_json": true,
                "success": value.get("success").and_then(Value::as_bool)
            }),
            Err(_) => json!({ "is_json": false, "success": Value::Null }),
        };

        artifacts.push(json!({
            "role": role,
            "path": path,
            "size_bytes": bytes.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "captured_at": Utc::now().to_rfc3339(),
            "content_status": json_status
        }));
    }

    let chain_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&artifacts)?));

    let manifest = json!({
        "success": true,
        "collector": "axios_forensic_export",
        "schema_version": 1,
        "case_id": case_id,
        "created_at": Utc::now().to_rfc3339(),
        "chain_of_custody": {
            "collection_method": "read_only_hash_manifest",
            "chain_sha256": chain_sha256,
            "artifact_count": artifacts.len(),
            "integrity_verification": "Recompute each SHA-256, serialize artifacts in listed order, then compare chain_sha256."
        },
        "artifacts": artifacts,
        "limitations": [
            "The manifest proves integrity of listed files after collection; it does not prove how a source file was originally created.",
            "AXIOS does not modify, quarantine, delete, or execute evidence files."
        ]
    });

    write_new_manifest(&output, &manifest)?;

    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn write_new_manifest(output: &Path, manifest: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)?;
    // A forensic export must never replace an input artifact or earlier manifest.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| {
            format!(
                "refusing to overwrite an existing file: {}",
                output.display()
            )
        })?;
    file.write_all(&bytes)
        .with_context(|| format!("cannot write {}", output.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync {}", output.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forensic_export_never_overwrites_existing_evidence() {
        let path = std::env::temp_dir().join(format!(
            "axios-evidence-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::write(&path, b"original evidence").unwrap();
        assert!(write_new_manifest(&path, &json!({"success": true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original evidence");
        fs::remove_file(path).unwrap();
    }
}
