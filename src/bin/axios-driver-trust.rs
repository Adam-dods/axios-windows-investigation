use anyhow::{bail, Context, Result};
use axios_core::security::native_authenticode::{verify_file, AuthenticodeVerification};
use clap::Parser;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const DEFAULT_MAX_DRIVERS: usize = 256;

#[derive(Parser, Debug)]
#[command(name = "axios-driver-trust")]
struct Options {
    #[arg(long)]
    kernel_posture: PathBuf,

    #[arg(long, default_value_t = DEFAULT_MAX_DRIVERS)]
    max_drivers: usize,
}

#[derive(Debug)]
struct DriverGroup {
    path: String,
    names: Vec<String>,
    service_types: Vec<String>,
    start_modes: Vec<String>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_drivers == 0 || options.max_drivers > DEFAULT_MAX_DRIVERS {
        anyhow::bail!("max-drivers must be between 1 and {DEFAULT_MAX_DRIVERS}");
    }

    let raw = fs::read_to_string(&options.kernel_posture)
        .with_context(|| format!("failed to read {}", options.kernel_posture.display()))?;
    let json_input = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let posture: Value =
        serde_json::from_str(json_input).context("kernel posture input is not valid JSON")?;

    validate_success(&posture, "kernel posture")?;

    println!(
        "{}",
        serde_json::to_string_pretty(&build_report(&posture, options.max_drivers))?
    );

    Ok(())
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn build_report(posture: &Value, max_drivers: usize) -> Value {
    let groups = collect_driver_groups(posture);
    let total_unique_drivers = groups.len();
    let truncated = total_unique_drivers > max_drivers;

    let mut artifacts = Vec::new();

    for group in groups.into_iter().take(max_drivers) {
        artifacts.push(inspect_driver(group));
    }

    let trusted = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "trusted")
        .count();

    let needs_review = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "needs_review")
        .count();

    let unknown = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "unknown")
        .count();

    let missing = artifacts
        .iter()
        .filter(|artifact| artifact["file_exists"] == false)
        .count();

    json!({
        "schema_version": 1,
        "collector": "axios_driver_trust",
        "success": true,
        "signature_engine": "winverifytrust",
        "source": {
            "collector": posture.get("collector").cloned().unwrap_or(Value::Null),
            "schema_version": posture.get("schema_version").cloned().unwrap_or(Value::Null)
        },
        "limits": {
            "max_drivers": max_drivers,
            "unique_driver_paths_collected": total_unique_drivers,
            "truncated": truncated
        },
        "summary": {
            "drivers_checked": artifacts.len(),
            "trusted": trusted,
            "needs_review": needs_review,
            "unknown": unknown,
            "missing_on_disk": missing
        },
        "artifacts": artifacts
    })
}

fn collect_driver_groups(posture: &Value) -> Vec<DriverGroup> {
    let mut groups: BTreeMap<String, DriverGroup> = BTreeMap::new();

    for driver in posture
        .get("running_drivers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(path) = driver
            .get("PathName")
            .or_else(|| driver.get("path_name"))
            .and_then(Value::as_str)
            .map(normalize_driver_path)
            .filter(|path| !path.is_empty())
        else {
            continue;
        };

        let key = path.to_ascii_lowercase();
        let group = groups.entry(key).or_insert_with(|| DriverGroup {
            path: path.clone(),
            names: Vec::new(),
            service_types: Vec::new(),
            start_modes: Vec::new(),
        });

        push_unique(
            &mut group.names,
            driver
                .get("Name")
                .or_else(|| driver.get("name"))
                .and_then(Value::as_str),
        );
        push_unique(
            &mut group.service_types,
            driver
                .get("ServiceType")
                .or_else(|| driver.get("service_type"))
                .and_then(Value::as_str),
        );
        push_unique(
            &mut group.start_modes,
            driver
                .get("StartMode")
                .or_else(|| driver.get("start_mode"))
                .and_then(Value::as_str),
        );
    }

    groups.into_values().collect()
}

fn inspect_driver(group: DriverGroup) -> Value {
    let path = PathBuf::from(&group.path);
    let file_exists = path.is_file();
    let standard_location = is_standard_driver_location(&group.path);

    if !file_exists {
        return json!({
            "path": group.path,
            "driver_names": group.names,
            "service_types": group.service_types,
            "start_modes": group.start_modes,
            "file_exists": false,
            "standard_location": standard_location,
            "classification": "needs_review",
            "reason": "running_driver_path_missing_on_disk",
            "signature": AuthenticodeVerification::not_checked(),
            "sha256": Value::Null
        });
    }

    let signature = verify_file(&path);
    let sha256 = sha256_file(&path).ok();

    let (classification, reason) = classify_driver(&signature, standard_location);

    json!({
        "path": group.path,
        "driver_names": group.names,
        "service_types": group.service_types,
        "start_modes": group.start_modes,
        "file_exists": true,
        "standard_location": standard_location,
        "classification": classification,
        "reason": reason,
        "signature": signature,
        "sha256": sha256
    })
}

fn classify_driver(
    signature: &AuthenticodeVerification,
    standard_location: bool,
) -> (&'static str, &'static str) {
    if signature.checked && signature.trusted {
        return ("trusted", "native_signature_valid");
    }

    if !signature.checked {
        return ("unknown", "signature_not_checked");
    }

    if !standard_location {
        return (
            "needs_review",
            "untrusted_driver_outside_standard_windows_location",
        );
    }

    ("needs_review", "loaded_driver_signature_not_trusted")
}

fn normalize_driver_path(value: &str) -> String {
    let value = value.trim().trim_matches('"');

    value
        .strip_prefix(r"\??\")
        .or_else(|| value.strip_prefix(r"\\?\"))
        .unwrap_or(value)
        .trim_matches('"')
        .to_string()
}

fn is_standard_driver_location(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();

    normalized.contains(r"\windows\system32\drivers\")
        || normalized.contains(r"\windows\system32\driverstore\filerepository\")
        || normalized.contains(r"\windows\system32\drivers\wd\")
}

fn push_unique(values: &mut Vec<String>, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };

    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(value))
    {
        values.push(value.to_string());
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(status: &str, checked: bool, trusted: bool) -> AuthenticodeVerification {
        AuthenticodeVerification {
            checked,
            trusted,
            status: status.to_string(),
            status_code: None,
            source: "test".to_string(),
        }
    }

    #[test]
    fn failed_kernel_posture_is_rejected() {
        assert!(validate_success(&json!({"success": false}), "kernel").is_err());
        assert!(validate_success(&json!({}), "kernel").is_err());
        assert!(validate_success(&json!({"success": true}), "kernel").is_ok());
    }

    #[test]
    fn valid_driver_is_trusted() {
        assert_eq!(
            classify_driver(&signature("Valid", true, true), true),
            ("trusted", "native_signature_valid")
        );
    }

    #[test]
    fn invalid_nonstandard_driver_requires_review() {
        assert_eq!(
            classify_driver(&signature("BadDigest", true, false), false),
            (
                "needs_review",
                "untrusted_driver_outside_standard_windows_location"
            )
        );
    }

    #[test]
    fn unchecked_driver_is_unknown() {
        assert_eq!(
            classify_driver(&signature("NotChecked", false, false), true),
            ("unknown", "signature_not_checked")
        );
    }

    #[test]
    fn standard_windows_locations_are_recognized() {
        assert!(is_standard_driver_location(
            r"C:\WINDOWS\system32\drivers\WdFilter.sys"
        ));
        assert!(is_standard_driver_location(
            r"C:\WINDOWS\system32\DriverStore\FileRepository\net.inf\driver.sys"
        ));
        assert!(!is_standard_driver_location(
            r"C:\Users\TestUser\Downloads\driver.sys"
        ));
    }

    #[test]
    fn duplicate_paths_are_grouped() {
        let posture = json!({
            "running_drivers": [
                {
                    "Name": "One",
                    "PathName": r"C:\WINDOWS\system32\drivers\same.sys",
                    "ServiceType": "Kernel Driver",
                    "StartMode": "Boot"
                },
                {
                    "Name": "Two",
                    "PathName": r"C:\WINDOWS\system32\drivers\same.sys",
                    "ServiceType": "Kernel Driver",
                    "StartMode": "System"
                }
            ]
        });

        let groups = collect_driver_groups(&posture);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].names, vec!["One", "Two"]);
        assert_eq!(groups[0].start_modes, vec!["Boot", "System"]);
    }
}
