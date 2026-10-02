use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs, path::PathBuf};

#[derive(Deserialize)]
struct Feed {
    schema_version: u32,
    advisories: Vec<Advisory>,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    component: String,
    manufacturer: Option<String>,
    model: Option<String>,
    affected_versions: Vec<String>,
    source_url: String,
    published_at: String,
    severity: String,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let mut hardware = None;
    let mut drivers = None;
    let mut updates = None;
    let mut feed = None;

    let mut supplied = BTreeSet::new();

    while let Some(flag) = args.next() {
        if flag == "--help" {
            println!(
                "Usage: axios-hardware-advisory.exe --hardware <json> --drivers <json> --updates <json> [--advisory-feed <json>]"
            );
            return Ok(());
        }

        if !matches!(
            flag.as_str(),
            "--hardware" | "--drivers" | "--updates" | "--advisory-feed"
        ) {
            bail!("unknown argument: {flag}");
        }

        if !supplied.insert(flag.clone()) {
            bail!("{flag} was supplied more than once");
        }

        let value = PathBuf::from(args.next().context(format!("{flag} needs a file"))?);

        match flag.as_str() {
            "--hardware" => hardware = Some(value),
            "--drivers" => drivers = Some(value),
            "--updates" => updates = Some(value),
            "--advisory-feed" => feed = Some(value),
            _ => unreachable!("validated advisory argument"),
        }
    }

    let hardware = read(hardware.context("--hardware is required")?)?;
    let drivers = read(drivers.context("--drivers is required")?)?;
    let updates = read(updates.context("--updates is required")?)?;
    let inventory = inventory(&hardware, &drivers, &updates);

    let (status, feed_hash, matches, note) = if let Some(path) = feed {
        let raw = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let parsed: Feed = serde_json::from_slice(&raw).context("invalid advisory feed JSON")?;
        if parsed.schema_version != 1 {
            bail!("unsupported advisory feed schema");
        }

        let mut matches = Vec::new();
        for item in &inventory {
            for advisory in &parsed.advisories {
                validate_advisory(advisory)?;
                if advisory
                    .component
                    .eq_ignore_ascii_case(item["component"].as_str().unwrap_or(""))
                    && equal(&advisory.manufacturer, item.get("manufacturer"))
                    && equal(&advisory.model, item.get("model"))
                    && advisory
                        .affected_versions
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(item["version"].as_str().unwrap_or("")))
                {
                    matches.push(json!({
                        "id": advisory.id,
                        "component": advisory.component,
                        "installed_component": item,
                        "severity": advisory.severity,
                        "source_url": advisory.source_url,
                        "published_at": advisory.published_at,
                        "classification": "potential_exposure_requires_vendor_verification"
                    }));
                }
            }
        }

        (
            "feed_evaluated",
            Some(hex::encode(Sha256::digest(raw))),
            matches,
            "A version match is not proof of exploitability, compromise, or a firmware backdoor.",
        )
    } else {
        (
            "trusted_feed_not_provided",
            None,
            vec![],
            "AXIOS collected inventory only. Without a trusted vendor or Microsoft advisory feed, it cannot claim that no firmware exposure exists."
        )
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "collector": "axios_hardware_advisory",
            "advisory_feed_status": status,
            "advisory_feed_sha256": feed_hash,
            "inventory": inventory,
            "potential_exposures": matches,
            "verification_note": note
        }))?
    );
    Ok(())
}

fn read(path: PathBuf) -> Result<Value> {
    let report = json_file::read_value(&path)?;
    if report["success"].as_bool() != Some(true) {
        bail!("report is not successful: {}", path.display());
    }
    Ok(report)
}

fn inventory(hardware: &Value, drivers: &Value, updates: &Value) -> Vec<Value> {
    let mut out = vec![json!({
        "component": "bios_uefi",
        "manufacturer": hardware["bios"]["Manufacturer"],
        "model": hardware["bios"]["Name"],
        "version": hardware["bios"]["SMBIOSBIOSVersion"]
    })];

    if let Some(disks) = hardware["physical_disks"].as_array() {
        for disk in disks {
            out.push(json!({
                "component": "storage_firmware",
                "manufacturer": Value::Null,
                "model": disk["Model"],
                "version": disk["FirmwareRevision"]
            }));
        }
    }

    if let Some(items) = drivers["artifacts"].as_array() {
        for item in items.iter().take(512) {
            out.push(json!({
                "component": "kernel_driver",
                "manufacturer": item["signer"],
                "model": item["driver_names"],
                "version": item["file_version"]
            }));
        }
    }

    out.push(json!({
        "component": "windows_build",
        "manufacturer": "Microsoft",
        "model": updates["operating_system"]["caption"],
        "version": format!("{}.{}", updates["operating_system"]["build_number"], updates["operating_system"]["ubr"])
    }));
    out
}

fn equal(expected: &Option<String>, actual: Option<&Value>) -> bool {
    match expected {
        None => true,
        Some(value) => actual
            .and_then(Value::as_str)
            .map(|x| x.eq_ignore_ascii_case(value))
            .unwrap_or(false),
    }
}

fn validate_advisory(item: &Advisory) -> Result<()> {
    if item.id.trim().is_empty()
        || item.source_url.trim().is_empty()
        || !item.source_url.starts_with("https://")
        || item.affected_versions.is_empty()
    {
        bail!("advisory feed contains incomplete evidence");
    }
    DateTime::parse_from_rfc3339(&item.published_at)
        .context("advisory published_at must be RFC3339")?;
    Ok(())
}
