use anyhow::{bail, Context, Result};
use axios_core::{
    analysis::diff,
    storage::{baseline, json_file},
};
use chrono::Utc;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

const REQUIRED: &[&str] = &[
    "hardware",
    "kernel",
    "drivers",
    "persistence",
    "network",
    "updates",
];

fn main() -> Result<()> {
    let options = parse_options()?;
    let reports = load_reports(&options)?;
    let snapshot = sensitive_snapshot(&reports);
    let result = update_baseline(&options.state_dir, snapshot)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "collector": "axios_sensitive_baseline",
            "generated_at": Utc::now().to_rfc3339(),
            "baseline": result
        }))?
    );

    Ok(())
}

struct Options {
    reports: BTreeMap<String, PathBuf>,
    state_dir: PathBuf,
}

fn parse_options() -> Result<Options> {
    let mut args = env::args().skip(1);
    let mut reports = BTreeMap::new();
    let mut state_dir = default_state_dir();

    while let Some(flag) = args.next() {
        if flag == "--state-dir" {
            state_dir = PathBuf::from(args.next().context("--state-dir needs a directory")?);
            continue;
        }
        if flag == "--help" || flag == "-h" {
            println!("Usage: axios-sensitive-baseline.exe --hardware <json> --kernel <json> --drivers <json> --persistence <json> --network <json> --updates <json> [--state-dir <directory>]");
            std::process::exit(0);
        }
        let name = flag.strip_prefix("--").context("unknown argument")?;
        if !REQUIRED.contains(&name) {
            bail!("unknown argument: {flag}");
        }
        if reports.contains_key(name) {
            bail!("{flag} was provided more than once");
        }
        reports.insert(
            name.to_string(),
            PathBuf::from(args.next().context(format!("{flag} needs a file"))?),
        );
    }

    for name in REQUIRED {
        if !reports.contains_key(*name) {
            bail!("--{name} is required");
        }
    }

    Ok(Options { reports, state_dir })
}

fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(program_data) = env::var_os("ProgramData") {
        return PathBuf::from(program_data)
            .join("AXIOS")
            .join("sensitive-baseline");
    }

    PathBuf::from("axios-sensitive-baseline")
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

fn load_reports(options: &Options) -> Result<BTreeMap<String, Value>> {
    let mut output = BTreeMap::new();

    for (name, path) in &options.reports {
        let value = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;

        if !value.is_object() {
            bail!("{name} is not a JSON object");
        }

        let successful = if name == "persistence" {
            persistence_report_succeeded(&value)
        } else {
            value.get("success").and_then(Value::as_bool) == Some(true)
        };

        if !successful {
            bail!("{name} report is not successful");
        }

        output.insert(name.clone(), value);
    }

    Ok(output)
}

fn get(reports: &BTreeMap<String, Value>, name: &str, pointer: &str) -> Value {
    reports
        .get(name)
        .and_then(|report| report.pointer(pointer))
        .cloned()
        .unwrap_or(Value::Null)
}

fn sensitive_snapshot(reports: &BTreeMap<String, Value>) -> Value {
    json!({
        "snapshot_schema_version": 1,
        "boot_and_kernel": {
            "bcd_security": get(reports, "kernel", "/bcd_security"),
            "findings": get(reports, "kernel", "/findings")
        },
        "firmware_and_hardware": {
            "bios": get(reports, "hardware", "/bios"),
            "secure_boot": get(reports, "hardware", "/secure_boot"),
            "physical_disks": get(reports, "hardware", "/physical_disks")
        },
        "drivers": get(reports, "drivers", "/artifacts"),
        "persistence": reports.get("persistence").cloned().unwrap_or(Value::Null),
        "firewall_and_network": {
            "summary": get(reports, "network", "/summary"),
            "firewall_profiles": get(reports, "network", "/firewall_profiles")
        },
        "defender_and_updates": {
            "defender": get(reports, "updates", "/defender"),
            "operating_system": get(reports, "updates", "/operating_system"),
            "reboot": get(reports, "updates", "/reboot"),
            "pending_software_updates": get(reports, "updates", "/pending_software_updates")
        }
    })
}

fn update_baseline(state_dir: &Path, snapshot: Value) -> Result<Value> {
    fs::create_dir_all(state_dir)?;
    let latest = state_dir.join("latest-sensitive-baseline.json");
    let history = state_dir.join("history");
    fs::create_dir_all(&history)?;

    let existed = latest.is_file();
    let previous = if existed {
        baseline::load(&latest).ok()
    } else {
        None
    };
    let valid = previous
        .as_ref()
        .map(baseline::verify)
        .map(|item| item.valid);
    let integrity_alert = existed && valid != Some(true);

    let archive = if existed {
        let stamp = Utc::now().format("%Y%m%d-%H%M%S");
        let suffix = if integrity_alert {
            "invalid"
        } else {
            "verified"
        };
        let path = history.join(format!("baseline-{stamp}-{suffix}.json"));
        fs::copy(&latest, &path)?;
        Some(path.display().to_string())
    } else {
        None
    };

    let comparison = previous
        .as_ref()
        .filter(|_| !integrity_alert)
        .map(|old| diff::compare_stable(&old.snapshot, &snapshot));

    let changes: Vec<Value> = comparison
        .as_ref()
        .into_iter()
        .flat_map(|result| result.changes.iter())
        .filter(|change| {
            let p = change.path.to_ascii_lowercase();
            p.contains("boot")
                || p.contains("kernel")
                || p.contains("secure_boot")
                || p.contains("bios")
                || p.contains("physical_disks")
                || p.contains("drivers")
                || p.contains("persistence")
                || p.contains("firewall")
                || p.contains("network")
                || p.contains("defender")
                || p.contains("updates")
        })
        .take(100)
        .map(|change| {
            json!({
                "path": change.path,
                "kind": format!("{:?}", change.kind).to_ascii_lowercase(),
                "before": change.before,
                "after": change.after
            })
        })
        .collect();

    let current = baseline::create(snapshot);
    json_file::write_pretty(&latest, &current)?;

    Ok(json!({
        "state_directory": state_dir,
        "latest_baseline": latest,
        "baseline_created": !existed,
        "previous_baseline_valid": valid,
        "baseline_integrity_alert": integrity_alert,
        "previous_baseline_archive": archive,
        "current_snapshot_sha256": current.snapshot_sha256,
        "stable_change_count": comparison.as_ref().map(|x| x.change_count).unwrap_or(0),
        "sensitive_changes": changes
    }))
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
}
