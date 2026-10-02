#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "axios-observation-integrity-review")]
struct Options {
    #[arg(long)]
    processes: PathBuf,

    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    let processes = json_file::read_value(&options.processes)?;
    validate_success(&processes, "process integrity")?;

    let snapshot = collect_snapshot()?;
    validate_success(&snapshot, "independent observation")?;

    let report = build_report(&processes, &snapshot);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

#[cfg(windows)]
fn collect_snapshot() -> Result<Value> {
    let script = r#"
$ErrorActionPreference = "Stop"

$cimProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        ForEach-Object { [uint32]$_.ProcessId } |
        Sort-Object -Unique
)

$dotNetProcesses = @(
    [System.Diagnostics.Process]::GetProcesses() |
        ForEach-Object {
            try {
                [uint32]$_.Id
            }
            catch {
                $null
            }
        } |
        Where-Object { $null -ne $_ } |
        Sort-Object -Unique
)

[PSCustomObject]@{
    success = $true
    sources = @{
        cim_process_ids = @($cimProcesses)
        dotnet_process_ids = @($dotNetProcesses)
    }
} | ConvertTo-Json -Depth 6 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("observation integrity collector failed: {}", output.stderr);
    }

    Ok(parse_json_output(output))
}

#[cfg(not(windows))]
fn collect_snapshot() -> Result<Value> {
    Ok(json!({
        "success": false,
        "collection_status": "windows_only"
    }))
}

fn process_ids(value: &Value, pointer: &str) -> BTreeSet<u32> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("pid").and_then(Value::as_u64))
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect()
}

fn numeric_ids(value: &Value, pointer: &str) -> BTreeSet<u32> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect()
}

fn ids_json(ids: &BTreeSet<u32>) -> Vec<u32> {
    ids.iter().copied().collect()
}

fn build_report(processes: &Value, snapshot: &Value) -> Value {
    let primary = process_ids(processes, "/artifacts");
    let cim = numeric_ids(snapshot, "/sources/cim_process_ids");
    let dotnet = numeric_ids(snapshot, "/sources/dotnet_process_ids");

    let independently_observed: BTreeSet<u32> = cim.union(&dotnet).copied().collect();
    let primary_missing_from_independent: BTreeSet<u32> = primary
        .difference(&independently_observed)
        .copied()
        .collect();
    let independent_source_difference: BTreeSet<u32> =
        cim.symmetric_difference(&dotnet).copied().collect();

    let mut findings = Vec::new();

    if !independent_source_difference.is_empty() {
        findings.push(json!({
            "priority": "context",
            "classification": "independent_process_source_difference",
            "reason": "CIM and .NET process observations differ; this is a visibility/timing signal, not malware proof",
            "process_ids": ids_json(&independent_source_difference)
        }));
    }

    let contradictions = findings.len();
    let confidence = if contradictions == 0 {
        "cross_source_consistent"
    } else {
        "cross_source_difference_observed"
    };

    json!({
        "schema_version": 1,
        "collector": "axios_observation_integrity_review",
        "success": true,
        "read_only": true,
        "database_used": false,
        "kernel_compromise_confirmed": false,
        "malware_confirmed": false,
        "policy": {
            "independent_source_difference": "same-window CIM/.NET difference is visibility context, not malware proof",
            "earlier_primary_snapshot": "a process report from an earlier pipeline stage is temporal context and is not counted as a cross-source contradiction",
            "same_host_limit": "local_user_mode sources cannot definitively rule out kernel or firmware compromise"
        },
        "summary": {
            "primary_processes_observed": primary.len(),
            "primary_processes_not_currently_observed": primary_missing_from_independent.len(),
            "cim_processes_observed": cim.len(),
            "dotnet_processes_observed": dotnet.len(),
            "cross_source_contradictions": contradictions,
            "collection_confidence": confidence
        },
        "findings": findings,
        "sources": {
            "process_integrity": ids_json(&primary),
            "cim": ids_json(&cim),
            "dotnet": ids_json(&dotnet)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_process_sources_are_cross_source_consistent() {
        let report = build_report(
            &json!({"artifacts": [{"pid": 10}, {"pid": 20}]}),
            &json!({
                "sources": {
                    "cim_process_ids": [10, 20],
                    "dotnet_process_ids": [10, 20]
                }
            }),
        );

        assert_eq!(
            report["summary"]["collection_confidence"],
            "cross_source_consistent"
        );
        assert!(report["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn earlier_primary_snapshot_delta_is_not_a_contradiction() {
        let report = build_report(
            &json!({"artifacts": [{"pid": 10}, {"pid": 99}]}),
            &json!({
                "sources": {
                    "cim_process_ids": [10],
                    "dotnet_process_ids": [10]
                }
            }),
        );

        assert_eq!(report["malware_confirmed"], false);
        assert_eq!(
            report["summary"]["collection_confidence"],
            "cross_source_consistent"
        );
        assert_eq!(report["summary"]["cross_source_contradictions"], 0);
        assert_eq!(
            report["summary"]["primary_processes_not_currently_observed"],
            1
        );
        assert!(report["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn same_window_independent_difference_is_context_not_malware() {
        let report = build_report(
            &json!({"artifacts": [{"pid": 10}]}),
            &json!({
                "sources": {
                    "cim_process_ids": [10],
                    "dotnet_process_ids": [10, 99]
                }
            }),
        );

        assert_eq!(report["malware_confirmed"], false);
        assert_eq!(
            report["summary"]["collection_confidence"],
            "cross_source_difference_observed"
        );
        assert_eq!(report["summary"]["cross_source_contradictions"], 1);
        assert_eq!(
            report["findings"][0]["classification"],
            "independent_process_source_difference"
        );
    }

    #[test]
    fn failed_inputs_are_rejected() {
        assert!(validate_success(&json!({"success": false}), "processes").is_err());
        assert!(validate_success(&json!({}), "snapshot").is_err());
        assert!(validate_success(&json!({"success": true}), "snapshot").is_ok());
    }
}
