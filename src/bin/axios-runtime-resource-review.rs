use anyhow::{bail, Result};
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-runtime-resource-review")]
struct Options {
    #[arg(long)]
    processes: PathBuf,
    #[arg(long, default_value_t = 30)]
    max_processes: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_processes == 0 || options.max_processes > 100 {
        bail!("max-processes must be between 1 and 100");
    }

    let process_report = json_file::read_value(&options.processes)?;
    if process_report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("process report is not successful");
    }

    let snapshot = collect_snapshot(options.max_processes)?;
    let report = build_report(&snapshot, &process_report);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_snapshot(max_processes: usize) -> Result<Value> {
    let script = format!(
        r#"
$ErrorActionPreference = "Stop"
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem

$top = Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First {max_processes} `
        Id, ProcessName, CPU, WorkingSet64, PagedMemorySize64, HandleCount, Path

[PSCustomObject]@{{
    success = $true
    collected_at_utc = [DateTime]::UtcNow.ToString("o")
    operating_system = [PSCustomObject]@{{
        total_visible_memory_kb = [UInt64]$os.TotalVisibleMemorySize
        free_physical_memory_kb = [UInt64]$os.FreePhysicalMemory
        last_boot_up_time = $os.LastBootUpTime
    }}
    computer_system = [PSCustomObject]@{{
        logical_processors = [UInt32]$computer.NumberOfLogicalProcessors
        total_physical_memory_bytes = [UInt64]$computer.TotalPhysicalMemory
    }}
    top_working_set_processes = @($top)
}} | ConvertTo-Json -Depth 6 -Compress
"#
    );

    let output = powershell(&script)?;
    if !output.success {
        bail!("runtime resource collector failed: {}", output.stderr);
    }

    Ok(parse_json_output(output))
}

#[cfg(not(windows))]
fn collect_snapshot(_max_processes: usize) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collection_status": "windows_only"
    }))
}

fn build_report(snapshot: &Value, process_report: &Value) -> Value {
    let total_kb = snapshot
        .pointer("/operating_system/total_visible_memory_kb")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let free_kb = snapshot
        .pointer("/operating_system/free_physical_memory_kb")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let memory_used_percent = if total_kb == 0 {
        None
    } else {
        Some(((total_kb.saturating_sub(free_kb)) * 100) / total_kb)
    };

    let process_findings = process_report
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut correlated = Vec::new();

    for process in snapshot
        .get("top_working_set_processes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let pid = process.get("Id").and_then(Value::as_u64);

        let suspicious = pid.and_then(|id| {
            process_findings.iter().find(|item| {
                item.get("pid").and_then(Value::as_u64) == Some(id)
                    && item.get("classification").and_then(Value::as_str) == Some("needs_review")
            })
        });

        if let Some(process_evidence) = suspicious {
            correlated.push(json!({
                "priority": "medium",
                "pid": pid,
                "name": process.get("ProcessName").cloned().unwrap_or(Value::Null),
                "working_set_bytes": process.get("WorkingSet64").cloned().unwrap_or(Value::Null),
                "process_evidence": {
                    "classification": process_evidence.get("classification").cloned().unwrap_or(Value::Null),
                    "reason": process_evidence.get("reason").cloned().unwrap_or(Value::Null),
                    "user_writable_location": process_evidence.get("user_writable_location").cloned().unwrap_or(Value::Null),
                    "parent_mismatch": process_evidence.get("parent_mismatch").cloned().unwrap_or(Value::Null)
                },
                "reason": "resource_observation_correlates_with_existing_process_review_signal"
            }));
        }
    }

    let pressure = match memory_used_percent {
        Some(value) if value >= 95 => "high",
        Some(value) if value >= 85 => "elevated",
        Some(_) => "normal",
        None => "unknown",
    };

    json!({
        "success": true,
        "collector": "axios_runtime_resource_review",
        "read_only": true,
        "snapshot_only": true,
        "malware_confirmed": false,
        "rootkit_confirmed": false,
        "policy": {
            "high_cpu_or_memory_alone": "not_a_malware_verdict",
            "resource_pressure": "system_health_context",
            "process_escalation": "requires_existing_process_evidence"
        },
        "summary": {
            "memory_used_percent": memory_used_percent,
            "memory_pressure": pressure,
            "top_processes_examined": snapshot
                .get("top_working_set_processes")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            "correlated_process_review_items": correlated.len()
        },
        "system_snapshot": snapshot,
        "artifacts": correlated
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_memory_use_alone_does_not_create_malware_finding() {
        let report = build_report(
            &json!({
                "operating_system": {
                    "total_visible_memory_kb": 1000,
                    "free_physical_memory_kb": 10
                },
                "top_working_set_processes": []
            }),
            &json!({"success": true, "artifacts": []}),
        );

        assert_eq!(report["summary"]["memory_pressure"], "high");
        assert!(report["artifacts"].as_array().unwrap().is_empty());
        assert_eq!(report["malware_confirmed"], false);
    }
}
