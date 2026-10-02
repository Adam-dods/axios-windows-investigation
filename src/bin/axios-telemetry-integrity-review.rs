use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-telemetry-integrity-review")]
struct Options {
    #[arg(long, default_value = "current")]
    collection_scope: String,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let collection_scope = options.collection_scope;

    let snapshot = collect_snapshot()?;
    let mut report = build_report(&snapshot);

    report["collection_scope"] = json!(collection_scope);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_snapshot() -> Result<Value> {
    let script = r#"
$ErrorActionPreference = "Stop"

$channelNames = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational"
)

$channels = foreach ($channelName in $channelNames) {
    try {
        $log = Get-WinEvent -ListLog $channelName -ErrorAction Stop
        [PSCustomObject]@{
            name = $channelName
            available = $true
            enabled = [bool]$log.IsEnabled
            record_count = $log.RecordCount
            maximum_size_bytes = $log.MaximumSizeInBytes
            log_mode = [string]$log.LogMode
        }
    }
    catch {
        [PSCustomObject]@{
            name = $channelName
            available = $false
            enabled = $false
            collection_error = $_.Exception.Message
        }
    }
}

$services = foreach ($serviceName in @("eventlog", "WinDefend", "WdNisSvc")) {
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
        [PSCustomObject]@{
            name = $serviceName
            available = $true
            state = [string]$service.State
            start_mode = [string]$service.StartMode
        }
    }
    catch {
        [PSCustomObject]@{
            name = $serviceName
            available = $false
            collection_error = $_.Exception.Message
        }
    }
}

[PSCustomObject]@{
    success = $true
    channels = @($channels)
    services = @($services)
} | ConvertTo-Json -Depth 7 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        anyhow::bail!("telemetry integrity collector failed: {}", output.stderr);
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

fn build_report(snapshot: &Value) -> Value {
    let channels = snapshot
        .get("channels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let services = snapshot
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();

    for channel in &channels {
        let name = channel.get("name").and_then(Value::as_str).unwrap_or("");

        if !channel
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            findings.push(json!({
                "priority": "context",
                "classification": "telemetry_channel_unavailable",
                "id": format!("channel_unavailable:{name}"),
                "reason": "channel could not be queried; this limits local visibility"
            }));
            continue;
        }

        if channel.get("enabled").and_then(Value::as_bool) == Some(false) {
            let priority = if name == "Security" || name == "System" {
                "high"
            } else {
                "medium"
            };

            findings.push(json!({
                "priority": priority,
                "classification": "telemetry_channel_disabled",
                "id": format!("channel_disabled:{name}"),
                "reason": "security-relevant Windows event channel is disabled"
            }));
        }
    }

    for service in &services {
        let name = service.get("name").and_then(Value::as_str).unwrap_or("");

        if !service
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            findings.push(json!({
                "priority": "context",
                "classification": "telemetry_service_unavailable",
                "id": format!("service_unavailable:{name}"),
                "reason": "service state could not be queried"
            }));
            continue;
        }

        let state = service
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();

        if name == "eventlog" && state != "running" {
            findings.push(json!({
                "priority": "high",
                "classification": "event_log_service_not_running",
                "id": "windows_eventlog_service_not_running",
                "reason": "Windows Event Log service is not running; event visibility is materially reduced"
            }));
        } else if (name == "WinDefend" || name == "WdNisSvc") && state == "stopped" {
            findings.push(json!({
                "priority": "medium",
                "classification": "defender_telemetry_service_stopped",
                "id": format!("defender_service_stopped:{name}"),
                "reason": "Defender-related service is stopped; verify whether another supported antivirus product is active"
            }));
        }
    }

    let high = findings
        .iter()
        .filter(|item| item["priority"] == "high")
        .count();
    let medium = findings
        .iter()
        .filter(|item| item["priority"] == "medium")
        .count();
    let context = findings
        .iter()
        .filter(|item| item["priority"] == "context")
        .count();

    json!({
        "success": true,
        "collector": "axios_telemetry_integrity_review",
        "read_only": true,
        "database_used": false,
        "tampering_confirmed": false,
        "policy": {
            "disabled_security_or_system_log": "high_priority_visibility_failure",
            "eventlog_service_stopped": "high_priority_visibility_failure",
            "channel_unavailable": "not_clean_and_not_tampering_confirmation",
            "empty_log": "not_a_tampering_verdict"
        },
        "summary": {
            "channels_checked": channels.len(),
            "services_checked": services.len(),
            "high_priority_findings": high,
            "medium_priority_findings": medium,
            "context_visibility_notes": context
        },
        "findings": findings,
        "snapshot": snapshot
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_security_log_is_high_priority_visibility_failure() {
        let report = build_report(&json!({
            "channels": [
                {"name": "Security", "available": true, "enabled": false}
            ],
            "services": [
                {"name": "eventlog", "available": true, "state": "Running"}
            ]
        }));

        assert_eq!(report["summary"]["high_priority_findings"], 1);
        assert_eq!(report["tampering_confirmed"], false);
    }

    #[test]
    fn unavailable_channel_is_visibility_context_not_tampering_claim() {
        let report = build_report(&json!({
            "channels": [
                {"name": "Security", "available": false, "enabled": false}
            ],
            "services": []
        }));

        assert_eq!(report["summary"]["context_visibility_notes"], 1);
        assert_eq!(report["tampering_confirmed"], false);
    }

    #[test]
    fn missing_channel_state_is_not_claimed_disabled() {
        let report = build_report(&serde_json::json!({
            "channels": [{"name": "Security", "available": true}],
            "services": []
        }));

        assert!(!report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"].as_str() == Some("channel_disabled:Security")));
    }
}
