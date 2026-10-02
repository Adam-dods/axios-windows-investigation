#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-execution-policy-review")]
struct Options {
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let snapshot = collect_snapshot()?;
    let report = build_report(&snapshot);

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

function Read-AxiosRegistryValue($Path, $Name) {
    try {
        (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        $null
    }
}

$scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

function Get-AxiosService {
    param([string]$Name)

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        return Get-CimInstance Win32_Service `
            -Filter ("Name='{0}'" -f $Name) `
            -ErrorAction SilentlyContinue
    }

    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        return Get-WmiObject Win32_Service `
            -Filter ("Name='{0}'" -f $Name) `
            -ErrorAction SilentlyContinue
    }

    return $null
}

$appIdService = Get-AxiosService "AppIDSvc"
$appLockerAvailable = $false

try {
    Get-AppLockerPolicy -Effective -ErrorAction Stop | Out-Null
    $appLockerAvailable = $true
}
catch {
    $appLockerAvailable = $false
}

[PSCustomObject]@{
    success = $true
    execution_policies = @(
        Get-ExecutionPolicy -List |
            Select-Object Scope, ExecutionPolicy
    )
    powershell_logging = [PSCustomObject]@{
        script_block = Read-AxiosRegistryValue $scriptBlockPath "EnableScriptBlockLogging"
        module = Read-AxiosRegistryValue $modulePath "EnableModuleLogging"
        transcription = Read-AxiosRegistryValue $transcriptionPath "EnableTranscripting"
    }
    audit = [PSCustomObject]@{
        process_command_line = Read-AxiosRegistryValue $auditPath "ProcessCreationIncludeCmdLine_Enabled"
    }
    applocker = [PSCustomObject]@{
        effective_policy_query_available = $appLockerAvailable
        service_available = ($null -ne $appIdService)
        service_state = if ($null -eq $appIdService) { $null } else { [string]$appIdService.State }
        service_start_mode = if ($null -eq $appIdService) { $null } else { [string]$appIdService.StartMode }
    }
} | ConvertTo-Json -Depth 7 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("execution policy collector failed: {}", output.stderr);
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

fn enabled(value: &Value) -> bool {
    value
        .as_i64()
        .map(|number| number != 0)
        .unwrap_or_else(|| value.as_bool().unwrap_or(false))
}

fn observed_enabled(value: &Value) -> Option<bool> {
    if value.is_null() {
        None
    } else {
        Some(enabled(value))
    }
}

fn build_report(snapshot: &Value) -> Value {
    let mut findings = Vec::new();

    for policy in snapshot
        .get("execution_policies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let scope = policy.get("Scope").and_then(Value::as_str).unwrap_or("");
        let value = policy
            .get("ExecutionPolicy")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();

        if matches!(scope, "MachinePolicy" | "UserPolicy")
            && matches!(value.as_str(), "bypass" | "unrestricted")
        {
            findings.push(json!({
                "priority": "medium",
                "id": format!("powershell_policy_weakened:{scope}"),
                "classification": "powershell_execution_policy_weakened",
                "scope": scope,
                "execution_policy": value,
                "reason": "a centrally effective PowerShell execution policy permits unrestricted execution"
            }));
        }
    }

    for (name, pointer) in [
        ("script_block_logging", "/powershell_logging/script_block"),
        ("module_logging", "/powershell_logging/module"),
        ("transcription", "/powershell_logging/transcription"),
    ] {
        if snapshot.pointer(pointer).and_then(observed_enabled) == Some(false) {
            findings.push(json!({
                "priority": "medium",
                "id": format!("powershell_{name}_disabled"),
                "classification": "powershell_telemetry_visibility_gap",
                "reason": "PowerShell security logging control is explicitly disabled"
            }));
        }
    }

    if snapshot
        .pointer("/audit/process_command_line")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "process_command_line_auditing_disabled",
            "classification": "execution_audit_visibility_gap",
            "reason": "process command-line auditing is explicitly disabled"
        }));
    }

    if snapshot
        .pointer("/applocker/effective_policy_query_available")
        .and_then(Value::as_bool)
        == Some(false)
    {
        findings.push(json!({
            "priority": "context",
            "id": "applocker_effective_policy_unavailable",
            "classification": "application_control_visibility_limited",
            "reason": "effective AppLocker policy could not be queried; this is not proof that application control is disabled"
        }));
    }

    let high = findings
        .iter()
        .filter(|finding| finding["priority"] == "high")
        .count();

    let medium = findings
        .iter()
        .filter(|finding| finding["priority"] == "medium")
        .count();

    let context = findings
        .iter()
        .filter(|finding| finding["priority"] == "context")
        .count();

    json!({
        "success": true,
        "collector": "axios_execution_policy_review",
        "read_only": true,
        "database_used": false,
        "malware_confirmed": false,
        "policy": {
            "weakened_execution_policy": "configuration_finding_not_intrusion_proof",
            "disabled_logging": "visibility_gap_not_tampering_confirmation",
            "applocker_unavailable": "visibility_limited"
        },
        "summary": {
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
    fn machine_policy_bypass_requires_review() {
        let report = build_report(&json!({
            "execution_policies": [{
                "Scope": "MachinePolicy",
                "ExecutionPolicy": "Bypass"
            }]
        }));

        assert_eq!(report["summary"]["medium_priority_findings"], 1);
    }

    #[test]
    fn unavailable_applocker_is_visibility_context() {
        let report = build_report(&json!({
            "applocker": {
                "effective_policy_query_available": false
            }
        }));

        assert_eq!(report["findings"][0]["priority"], "context");
    }

    #[test]
    fn unavailable_telemetry_values_are_not_claimed_disabled() {
        let report = build_report(&serde_json::json!({
            "powershell_logging": {
                "script_block": null,
                "module": null,
                "transcription": null
            },
            "audit": {"process_command_line": null}
        }));

        assert!(report["findings"].as_array().unwrap().is_empty());
    }
}
