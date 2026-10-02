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
#[command(name = "axios-platform-hardening-review")]
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
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
            return $null
        }

        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        $property = $item.PSObject.Properties[$Name]

        if ($null -eq $property) {
            return $null
        }

        $property.Value
    }
    catch {
        throw
    }
}

$updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

$featureNames = @(
    "SMB1Protocol",
    "TelnetClient",
    "TFTP",
    "IIS-WebServerRole",
    "OpenSSH.Server",
    "Microsoft-Hyper-V-All",
    "VirtualMachinePlatform",
    "Microsoft-Windows-Subsystem-Linux"
)

try {
    $features = @(
        foreach ($featureName in $featureNames) {
            Get-WindowsOptionalFeature -Online `
                -FeatureName $featureName -ErrorAction Stop |
                Where-Object { $_.FeatureName -eq $featureName } |
                Select-Object FeatureName, @{
                    Name = "State"
                    Expression = { [string]$_.State }
                }
        }
    )
}
catch {
    $features = @(
        Get-WindowsOptionalFeature -Online -ErrorAction Stop |
            Where-Object { $_.FeatureName -in $featureNames } |
            Select-Object FeatureName, State
    )
}

$serviceNames = @("wuauserv", "BITS", "UsoSvc", "TrustedInstaller", "sshd")
$serviceIndex = @{}

Get-CimInstance Win32_Service -ErrorAction Stop |
    Where-Object { $_.Name -in $serviceNames } |
    ForEach-Object {
        $serviceIndex[$_.Name] = $_
    }

$services = @(
    $serviceNames |
        ForEach-Object {
            $service = $serviceIndex[$_]

            if ($null -eq $service) {
                [PSCustomObject]@{
                    name = $_
                    available = $false
                }
            } else {
                [PSCustomObject]@{
                    name = $_
                    available = $true
                    state = [string]$service.State
                    start_mode = [string]$service.StartMode
                }
            }
        }
)

$computer = Get-CimInstance Win32_ComputerSystem

[PSCustomObject]@{
    success = $true
    update_policy = [PSCustomObject]@{
        no_auto_update = Read-AxiosRegistryValue $updatePath "NoAutoUpdate"
        au_options = Read-AxiosRegistryValue $updatePath "AUOptions"
    }
    optional_features = $features
    services = $services
    virtualization = [PSCustomObject]@{
        hypervisor_present = [bool]$computer.HypervisorPresent
    }
} | ConvertTo-Json -Depth 8 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("platform hardening collector failed: {}", output.stderr);
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

fn feature_enabled(feature: &Value) -> bool {
    feature
        .get("State")
        .and_then(Value::as_str)
        .map(|value| value.eq_ignore_ascii_case("Enabled"))
        .unwrap_or(false)
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

    if snapshot
        .pointer("/update_policy/no_auto_update")
        .and_then(observed_enabled)
        == Some(true)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "windows_automatic_updates_disabled_by_policy",
            "classification": "patch_management_control_weakened",
            "reason": "Windows Update policy disables automatic updates"
        }));
    }

    for service in snapshot
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let name = service.get("name").and_then(Value::as_str).unwrap_or("");
        let start_mode = service
            .get("start_mode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();

        if matches!(name, "wuauserv" | "BITS" | "UsoSvc") && start_mode == "disabled" {
            findings.push(json!({
                "priority": "medium",
                "id": format!("update_service_disabled:{name}"),
                "classification": "patch_management_control_weakened",
                "reason": "Windows Update-related service is disabled"
            }));
        }

        if name == "sshd"
            && service
                .get("state")
                .and_then(Value::as_str)
                .map(|state| state.eq_ignore_ascii_case("running"))
                .unwrap_or(false)
        {
            findings.push(json!({
                "priority": "medium",
                "id": "openssh_server_running",
                "classification": "remote_access_exposure",
                "reason": "OpenSSH Server is running; correlate with listening-port and firewall evidence"
            }));
        }
    }

    for feature in snapshot
        .get("optional_features")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let name = feature
            .get("FeatureName")
            .and_then(Value::as_str)
            .unwrap_or("");

        if !feature_enabled(&feature) {
            continue;
        }

        match name {
            "SMB1Protocol" => findings.push(json!({
                "priority": "high",
                "id": "smb1_optional_feature_enabled",
                "classification": "legacy_network_protocol_enabled",
                "reason": "SMBv1 optional feature is enabled"
            })),
            "TelnetClient" | "TFTP" => findings.push(json!({
                "priority": "medium",
                "id": format!("legacy_client_feature_enabled:{name}"),
                "classification": "legacy_network_feature_enabled",
                "reason": "legacy network client feature is enabled"
            })),
            "OpenSSH.Server" => findings.push(json!({
                "priority": "context",
                "id": "openssh_server_feature_enabled",
                "classification": "remote_access_feature_present",
                "reason": "OpenSSH Server feature is installed; service state determines active exposure"
            })),
            "IIS-WebServerRole" => findings.push(json!({
                "priority": "context",
                "id": "iis_web_server_feature_enabled",
                "classification": "server_feature_present",
                "reason": "IIS feature is installed; listener and firewall evidence determine active exposure"
            })),
            "Microsoft-Hyper-V-All"
            | "VirtualMachinePlatform"
            | "Microsoft-Windows-Subsystem-Linux" => findings.push(json!({
                "priority": "context",
                "id": format!("virtualization_feature_enabled:{name}"),
                "classification": "virtualization_context",
                "reason": "virtualization feature is enabled; this is not a compromise finding"
            })),
            _ => {}
        }
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
        "collector": "axios_platform_hardening_review",
        "read_only": true,
        "database_used": false,
        "virtualization_escape_confirmed": false,
        "policy": {
            "smb1": "high_priority_configuration_finding_not_intrusion_proof",
            "remote_server_feature": "requires_listener_and_firewall_correlation",
            "virtualization": "normal_context_not_vm_escape_evidence"
        },
        "summary": {
            "high_priority_findings": high,
            "medium_priority_findings": medium,
            "context_findings": context
        },
        "findings": findings,
        "snapshot": snapshot
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn registry_read_failure_is_not_silently_converted_to_clean_data() {
        let source = include_str!("axios-platform-hardening-review.rs");

        assert!(source.contains("catch {\n        throw\n    }"));
        assert!(!source.contains("catch {\n        $null\n    }"));
    }
    use super::*;

    #[test]
    fn smb1_feature_is_high_priority() {
        let report = build_report(&json!({
            "optional_features": [{
                "FeatureName": "SMB1Protocol",
                "State": "Enabled"
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "high");
    }

    #[test]
    fn virtualization_feature_is_context() {
        let report = build_report(&json!({
            "optional_features": [{
                "FeatureName": "VirtualMachinePlatform",
                "State": "Enabled"
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "context");
    }

    #[test]
    fn unavailable_update_policy_is_not_claimed_disabled() {
        let report = build_report(&serde_json::json!({
            "update_policy": {"no_auto_update": null},
            "services": [],
            "optional_features": []
        }));

        assert!(!report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["id"].as_str() == Some("windows_automatic_updates_disabled_by_policy")
            }));
    }

    #[test]
    fn platform_service_collection_does_not_suppress_errors() {
        let source = include_str!("axios-platform-hardening-review.rs");
        let suppressed = concat!(
            "Get-CimInstance Win32_Service -Filter \"Name='$($_)'\" -ErrorAction ",
            "SilentlyContinue"
        );
        let bulk_query = concat!("Get-CimInstance Win32_Service -ErrorAction ", "Stop");

        assert!(!source.contains(suppressed));
        assert_eq!(source.matches(bulk_query).count(), 1);
    }

    #[test]
    fn platform_service_collection_uses_one_bulk_wmi_query() {
        let source = include_str!("axios-platform-hardening-review.rs");

        assert!(source.contains("Where-Object { $_.Name -in $serviceNames }"));
        assert!(source.contains("$serviceIndex[$_.Name] = $_"));
    }
}
