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
#[command(name = "axios-remote-access-review")]
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
        throw
    }
}

$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$remoteAssistancePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
$smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

function Get-AxiosService {
    param([string]$Name)

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        return Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    }

    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        return Get-WmiObject Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    }

    throw "Neither Get-CimInstance nor Get-WmiObject is available."
}

$services = @(
    "TermService", "WinRM", "RemoteRegistry", "LanmanServer" |
        ForEach-Object {
            $serviceName = [string]$_
            $service = Get-AxiosService $serviceName

            if ($null -eq $service) {
                [PSCustomObject]@{
                    name = $serviceName
                    available = $false
                }
            } else {
                [PSCustomObject]@{
                    name = $serviceName
                    available = $true
                    state = [string]$service.State
                    start_mode = [string]$service.StartMode
                }
            }
        }
)

[PSCustomObject]@{
    success = $true
    rdp = [PSCustomObject]@{
        denied = Read-AxiosRegistryValue $rdpPath "fDenyTSConnections"
        nla = Read-AxiosRegistryValue $rdpTcpPath "UserAuthentication"
    }
    remote_assistance = [PSCustomObject]@{
        allow_help = Read-AxiosRegistryValue $remoteAssistancePath "fAllowToGetHelp"
        allow_full_control = Read-AxiosRegistryValue $remoteAssistancePath "fAllowFullControl"
    }
    smb_server = [PSCustomObject]@{
        smb1 = Read-AxiosRegistryValue $smbServerPath "SMB1"
        require_signing = Read-AxiosRegistryValue $smbServerPath "RequireSecuritySignature"
    }
    smb_client = [PSCustomObject]@{
        require_signing = Read-AxiosRegistryValue $smbClientPath "RequireSecuritySignature"
    }
    services = $services
} | ConvertTo-Json -Depth 7 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("remote access collector failed: {}", output.stderr);
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

    let rdp_enabled = snapshot.pointer("/rdp/denied").and_then(observed_enabled) == Some(false);

    if rdp_enabled {
        let nla_enabled = snapshot.pointer("/rdp/nla").and_then(observed_enabled) == Some(true);

        findings.push(json!({
            "priority": if nla_enabled { "medium" } else { "high" },
            "id": "remote_desktop_enabled",
            "classification": if nla_enabled {
                "remote_access_exposure"
            } else {
                "remote_desktop_without_nla"
            },
            "reason": if nla_enabled {
                "Remote Desktop is enabled; correlate with firewall and listening-port evidence"
            } else {
                "Remote Desktop is enabled without Network Level Authentication"
            }
        }));
    }

    if snapshot
        .pointer("/remote_assistance/allow_full_control")
        .and_then(observed_enabled)
        == Some(true)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "remote_assistance_full_control_enabled",
            "classification": "remote_access_exposure",
            "reason": "Remote Assistance permits full control"
        }));
    }

    if snapshot
        .pointer("/smb_server/smb1")
        .and_then(observed_enabled)
        == Some(true)
    {
        findings.push(json!({
            "priority": "high",
            "id": "smb1_enabled",
            "classification": "legacy_network_protocol_enabled",
            "reason": "SMBv1 is enabled"
        }));
    }

    let smb_signing_not_required_on: Vec<&str> = [
        ("server", "/smb_server/require_signing"),
        ("client", "/smb_client/require_signing"),
    ]
    .into_iter()
    .filter_map(|(side, pointer)| {
        (snapshot.pointer(pointer).and_then(observed_enabled) == Some(false)).then_some(side)
    })
    .collect();

    if !smb_signing_not_required_on.is_empty() {
        findings.push(json!({
            "priority": "medium",
            "id": "smb_signing_not_required",
            "classification": "smb_integrity_control_weakened",
            "affected_sides": smb_signing_not_required_on,
            "reason": "SMB signing is not required by observed configuration"
        }));
    }

    for service in snapshot
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let name = service.get("name").and_then(Value::as_str).unwrap_or("");

        let running = service
            .get("state")
            .and_then(Value::as_str)
            .map(|state| state.eq_ignore_ascii_case("running"))
            .unwrap_or(false);

        if running && matches!(name, "WinRM" | "RemoteRegistry") {
            findings.push(json!({
                "priority": "medium",
                "id": format!("remote_management_service_running:{name}"),
                "classification": "remote_management_exposure",
                "service": name,
                "reason": "remote management service is running; correlate with listener and firewall evidence"
            }));
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

    json!({
        "success": true,
        "collector": "axios_remote_access_review",
        "read_only": true,
        "database_used": false,
        "backdoor_confirmed": false,
        "policy": {
            "enabled_remote_service": "exposure_requires_network_correlation",
            "smb1": "high_priority_configuration_finding_not_intrusion_proof",
            "remote_access": "not_a_backdoor_verdict"
        },
        "summary": {
            "high_priority_findings": high,
            "medium_priority_findings": medium
        },
        "findings": findings,
        "snapshot": snapshot
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn registry_read_failure_is_not_silently_converted_to_clean_data() {
        let source = include_str!("axios-remote-access-review.rs");

        assert!(source.contains("catch {\n        throw\n    }"));
        assert!(!source.contains("catch {\n        $null\n    }"));
    }
    use super::*;

    #[test]
    fn smb1_is_high_priority() {
        let report = build_report(&json!({
            "smb_server": { "smb1": 1 }
        }));

        assert_eq!(report["findings"][0]["priority"], "high");
    }

    #[test]
    fn rdp_with_nla_is_medium_priority() {
        let report = build_report(&json!({
            "rdp": { "denied": 0, "nla": 1 }
        }));

        assert_eq!(report["findings"][0]["priority"], "medium");
    }

    #[test]
    fn smb_signing_gap_is_merged_with_affected_sides() {
        let report = build_report(&serde_json::json!({
            "smb_server": {"smb1": 0, "require_signing": 0},
            "smb_client": {"require_signing": 0},
            "services": []
        }));

        let findings: Vec<_> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"].as_str() == Some("smb_signing_not_required"))
            .collect();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0]["affected_sides"],
            serde_json::json!(["server", "client"])
        );
    }

    #[test]
    fn remote_service_collection_supports_cim_and_legacy_wmi() {
        let source = include_str!("axios-remote-access-review.rs");

        assert!(source.contains("Get-Command Get-CimInstance"));
        assert!(source.contains("Get-Command Get-WmiObject"));
        assert!(source
            .contains("Get-CimInstance Win32_Service -Filter \"Name='$Name'\" -ErrorAction Stop"));
        assert!(source
            .contains("Get-WmiObject Win32_Service -Filter \"Name='$Name'\" -ErrorAction Stop"));
        assert!(source.contains("Neither Get-CimInstance nor Get-WmiObject is available."));
    }
}
