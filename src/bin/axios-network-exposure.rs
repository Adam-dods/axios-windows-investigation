use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

const DEFAULT_MAX_ENDPOINTS: usize = 512;
const MAX_ENDPOINTS: usize = 1024;

#[derive(Parser, Debug)]
#[command(name = "axios-network-exposure")]
struct Options {
    #[arg(long)]
    live_activity: PathBuf,

    #[arg(long)]
    process_integrity: PathBuf,

    #[arg(long, default_value_t = DEFAULT_MAX_ENDPOINTS)]
    max_endpoints: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct LiveActivity {
    #[serde(default)]
    tcp_endpoints: Vec<Endpoint>,
    #[serde(default)]
    udp_endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize)]
struct Endpoint {
    process_id: Option<u32>,
    parent_process_id: Option<u32>,
    process_name: Option<String>,
    executable: Option<String>,
    protocol: Option<String>,
    local_address: Option<String>,
    local_port: Option<u16>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    state: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProcessIntegrity {
    #[serde(default)]
    artifacts: Vec<ProcessArtifact>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProcessArtifact {
    pid: Option<u32>,
    classification: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    command_signals: Vec<String>,
    user_writable_location: Option<bool>,
    signature: Option<SignatureSummary>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignatureSummary {
    checked: Option<bool>,
    trusted: Option<bool>,
    status: Option<String>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_endpoints == 0 || options.max_endpoints > MAX_ENDPOINTS {
        anyhow::bail!("max-endpoints must be between 1 and {MAX_ENDPOINTS}");
    }

    let live: LiveActivity = read_json(&options.live_activity)?;
    let integrity: ProcessIntegrity = read_json(&options.process_integrity)?;

    let report = build_report(&live, &integrity, options.max_endpoints);
    println!("{}", serde_json::to_string_pretty(&report)?);

    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let input = raw.strip_prefix('\u{feff}').unwrap_or(&raw);

    let value: Value = serde_json::from_str(input)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    validate_success(&value, path)?;
    serde_json::from_value(value)
        .with_context(|| format!("invalid report schema in {}", path.display()))
}

fn validate_success(report: &Value, path: &Path) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!(
            "input report must explicitly declare success=true: {}",
            path.display()
        );
    }

    Ok(())
}

fn build_report(live: &LiveActivity, integrity: &ProcessIntegrity, max_endpoints: usize) -> Value {
    let process_index: BTreeMap<u32, &ProcessArtifact> = integrity
        .artifacts
        .iter()
        .filter_map(|artifact| artifact.pid.map(|pid| (pid, artifact)))
        .collect();

    let mut endpoints: Vec<&Endpoint> = live
        .tcp_endpoints
        .iter()
        .chain(live.udp_endpoints.iter())
        .filter(|endpoint| is_listener(endpoint))
        .collect();

    endpoints.sort_by_key(|endpoint| endpoint_sort_key(endpoint));

    let total_listeners = endpoints.len();
    let truncated = total_listeners > max_endpoints;
    endpoints.truncate(max_endpoints);

    let artifacts: Vec<Value> = endpoints
        .iter()
        .map(|endpoint| inspect_endpoint(endpoint, &process_index))
        .collect();

    let needs_review = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "needs_review")
        .count();

    let context = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "context")
        .count();

    let loopback_only = artifacts
        .iter()
        .filter(|artifact| artifact["exposure_scope"] == "loopback_only")
        .count();

    let external_listeners = artifacts
        .iter()
        .filter(|artifact| artifact["externally_reachable"] == true)
        .count();

    json!({
        "schema_version": 1,
        "collector": "axios_network_exposure",
        "success": true,
        "limits": {
            "max_endpoints": max_endpoints,
            "listening_endpoints_observed": total_listeners,
            "listening_endpoints_reported": artifacts.len(),
            "truncated": truncated
        },
        "summary": {
            "listeners": artifacts.len(),
            "externally_reachable_listeners": external_listeners,
            "loopback_only_listeners": loopback_only,
            "needs_review": needs_review,
            "context": context
        },
        "artifacts": artifacts
    })
}

fn inspect_endpoint(endpoint: &Endpoint, process_index: &BTreeMap<u32, &ProcessArtifact>) -> Value {
    let local_address = endpoint.local_address.as_deref().unwrap_or_default();
    let local_port = endpoint.local_port.unwrap_or(0);
    let process = endpoint
        .process_id
        .and_then(|pid| process_index.get(&pid))
        .copied();

    let exposure_scope = exposure_scope(local_address);
    let externally_reachable = matches!(exposure_scope, "wildcard" | "network_interface");
    let service_role = known_service_role(local_port);
    let process_classification = process
        .and_then(|record| record.classification.as_deref())
        .unwrap_or("unknown");

    let user_writable_process = process
        .and_then(|record| record.user_writable_location)
        .unwrap_or(false);

    let expected_system_owner = is_expected_system_owner(
        endpoint.process_name.as_deref(),
        endpoint.executable.as_deref(),
    );

    let store_application = is_windows_store_application(endpoint.executable.as_deref());

    let mut signals = BTreeSet::new();

    if externally_reachable {
        signals.insert("externally_reachable_listener".to_string());
    }

    if service_role.is_some() {
        signals.insert("known_service_port".to_string());
    }

    if user_writable_process {
        signals.insert("user_writable_process".to_string());
    }

    if process_classification == "needs_review" {
        signals.insert("process_integrity_needs_review".to_string());
    }

    if expected_system_owner {
        signals.insert("expected_system_owner".to_string());
    }

    if store_application {
        signals.insert("windows_store_application".to_string());
    }

    for signal in process
        .map(|record| record.command_signals.iter())
        .into_iter()
        .flatten()
    {
        signals.insert(format!("process_{signal}"));
    }

    let (classification, reason) = classify(
        externally_reachable,
        service_role,
        process_classification,
        user_writable_process,
        expected_system_owner,
        store_application,
    );

    json!({
        "protocol": endpoint.protocol.as_deref().unwrap_or("unknown").to_ascii_lowercase(),
        "state": endpoint.state.as_deref().unwrap_or("unknown"),
        "local_address": local_address,
        "local_port": local_port,
        "remote_address": endpoint.remote_address,
        "remote_port": endpoint.remote_port,
        "exposure_scope": exposure_scope,
        "externally_reachable": externally_reachable,
        "service_role": service_role,
        "process": {
            "pid": endpoint.process_id,
            "parent_pid": endpoint.parent_process_id,
            "name": endpoint.process_name,
            "executable": endpoint.executable,
            "integrity_classification": process_classification,
            "integrity_reason": process.and_then(|record| record.reason.clone()),
            "signature_status": process
                .and_then(|record| record.signature.as_ref())
                .and_then(|signature| signature.status.clone()),
            "signature_checked": process
                .and_then(|record| record.signature.as_ref())
                .and_then(|signature| signature.checked),
            "signature_trusted": process
                .and_then(|record| record.signature.as_ref())
                .and_then(|signature| signature.trusted),
            "user_writable_location": user_writable_process,
            "expected_system_owner": expected_system_owner,
            "windows_store_application": store_application
        },
        "classification": classification,
        "reason": reason,
        "signals": signals.into_iter().collect::<Vec<_>>()
    })
}

fn classify(
    externally_reachable: bool,
    service_role: Option<&'static str>,
    process_classification: &str,
    user_writable_process: bool,
    expected_system_owner: bool,
    store_application: bool,
) -> (&'static str, &'static str) {
    if !externally_reachable {
        return ("context", "local_or_loopback_listener");
    }

    if user_writable_process {
        return (
            "needs_review",
            "externally_reachable_listener_owned_by_user_writable_process",
        );
    }

    if store_application {
        return (
            "context",
            "windows_store_application_requires_package_level_signature_verification",
        );
    }

    if process_classification == "needs_review" {
        return (
            "needs_review",
            "externally_reachable_listener_owned_by_process_requiring_review",
        );
    }

    if service_role.is_some() {
        return (
            "needs_review",
            "externally_reachable_remote_service_requires_exposure_review",
        );
    }

    if process_classification == "trusted" {
        return (
            "context",
            "externally_reachable_listener_owned_by_trusted_process",
        );
    }

    if expected_system_owner {
        return (
            "context",
            "externally_reachable_listener_owned_by_expected_windows_component",
        );
    }

    (
        "needs_review",
        "externally_reachable_listener_with_unverified_owner",
    )
}

fn is_listener(endpoint: &Endpoint) -> bool {
    let protocol = endpoint
        .protocol
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    let state = endpoint
        .state
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    endpoint.local_port.unwrap_or(0) != 0 && (protocol == "udp" || state == "listen")
}

fn endpoint_sort_key(endpoint: &Endpoint) -> (String, u16, String, u32) {
    (
        endpoint
            .protocol
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        endpoint.local_port.unwrap_or(0),
        endpoint
            .local_address
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        endpoint.process_id.unwrap_or(0),
    )
}

fn exposure_scope(address: &str) -> &'static str {
    let address = address.trim().to_ascii_lowercase();

    if matches!(address.as_str(), "127.0.0.1" | "::1" | "localhost") {
        "loopback_only"
    } else if matches!(address.as_str(), "0.0.0.0" | "::" | "*") {
        "wildcard"
    } else if address.is_empty() {
        "unknown"
    } else {
        "network_interface"
    }
}

fn is_expected_system_owner(process_name: Option<&str>, executable: Option<&str>) -> bool {
    let process_name = process_name.unwrap_or_default().to_ascii_lowercase();
    let executable = executable
        .unwrap_or_default()
        .replace('/', "\\")
        .to_ascii_lowercase();

    if matches!(
        process_name.as_str(),
        "system"
            | "services.exe"
            | "svchost.exe"
            | "lsass.exe"
            | "wininit.exe"
            | "spoolsv.exe"
            | "dns.exe"
    ) {
        return true;
    }

    executable.contains(r"\windows\system32\")
        || executable.contains(r"\windows\system32\driverstore\")
        || executable.contains(r"\program files\")
        || executable.contains(r"\program files (x86)\")
}

fn is_windows_store_application(executable: Option<&str>) -> bool {
    executable
        .unwrap_or_default()
        .replace('/', "\\")
        .to_ascii_lowercase()
        .contains(r"\program files\windowsapps\")
}

fn known_service_role(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        53 => Some("dns"),
        80 => Some("http"),
        135 => Some("rpc"),
        139 => Some("netbios_session"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900..=5910 => Some("vnc"),
        5985 => Some("winrm_http"),
        5986 => Some("winrm_https"),
        6379 => Some("redis"),
        8080 | 8443 => Some("web_proxy_or_application_server"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, port: u16, protocol: &str, state: &str) -> Endpoint {
        Endpoint {
            process_id: Some(100),
            parent_process_id: Some(1),
            process_name: Some("test.exe".to_string()),
            executable: Some(r"C:\Program Files\Test\test.exe".to_string()),
            protocol: Some(protocol.to_string()),
            local_address: Some(address.to_string()),
            local_port: Some(port),
            remote_address: None,
            remote_port: None,
            state: Some(state.to_string()),
        }
    }

    #[test]
    fn loopback_listener_is_context() {
        let live = LiveActivity {
            tcp_endpoints: vec![endpoint("127.0.0.1", 8080, "tcp", "Listen")],
            udp_endpoints: Vec::new(),
        };

        let report = build_report(
            &live,
            &ProcessIntegrity {
                artifacts: Vec::new(),
            },
            32,
        );
        assert_eq!(report["summary"]["context"], 1);
        assert_eq!(report["summary"]["needs_review"], 0);
    }

    #[test]
    fn externally_reachable_rdp_requires_review() {
        let live = LiveActivity {
            tcp_endpoints: vec![endpoint("0.0.0.0", 3389, "tcp", "Listen")],
            udp_endpoints: Vec::new(),
        };

        let report = build_report(
            &live,
            &ProcessIntegrity {
                artifacts: Vec::new(),
            },
            32,
        );
        assert_eq!(report["summary"]["needs_review"], 1);
        assert_eq!(
            report["artifacts"][0]["reason"],
            "externally_reachable_remote_service_requires_exposure_review"
        );
    }

    #[test]
    fn udp_endpoint_is_a_listener() {
        assert!(is_listener(&endpoint("0.0.0.0", 53, "udp", "")));
    }

    #[test]
    fn connection_is_not_a_listener() {
        assert!(!is_listener(&endpoint(
            "10.0.0.2",
            50000,
            "tcp",
            "Established"
        )));
    }

    #[test]
    fn known_ports_are_labeled() {
        assert_eq!(known_service_role(445), Some("smb"));
        assert_eq!(known_service_role(3389), Some("rdp"));
        assert_eq!(known_service_role(12345), None);
    }

    #[test]
    fn trusted_external_high_port_is_context() {
        assert_eq!(
            classify(true, None, "trusted", false, false, false),
            (
                "context",
                "externally_reachable_listener_owned_by_trusted_process"
            )
        );
    }

    #[test]
    fn windows_service_external_high_port_is_context() {
        assert_eq!(
            classify(true, None, "unknown", false, true, false),
            (
                "context",
                "externally_reachable_listener_owned_by_expected_windows_component"
            )
        );
    }

    #[test]
    fn system_owner_detection_is_conservative() {
        assert!(is_expected_system_owner(Some("svchost.exe"), None));
        assert!(is_expected_system_owner(
            Some("chrome.exe"),
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        ));
        assert!(!is_expected_system_owner(
            Some("loader.exe"),
            Some(r"C:\Users\TestUser\AppData\Local\Temp\loader.exe")
        ));
    }

    #[test]
    fn store_application_listener_is_context_not_an_authenticode_false_positive() {
        assert_eq!(
            classify(true, None, "needs_review", false, true, true),
            (
                "context",
                "windows_store_application_requires_package_level_signature_verification"
            )
        );
    }

    #[test]
    fn windows_store_paths_are_recognized() {
        assert!(is_windows_store_application(Some(
            r"C:\Program Files\WindowsApps\ExampleVendor.ExampleApp_1.0.0.0_x64__example\ExampleApp.exe"
        )));
        assert!(!is_windows_store_application(Some(
            r"C:\Users\TestUser\Downloads\ExampleClient.exe"
        )));
    }

    #[test]
    fn user_writable_external_listener_has_highest_priority() {
        assert_eq!(
            classify(true, Some("http"), "trusted", true, false, false),
            (
                "needs_review",
                "externally_reachable_listener_owned_by_user_writable_process"
            )
        );
    }

    #[test]
    fn failed_network_exposure_inputs_are_rejected() {
        let path = PathBuf::from("failed-input.json");

        assert!(validate_success(&json!({"success": false}), &path).is_err());
        assert!(validate_success(&json!({}), &path).is_err());
        assert!(validate_success(&json!({"success": true}), &path).is_ok());
    }
}
