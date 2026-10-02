use anyhow::{bail, Result};
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

#[derive(Parser, Debug)]
#[command(name = "axios-network-identity-review")]
struct Options {
    #[arg(long)]
    processes: PathBuf,
    #[arg(long, default_value_t = 512)]
    max_connections: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_connections == 0 || options.max_connections > 4096 {
        bail!("max-connections must be between 1 and 4096");
    }

    let processes = json_file::read_value(&options.processes)?;
    if processes.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("process report is not successful");
    }

    let connections = collect_connections(options.max_connections)?;
    let report = build_report(&processes, &connections);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_connections(max_connections: usize) -> Result<Value> {
    let script = format!(
        r#"
$ErrorActionPreference = "Stop"

$allConnections = @(
    Get-NetTCPConnection -State Established -ErrorAction Stop
)

$connections = @(
    $allConnections |
        Sort-Object `
            @{{ Expression = {{
                if ([string]$_.RemoteAddress -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1$|fe80:|f[cd])') {{ 1 }} else {{ 0 }}
            }} }}, `
            OwningProcess, RemoteAddress, RemotePort |
        Select-Object -First {max_connections} `
            OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State
)

[PSCustomObject]@{{
    success = $true
    established_connections = $connections
    established_connection_total = @($allConnections).Count
    collection_limited = @($allConnections).Count -gt {max_connections}
}} | ConvertTo-Json -Depth 5 -Compress
"#
    );

    let output = powershell(&script)?;
    if !output.success {
        bail!("network identity collector failed: {}", output.stderr);
    }

    Ok(parse_json_output(output))
}

#[cfg(not(windows))]
fn collect_connections(_max_connections: usize) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collection_status": "windows_only"
    }))
}

fn build_report(processes: &Value, connections: &Value) -> Value {
    let process_items = processes
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut artifacts = Vec::new();
    let mut public_connections = 0usize;
    let mut context_connections = 0usize;

    for connection in connections
        .get("established_connections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let pid = connection
            .get("OwningProcess")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let remote = connection
            .get("RemoteAddress")
            .and_then(Value::as_str)
            .unwrap_or("");

        if !is_public_remote(remote) {
            context_connections += 1;
            continue;
        }

        public_connections += 1;

        let process = process_items
            .iter()
            .find(|item| item.get("pid").and_then(Value::as_u64) == Some(pid));

        let priority = process
            .map(|item| assess_priority(item, remote))
            .unwrap_or("context");

        if priority == "context" {
            context_connections += 1;
            continue;
        }

        artifacts.push(json!({
            "priority": priority,
            "pid": pid,
            "remote_address": remote,
            "remote_port": connection.get("RemotePort").cloned().unwrap_or(Value::Null),
            "local_address": connection.get("LocalAddress").cloned().unwrap_or(Value::Null),
            "local_port": connection.get("LocalPort").cloned().unwrap_or(Value::Null),
            "identity": process.map(process_identity).unwrap_or_else(empty_process_identity),
            "process": process.cloned().unwrap_or(Value::Null),
            "reason": "public_egress_connection_correlates_with_existing_process_risk_evidence"
        }));
    }

    artifacts.sort_by(|left, right| {
        priority_rank(right["priority"].as_str().unwrap_or("context")).cmp(&priority_rank(
            left["priority"].as_str().unwrap_or("context"),
        ))
    });

    let high = artifacts
        .iter()
        .filter(|item| item["priority"] == "high")
        .count();
    let medium = artifacts
        .iter()
        .filter(|item| item["priority"] == "medium")
        .count();

    json!({
        "success": true,
        "collector": "axios_network_identity_review",
        "read_only": true,
        "database_used": false,
        "malware_confirmed": false,
        "backdoor_confirmed": false,
        "policy": {
            "connection_alone": "not_a_malware_verdict",
            "public_egress_from_trusted_app": "context",
            "medium_requires": "public_egress AND existing_process_review_signal",
            "high_requires": "public_egress AND user_writable_process AND suspicious_execution_signal"
        },
        "summary": {
            "established_connections_observed": connections
                .get("established_connections")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
            "established_connection_total": connections
                .get("established_connection_total")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            "public_connections_observed": public_connections,
            "context_connections": context_connections,
            "high_priority_connections": high,
            "medium_priority_connections": medium,
            "reported_high_or_medium_connections": artifacts.len(),
            "collection_limited": connections
                .get("collection_limited")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        },
        "artifacts": artifacts
    })
}

fn process_identity(process: &Value) -> Value {
    let path = process
        .get("executable_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let sha256 = process
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let start_time = process
        .get("creation_date")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let pid = process.get("pid").and_then(Value::as_u64);
    let quality = if path.is_some() && sha256.is_some() && start_time.is_some() && pid.is_some() {
        "strong"
    } else {
        "partial"
    };

    json!({
        "pid": pid,
        "start_time": start_time,
        "normalized_path": path.map(normalize_identity_path),
        "sha256": sha256.map(str::to_ascii_lowercase),
        "identity_quality": quality
    })
}

fn empty_process_identity() -> Value {
    json!({
        "pid": Value::Null,
        "start_time": Value::Null,
        "normalized_path": Value::Null,
        "sha256": Value::Null,
        "identity_quality": "unresolved"
    })
}

fn normalize_identity_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn assess_priority(process: &Value, remote: &str) -> &'static str {
    if !is_public_remote(remote) {
        return "context";
    }

    let classification = process
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let user_writable = process
        .get("user_writable_location")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let parent_mismatch = process
        .get("parent_mismatch")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let command_signals = process
        .get("command_signals")
        .and_then(Value::as_array)
        .map(|signals| !signals.is_empty())
        .unwrap_or(false);

    if classification == "needs_review" && user_writable && (parent_mismatch || command_signals) {
        "high"
    } else if classification == "needs_review" {
        "medium"
    } else {
        "context"
    }
}

fn is_public_remote(address: &str) -> bool {
    match address.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => is_public_ipv4(address),
        Ok(IpAddr::V6(address)) => is_public_ipv6(address),
        Err(_) => false,
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();

    let reserved = matches!(first, 0 | 10 | 127 | 224..=255)
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 192 && second == 0)
        || (first == 192 && second == 2)
        || (first == 198 && (18..=19).contains(&second))
        || (first == 198 && second == 51)
        || (first == 203 && second == 0);

    !reserved
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped_ipv4) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped_ipv4);
    }

    let bytes = address.octets();

    address != Ipv6Addr::UNSPECIFIED
        && address != Ipv6Addr::LOCALHOST
        && bytes[0] != 0xff
        && (bytes[0] & 0xfe) != 0xfc
        && !(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
        && bytes[..4] != [0x20, 0x01, 0x0d, 0xb8]
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_not_public_egress() {
        assert!(!is_public_remote("127.0.0.1"));
        assert!(!is_public_remote("127.0.0.2"));
        assert!(!is_public_remote("0.0.0.0"));
        assert!(!is_public_remote("10.0.0.5"));
        assert!(!is_public_remote("172.16.0.1"));
        assert!(!is_public_remote("192.168.1.1"));
        assert!(!is_public_remote("100.64.0.1"));
        assert!(!is_public_remote("198.18.0.1"));
        assert!(!is_public_remote("::"));
        assert!(!is_public_remote("::1"));
        assert!(!is_public_remote("fe80::1"));
        assert!(!is_public_remote("fc00::1"));
        assert!(!is_public_remote("2001:db8::1"));
        assert!(is_public_remote("1.1.1.1"));
    }

    #[test]
    fn high_requires_multiple_process_signals() {
        let suspicious = json!({
            "classification": "needs_review",
            "user_writable_location": true,
            "parent_mismatch": false,
            "command_signals": ["encoded_powershell"]
        });

        let ordinary = json!({
            "classification": "needs_review",
            "user_writable_location": false,
            "parent_mismatch": false,
            "command_signals": []
        });

        assert_eq!(assess_priority(&suspicious, "1.1.1.1"), "high");
        assert_eq!(assess_priority(&ordinary, "1.1.1.1"), "medium");
        assert_eq!(assess_priority(&ordinary, "192.168.1.1"), "context");
    }

    #[test]
    fn collector_does_not_hide_connection_collection_failure() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bin/axios-network-identity-review.rs"
        ));

        assert!(source.contains("Get-NetTCPConnection -State Established -ErrorAction Stop"));

        let suppressed_form = concat!(
            "Get-NetTCPConnection -State Established -ErrorAction ",
            "SilentlyContinue"
        );

        assert!(!source.contains(suppressed_form));
    }

    #[test]
    fn network_artifact_identity_uses_process_hash_and_start_time() {
        let identity = process_identity(&json!({
            "pid": 77,
            "creation_date": "20260915010101.000000+000",
            "executable_path": r"C:\Program Files\Sample\sample.exe",
            "sha256": "DDEEFF"
        }));

        assert_eq!(identity["pid"], 77);
        assert_eq!(identity["start_time"], "20260915010101.000000+000");
        assert_eq!(identity["sha256"], "ddeeff");
        assert_eq!(identity["identity_quality"], "strong");
    }

    #[test]
    fn unresolved_network_process_does_not_claim_identity() {
        let identity = empty_process_identity();

        assert_eq!(identity["identity_quality"], "unresolved");
        assert!(identity["pid"].is_null());
        assert!(identity["sha256"].is_null());
    }
}
