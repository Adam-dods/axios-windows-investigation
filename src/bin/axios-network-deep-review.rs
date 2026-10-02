#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_TARGETS: usize = 32;
const MAX_PORTS: usize = 128;
const MAX_ADDRESSES_PER_TARGET: usize = 8;
const MAX_WORKERS: usize = 32;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Profile {
    Auto,
    Standard,
    Administrator,
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Standard => "standard",
            Self::Administrator => "administrator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Focus {
    Overview,
    Wifi,
    Connections,
    Services,
    Dns,
    Routing,
    Firewall,
    Targeted,
    Full,
}

impl Focus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Wifi => "wifi",
            Self::Connections => "connections",
            Self::Services => "services",
            Self::Dns => "dns",
            Self::Routing => "routing",
            Self::Firewall => "firewall",
            Self::Targeted => "targeted",
            Self::Full => "full",
        }
    }

    fn permits_targets(self) -> bool {
        matches!(self, Self::Connections | Self::Targeted | Self::Full)
    }
}

#[derive(Parser, Debug)]
#[command(name = "axios-network-deep-review")]
struct Options {
    #[arg(long, value_enum, default_value_t = Profile::Auto)]
    profile: Profile,

    #[arg(long, value_enum, default_value_t = Focus::Full)]
    focus: Focus,

    #[arg(long, action = clap::ArgAction::Append)]
    target: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    ports: Vec<u16>,

    #[arg(long, default_value_t = 750)]
    timeout_ms: u64,

    #[arg(long, default_value_t = 2048)]
    max_tcp: usize,

    #[arg(long, default_value_t = 1024)]
    max_udp: usize,

    #[arg(long, default_value_t = 1024)]
    max_dns: usize,

    #[arg(long, default_value_t = 1024)]
    max_routes: usize,

    #[arg(long, default_value_t = 1024)]
    max_neighbors: usize,

    #[arg(long, default_value_t = 2048)]
    max_firewall_rules: usize,

    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ScanJob {
    target: String,
    address: SocketAddr,
    port: u16,
}

#[derive(Clone, Debug, Serialize)]
struct ActiveResult {
    target: String,
    resolved_address: String,
    port: u16,
    transport: &'static str,
    state: &'static str,
    error_kind: Option<String>,
    error: Option<String>,
    duration_ms: u128,
    service_hint: &'static str,
}

fn main() -> Result<()> {
    let mut options = Options::parse();
    validate_options(&mut options)?;

    let passive = collect_passive(&options)?;
    let active = if options.target.is_empty() {
        Vec::new()
    } else {
        scan_targets(&options)?
    };

    let report = build_report(&passive, &active, &options);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn valid_explicit_target(target: &str) -> bool {
    use std::net::IpAddr;

    if target.parse::<IpAddr>().is_ok() {
        return true;
    }

    if target.is_empty() || target.len() > 253 || !target.is_ascii() {
        return false;
    }

    target.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn validate_options(options: &mut Options) -> Result<()> {
    for (name, value, maximum) in [
        ("max-tcp", options.max_tcp, 16_384),
        ("max-udp", options.max_udp, 16_384),
        ("max-dns", options.max_dns, 16_384),
        ("max-routes", options.max_routes, 16_384),
        ("max-neighbors", options.max_neighbors, 16_384),
        ("max-firewall-rules", options.max_firewall_rules, 16_384),
    ] {
        if value == 0 || value > maximum {
            anyhow::bail!("{name} must be between 1 and {maximum}");
        }
    }

    if options.timeout_ms < 50 || options.timeout_ms > 10_000 {
        anyhow::bail!("timeout-ms must be between 50 and 10000");
    }

    if options.target.len() > MAX_TARGETS {
        anyhow::bail!("no more than {MAX_TARGETS} explicit targets are allowed");
    }

    if !options.target.is_empty() && !options.focus.permits_targets() {
        anyhow::bail!("targets require --focus connections, targeted, or full");
    }

    if options.focus == Focus::Targeted && options.target.is_empty() {
        anyhow::bail!("targeted focus requires at least one --target");
    }

    for target in &options.target {
        if !valid_explicit_target(target) {
            anyhow::bail!("targets must be explicit hostnames or IP addresses; CIDR, wildcard, and whitespace are rejected; invalid target: {target}");
        }
    }

    for target in &mut options.target {
        if let Ok(address) = target.parse::<std::net::IpAddr>() {
            *target = address.to_string();
        } else {
            *target = target.to_ascii_lowercase();
        }
    }

    options.target.sort_unstable();
    options.target.dedup();

    if !options.target.is_empty() && options.ports.is_empty() {
        options.ports = vec![22, 53, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443];
    }

    options.ports.sort_unstable();
    options.ports.dedup();

    if options.ports.len() > MAX_PORTS {
        anyhow::bail!("no more than {MAX_PORTS} explicit ports are allowed");
    }

    Ok(())
}

#[cfg(windows)]
fn collect_passive(options: &Options) -> Result<Value> {
    let script = PASSIVE_SCRIPT
        .replace("__PROFILE__", options.profile.as_str())
        .replace("__FOCUS__", options.focus.as_str())
        .replace("__MAX_TCP__", &options.max_tcp.to_string())
        .replace("__MAX_UDP__", &options.max_udp.to_string())
        .replace("__MAX_DNS__", &options.max_dns.to_string())
        .replace("__MAX_ROUTES__", &options.max_routes.to_string())
        .replace("__MAX_NEIGHBORS__", &options.max_neighbors.to_string())
        .replace(
            "__MAX_FIREWALL_RULES__",
            &options.max_firewall_rules.to_string(),
        );

    let output = powershell(&script)?;
    if !output.success {
        bail!("network deep collector failed: {}", output.stderr);
    }

    let report = parse_json_output(output);
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("network deep collector returned an unsuccessful report");
    }

    Ok(report)
}

#[cfg(not(windows))]
fn collect_passive(_options: &Options) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collector": "axios_network_deep_review_raw",
        "collection_status": "windows_only",
        "collection_errors": ["passive Windows collection requires Windows"],
        "execution_context": {
            "administrator": false,
            "requested_profile": "unsupported",
            "effective_profile": "unsupported"
        },
        "capabilities": [],
        "tcp_connections": [],
        "udp_endpoints": [],
        "processes": []
    }))
}

fn scan_targets(options: &Options) -> Result<Vec<ActiveResult>> {
    let mut jobs = Vec::new();
    let mut resolution_errors = Vec::new();
    let mut scheduled_endpoints = HashSet::new();

    for target in &options.target {
        for port in &options.ports {
            match (target.as_str(), *port).to_socket_addrs() {
                Ok(resolved) => {
                    for address in resolved.take(MAX_ADDRESSES_PER_TARGET) {
                        if scheduled_endpoints.insert((address.ip(), *port)) {
                            jobs.push(ScanJob {
                                target: target.clone(),
                                address,
                                port: *port,
                            });
                        }
                    }
                }
                Err(error) => {
                    resolution_errors.push(ActiveResult {
                        target: target.clone(),
                        resolved_address: String::new(),
                        port: *port,
                        transport: "tcp",
                        state: "resolution_failed",
                        error_kind: Some(format!("{:?}", error.kind())),
                        error: Some(error.to_string()),
                        duration_ms: 0,
                        service_hint: service_hint(*port),
                    });
                }
            }
        }
    }

    let worker_count = jobs.len().clamp(1, MAX_WORKERS);
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let timeout = Duration::from_millis(options.timeout_ms);
    let (sender, receiver) = mpsc::channel();

    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let sender = sender.clone();

        workers.push(thread::spawn(move || loop {
            let job = {
                let mut queue = match queue.lock() {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner(),
                };
                queue.pop_front()
            };

            let Some(job) = job else {
                break;
            };

            let started = Instant::now();
            let result = match TcpStream::connect_timeout(&job.address, timeout) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    ActiveResult {
                        target: job.target,
                        resolved_address: job.address.ip().to_string(),
                        port: job.port,
                        transport: "tcp",
                        state: "open",
                        error_kind: None,
                        error: None,
                        duration_ms: started.elapsed().as_millis(),
                        service_hint: service_hint(job.port),
                    }
                }
                Err(error) => ActiveResult {
                    target: job.target,
                    resolved_address: job.address.ip().to_string(),
                    port: job.port,
                    transport: "tcp",
                    state: classify_connect_error(&error),
                    error_kind: Some(format!("{:?}", error.kind())),
                    error: Some(error.to_string()),
                    duration_ms: started.elapsed().as_millis(),
                    service_hint: service_hint(job.port),
                },
            };

            if sender.send(result).is_err() {
                break;
            }
        }));
    }

    drop(sender);

    let mut results: Vec<_> = receiver.into_iter().collect();
    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("network scan worker panicked"))?;
    }

    results.extend(resolution_errors);
    results.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.resolved_address.cmp(&right.resolved_address))
            .then_with(|| left.port.cmp(&right.port))
    });

    Ok(results)
}

fn classify_connect_error(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "closed",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout_or_filtered",
        io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::AddrNotAvailable => "unreachable",
        _ => "connect_error",
    }
}

fn service_hint(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-session",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "smtp-submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5985 => "winrm-http",
        5986 => "winrm-https",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "unknown",
    }
}

fn build_report(passive: &Value, active: &[ActiveResult], options: &Options) -> Value {
    let mut findings = Vec::new();
    let mut observations = Vec::new();
    let mut process_map = HashMap::new();

    for process in passive
        .get("processes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(pid) = process.get("pid").and_then(Value::as_u64) {
            process_map.insert(pid, process);
        }
    }

    for connection in passive
        .get("tcp_connections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let pid = connection
            .get("owning_process")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let process = process_map.get(&pid);
        let path = process
            .and_then(|value| value.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let state = connection
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("");

        let local_address = connection
            .get("local_address")
            .and_then(Value::as_str)
            .unwrap_or("");

        let remote_address = connection
            .get("remote_address")
            .and_then(Value::as_str)
            .unwrap_or("");

        let local_port = connection
            .get("local_port")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        if state.eq_ignore_ascii_case("listen") && is_wildcard(local_address) {
            observations.push(json!({
                "classification": "wildcard_listener_observed",
                "confidence": "high",
                "pid": pid,
                "process_path": path,
                "local_address": local_address,
                "local_port": local_port
            }));

            if is_user_writable_path(path) {
                findings.push(json!({
                    "id": "user_writable_process_listens_on_all_interfaces",
                    "priority": "medium",
                    "confidence": "high",
                    "classification": "network_execution_exposure",
                    "title": "A process in a user-writable location listens on all interfaces",
                    "evidence": {
                        "pid": pid,
                        "process_path": path,
                        "local_address": local_address,
                        "local_port": local_port
                    },
                    "next_check": "Correlate the executable signature, hash, parent process, persistence, and firewall scope."
                }));
            }
        }

        if state.eq_ignore_ascii_case("established")
            && is_public_address(remote_address)
            && is_user_writable_path(path)
        {
            findings.push(json!({
                "id": "user_writable_process_has_public_connection",
                "priority": "medium",
                "confidence": "high",
                "classification": "network_execution_requires_review",
                "title": "A process in a user-writable location has a public network connection",
                "evidence": {
                    "pid": pid,
                    "process_path": path,
                    "remote_address": remote_address,
                    "remote_port": connection.get("remote_port").cloned().unwrap_or(Value::Null),
                    "local_address": local_address,
                    "local_port": local_port
                },
                "next_check": "Verify signer, hash, domain ownership, execution origin, and related persistence evidence."
            }));
        }
    }

    for result in active {
        if result.state == "open" {
            observations.push(json!({
                "classification": "explicit_target_open_port_observed",
                "confidence": "high",
                "target": result.target,
                "resolved_address": result.resolved_address,
                "port": result.port,
                "service_hint": result.service_hint,
                "interpretation": "A completed TCP handshake confirms reachability only; it does not confirm the service identity or a vulnerability."
            }));
        }
    }

    let mut finding_keys = HashSet::new();
    findings.retain(|finding| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            finding.get("id").and_then(Value::as_str).unwrap_or(""),
            finding
                .pointer("/evidence/pid")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            finding
                .pointer("/evidence/process_path")
                .and_then(Value::as_str)
                .unwrap_or(""),
            finding
                .pointer("/evidence/remote_address")
                .and_then(Value::as_str)
                .unwrap_or(""),
            finding
                .pointer("/evidence/local_port")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        );
        finding_keys.insert(key)
    });

    let resolution_failures = active
        .iter()
        .filter(|item| item.state == "resolution_failed")
        .count();
    let connection_errors = active
        .iter()
        .filter(|item| item.state == "connect_error")
        .count();
    let mut collection_errors = passive
        .get("collection_errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if resolution_failures > 0 {
        collection_errors.push(json!(format!(
            "active checks: {resolution_failures} target and port combinations could not be resolved"
        )));
    }
    if connection_errors > 0 {
        collection_errors.push(json!(format!(
            "active checks: {connection_errors} connection attempts ended in an unexpected error"
        )));
    }
    let passive_status = passive
        .get("collection_status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    let collection_status =
        if passive_status == "complete" && (resolution_failures > 0 || connection_errors > 0) {
            "partial"
        } else {
            passive_status
        };
    let open_ports = active.iter().filter(|item| item.state == "open").count();
    let closed_ports = active.iter().filter(|item| item.state == "closed").count();
    let filtered_ports = active
        .iter()
        .filter(|item| item.state == "timeout_or_filtered")
        .count();

    json!({
        "success": passive.get("success").and_then(Value::as_bool).unwrap_or(false),
        "collector": "axios_network_deep_review",
        "collection_status": collection_status,
        "collection_errors": collection_errors,
        "execution_context": passive.get("execution_context").cloned().unwrap_or(Value::Null),
        "requested_scope": {
            "profile": options.profile.as_str(),
            "focus": options.focus.as_str(),
            "explicit_targets": options.target,
            "explicit_ports": options.ports,
            "timeout_ms": options.timeout_ms
        },
        "capabilities": passive.get("capabilities").cloned().unwrap_or_else(|| json!([])),
        "limits": passive.get("limits").cloned().unwrap_or(Value::Null),
        "truncation": passive.get("truncation").cloned().unwrap_or(Value::Null),
        "adapters": passive.get("adapters").cloned().unwrap_or_else(|| json!([])),
        "ip_configuration": passive.get("ip_configuration").cloned().unwrap_or_else(|| json!([])),
        "routes": passive.get("routes").cloned().unwrap_or_else(|| json!([])),
        "neighbors": passive.get("neighbors").cloned().unwrap_or_else(|| json!([])),
        "dns_cache": passive.get("dns_cache").cloned().unwrap_or_else(|| json!([])),
        "tcp_connections": passive.get("tcp_connections").cloned().unwrap_or_else(|| json!([])),
        "udp_endpoints": passive.get("udp_endpoints").cloned().unwrap_or_else(|| json!([])),
        "processes": passive.get("processes").cloned().unwrap_or_else(|| json!([])),
        "firewall_profiles": passive.get("firewall_profiles").cloned().unwrap_or_else(|| json!([])),
        "firewall_rules": passive.get("firewall_rules").cloned().unwrap_or_else(|| json!([])),
        "proxy": passive.get("proxy").cloned().unwrap_or(Value::Null),
        "wireless": passive.get("wireless").cloned().unwrap_or(Value::Null),
        "active_target_results": active,
        "observations": observations,
        "findings": findings,
        "claim_policy": {
            "packet_capture_performed": false,
            "service_version_confirmed": false,
            "vulnerability_confirmed": false,
            "malware_confirmed": false,
            "intrusion_confirmed": false,
            "interpretation": "Socket, route, DNS, firewall, and explicit TCP handshake evidence is reported without claiming packet capture, service identity, exploitation, malware, or intrusion."
        },
        "summary": {
            "tcp_connections_observed": passive
                .pointer("/totals/tcp_returned")
                .cloned()
                .unwrap_or_else(|| json!(0)),
            "udp_endpoints_observed": passive
                .pointer("/totals/udp_returned")
                .cloned()
                .unwrap_or_else(|| json!(0)),
            "active_checks_completed": active.len() - resolution_failures,
            "active_resolution_failures": resolution_failures,
            "active_connection_errors": connection_errors,
            "active_open_ports": open_ports,
            "active_closed_ports": closed_ports,
            "active_timeout_or_filtered": filtered_ports,
            "findings": findings.len(),
            "observations": observations.len()
        }
    })
}

fn is_wildcard(address: &str) -> bool {
    matches!(address, "0.0.0.0" | "::" | "*" | "[::]")
}

fn is_user_writable_path(path: &str) -> bool {
    let value = path.replace('/', "\\").to_ascii_lowercase();
    value.contains(r"\users\")
        || value.contains(r"\appdata\")
        || value.contains(r"\downloads\")
        || value.contains(r"\temp\")
}

fn is_public_address(address: &str) -> bool {
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };

    match address {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => {
            if let Some(mapped) = value.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }

            !(value.is_loopback()
                || value.is_multicast()
                || value.is_unspecified()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
                || (value.segments()[0] == 0x2001 && value.segments()[1] == 0x0db8))
        }
    }
}

fn is_public_ipv4(value: Ipv4Addr) -> bool {
    let [a, b, c, _] = value.octets();
    !(value.is_private()
        || value.is_loopback()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || value.is_unspecified()
        || a == 0
        || a >= 224
        || (a == 100 && (b & 0xc0) == 64) // shared address space
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

#[cfg(windows)]
const PASSIVE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$requestedProfile = '__PROFILE__'
$focus = '__FOCUS__'
$errors = [System.Collections.Generic.List[string]]::new()
$capabilities = [System.Collections.Generic.List[object]]::new()

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$isAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$effectiveProfile = if (
    $requestedProfile -eq 'administrator' -and
    $isAdministrator
) {
    'administrator'
}
elseif (
    $requestedProfile -eq 'administrator' -and
    -not $isAdministrator
) {
    $errors.Add(
        'execution_context: administrator profile requested without an elevated token'
    )
    'standard'
}
elseif ($requestedProfile -eq 'standard') {
    'standard'
}
elseif ($isAdministrator) {
    'administrator'
}
else {
    'standard'
}

function Add-AxiosError {
    param([string]$Source, [object]$Failure)

    $message = if ($null -ne $Failure.Exception) {
        $Failure.Exception.Message
    }
    else {
        [string]$Failure
    }

    $errors.Add(('{0}: {1}' -f $Source, $message))
}

function Add-AxiosCapability {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Reason
    )

    $capabilities.Add([PSCustomObject]@{
        name = $Name
        status = $Status
        reason = $Reason
    })
}

function Test-AxiosFocus {
    param([string[]]$Allowed)

    return (
        $focus -eq 'full' -or
        $Allowed -contains $focus
    )
}

$adaptersAll = @()
$ipConfiguration = @()
$routesAll = @()
$neighborsAll = @()
$dnsAll = @()
$tcpAll = @()
$udpAll = @()
$firewallProfiles = @()
$firewallRulesAll = @()
$processes = [System.Collections.Generic.List[object]]::new()
$processPathErrors = 0
$proxy = $null
$wireless = $null

if (Test-AxiosFocus @('overview', 'wifi', 'routing')) {
    try {
        $adaptersAll = @(
            Get-NetAdapter -ErrorAction Stop |
                Select-Object Name, InterfaceDescription, InterfaceIndex,
                    Status, MacAddress, LinkSpeed, MediaType,
                    PhysicalMediaType
        )
        Add-AxiosCapability 'network_adapters' 'collected' ''
    }
    catch {
        Add-AxiosError 'network_adapters' $_
        Add-AxiosCapability 'network_adapters' 'failed' $_.Exception.Message
    }

    try {
        $ipConfiguration = @(
            Get-NetIPConfiguration -Detailed -ErrorAction Stop |
                ForEach-Object {
                    $configuration = $_

                    $networkCategory = if (
                        $null -ne $configuration.NetProfile
                    ) {
                        [string]$configuration.NetProfile.NetworkCategory
                    }
                    else {
                        ""
                    }

                    $networkName = if (
                        $null -ne $configuration.NetProfile
                    ) {
                        [string]$configuration.NetProfile.Name
                    }
                    else {
                        ""
                    }

                    [PSCustomObject]@{
                        interface_alias = [string]$configuration.InterfaceAlias
                        interface_index = [int]$configuration.InterfaceIndex
                        network_name = $networkName
                        network_category = $networkCategory
                        ipv4_addresses = @(
                            $configuration.IPv4Address |
                                ForEach-Object {
                                    [string]$_.IPAddress
                                }
                        )
                        ipv6_addresses = @(
                            $configuration.IPv6Address |
                                ForEach-Object {
                                    [string]$_.IPAddress
                                }
                        )
                        ipv4_gateways = @(
                            $configuration.IPv4DefaultGateway |
                                ForEach-Object {
                                    [string]$_.NextHop
                                }
                        )
                        ipv6_gateways = @(
                            $configuration.IPv6DefaultGateway |
                                ForEach-Object {
                                    [string]$_.NextHop
                                }
                        )
                        dns_servers = @(
                            $configuration.DNSServer.ServerAddresses |
                                ForEach-Object {
                                    [string]$_
                                }
                        )
                    }
                }
        )
        Add-AxiosCapability 'ip_configuration' 'collected' ''
    }
    catch {
        Add-AxiosError 'ip_configuration' $_
        Add-AxiosCapability 'ip_configuration' 'failed' $_.Exception.Message
    }

    try {
        $proxyRaw = @(& netsh.exe winhttp show proxy 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "netsh.exe winhttp show proxy failed with exit code ${LASTEXITCODE}: $($proxyRaw -join ' ')"
        }
        $proxy = [PSCustomObject]@{
            source = 'netsh_winhttp'
            raw = $proxyRaw
        }
        Add-AxiosCapability 'winhttp_proxy' 'collected' ''
    }
    catch {
        Add-AxiosError 'winhttp_proxy' $_
        Add-AxiosCapability 'winhttp_proxy' 'failed' $_.Exception.Message
    }

    try {
        $wirelessRaw = @(& netsh.exe wlan show interfaces 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "netsh.exe wlan show interfaces failed with exit code ${LASTEXITCODE}: $($wirelessRaw -join ' ')"
        }
        $wireless = [PSCustomObject]@{
            source = 'netsh_wlan'
            raw = $wirelessRaw
            localization_limited = $true
        }
        Add-AxiosCapability 'wireless_interfaces' 'collected' ''
    }
    catch {
        Add-AxiosError 'wireless_interfaces' $_
        Add-AxiosCapability 'wireless_interfaces' 'failed' $_.Exception.Message
    }
}
else {
    Add-AxiosCapability 'network_adapters' 'not_requested' $focus
    Add-AxiosCapability 'ip_configuration' 'not_requested' $focus
    Add-AxiosCapability 'winhttp_proxy' 'not_requested' $focus
    Add-AxiosCapability 'wireless_interfaces' 'not_requested' $focus
}

if (Test-AxiosFocus @('routing')) {
    try {
        $routesAll = @(
            Get-NetRoute -ErrorAction Stop |
                Sort-Object RouteMetric, DestinationPrefix |
                Select-Object DestinationPrefix, NextHop,
                    InterfaceAlias, InterfaceIndex, RouteMetric,
                    Protocol, State, AddressFamily
        )
        Add-AxiosCapability 'routes' 'collected' ''
    }
    catch {
        Add-AxiosError 'routes' $_
        Add-AxiosCapability 'routes' 'failed' $_.Exception.Message
    }

    try {
        $neighborsAll = @(
            Get-NetNeighbor -ErrorAction Stop |
                Select-Object InterfaceAlias, InterfaceIndex,
                    IPAddress, LinkLayerAddress, State,
                    AddressFamily
        )
        Add-AxiosCapability 'neighbors' 'collected' ''
    }
    catch {
        Add-AxiosError 'neighbors' $_
        Add-AxiosCapability 'neighbors' 'failed' $_.Exception.Message
    }
}
else {
    Add-AxiosCapability 'routes' 'not_requested' $focus
    Add-AxiosCapability 'neighbors' 'not_requested' $focus
}

if (Test-AxiosFocus @('dns')) {
    try {
        $dnsAll = @(
            Get-DnsClientCache -ErrorAction Stop |
                Select-Object Entry, Name, Data, Type,
                    Status, TimeToLive, Section
        )
        Add-AxiosCapability 'dns_cache' 'collected' ''
    }
    catch {
        Add-AxiosError 'dns_cache' $_
        Add-AxiosCapability 'dns_cache' 'failed' $_.Exception.Message
    }
}
else {
    Add-AxiosCapability 'dns_cache' 'not_requested' $focus
}

if (Test-AxiosFocus @('connections', 'services')) {
    try {
        $tcpAll = @(
            Get-NetTCPConnection -ErrorAction Stop |
                Sort-Object State, OwningProcess, LocalPort |
                Select-Object @{
                    Name = 'local_address'
                    Expression = { $_.LocalAddress }
                }, @{
                    Name = 'local_port'
                    Expression = { $_.LocalPort }
                }, @{
                    Name = 'remote_address'
                    Expression = { $_.RemoteAddress }
                }, @{
                    Name = 'remote_port'
                    Expression = { $_.RemotePort }
                }, @{
                    Name = 'state'
                    Expression = { [string]$_.State }
                }, @{
                    Name = 'owning_process'
                    Expression = { $_.OwningProcess }
                }, CreationTime, OffloadState
        )
        Add-AxiosCapability 'tcp_connections' 'collected' ''
    }
    catch {
        Add-AxiosError 'tcp_connections' $_
        Add-AxiosCapability 'tcp_connections' 'failed' $_.Exception.Message
    }

    try {
        $udpAll = @(
            Get-NetUDPEndpoint -ErrorAction Stop |
                Sort-Object OwningProcess, LocalPort |
                Select-Object @{
                    Name = 'local_address'
                    Expression = { $_.LocalAddress }
                }, @{
                    Name = 'local_port'
                    Expression = { $_.LocalPort }
                }, @{
                    Name = 'owning_process'
                    Expression = { $_.OwningProcess }
                }, CreationTime
        )
        Add-AxiosCapability 'udp_endpoints' 'collected' ''
    }
    catch {
        Add-AxiosError 'udp_endpoints' $_
        Add-AxiosCapability 'udp_endpoints' 'failed' $_.Exception.Message
    }

    $pids = @(
        @($tcpAll.owning_process) +
        @($udpAll.owning_process) |
            Where-Object { $_ -gt 0 } |
            Sort-Object -Unique
    )

    foreach ($pidValue in $pids) {
        try {
            $process = Get-Process -Id $pidValue -ErrorAction Stop
            $path = $null

            try {
                $path = $process.Path
            }
            catch {
                $processPathErrors++
            }

            $processes.Add([PSCustomObject]@{
                pid = $process.Id
                name = $process.ProcessName
                path = $path
                path_visible = (
                    -not [string]::IsNullOrWhiteSpace($path)
                )
                start_time = try {
                    $process.StartTime.ToUniversalTime().ToString('o')
                }
                catch {
                    $null
                }
            })
        }
        catch {
            $processPathErrors++
        }
    }

    Add-AxiosCapability `
        'process_endpoint_correlation' `
        $(if ($processPathErrors -gt 0) { 'partial' } else { 'collected' }) `
        ("unavailable_process_paths={0}" -f $processPathErrors)
}
else {
    Add-AxiosCapability 'tcp_connections' 'not_requested' $focus
    Add-AxiosCapability 'udp_endpoints' 'not_requested' $focus
    Add-AxiosCapability 'process_endpoint_correlation' 'not_requested' $focus
}

if (Test-AxiosFocus @('overview', 'services', 'firewall')) {
    try {
        $firewallProfiles = @(
            Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled,
                    DefaultInboundAction, DefaultOutboundAction,
                    AllowInboundRules, AllowLocalFirewallRules,
                    LogAllowed, LogBlocked, LogFileName
        )
        Add-AxiosCapability 'firewall_profiles' 'collected' ''
    }
    catch {
        Add-AxiosError 'firewall_profiles' $_
        Add-AxiosCapability 'firewall_profiles' 'failed' $_.Exception.Message
    }
}
else {
    Add-AxiosCapability 'firewall_profiles' 'not_requested' $focus
}

if (Test-AxiosFocus @('firewall')) {
    if ($effectiveProfile -eq 'administrator') {
        try {
            $firewallRulesAll = @(
                Get-NetFirewallRule -ErrorAction Stop |
                    Sort-Object -Property @{ Expression = 'Enabled'; Descending = $true }, @{ Expression = 'Direction'; Descending = $false }, @{ Expression = 'DisplayName'; Descending = $false } |
                    Select-Object Name, DisplayName, Description,
                        Enabled, Direction, Action, Profile,
                        PolicyStoreSourceType, PrimaryStatus, Status
            )
            Add-AxiosCapability 'firewall_rules' 'collected' ''
        }
        catch {
            Add-AxiosError 'firewall_rules' $_
            Add-AxiosCapability 'firewall_rules' 'failed' $_.Exception.Message
        }
    }
    else {
        Add-AxiosCapability `
            'firewall_rules' `
            'not_attempted' `
            'administrator_required'
    }
}
else {
    Add-AxiosCapability 'firewall_rules' 'not_requested' $focus
}

if ($focus -eq 'targeted') {
    Add-AxiosCapability `
        'passive_collection' `
        'not_requested' `
        'targeted_focus_runs_only_explicit_connect_checks'
}

Add-AxiosCapability `
    'raw_packet_capture' `
    'not_attempted' `
    'a trusted packet-capture driver is required; socket metadata is not packet capture'

$tcpReturned = @($tcpAll | Select-Object -First __MAX_TCP__)
$udpReturned = @($udpAll | Select-Object -First __MAX_UDP__)
$dnsReturned = @($dnsAll | Select-Object -First __MAX_DNS__)
$routesReturned = @($routesAll | Select-Object -First __MAX_ROUTES__)
$neighborsReturned = @(
    $neighborsAll |
        Select-Object -First __MAX_NEIGHBORS__
)
$firewallRulesReturned = @(
    $firewallRulesAll |
        Select-Object -First __MAX_FIREWALL_RULES__
)

$truncation = [PSCustomObject]@{
    tcp_connections = [PSCustomObject]@{
        total = $tcpAll.Count
        returned = $tcpReturned.Count
        limit = __MAX_TCP__
        truncated = ($tcpAll.Count -gt $tcpReturned.Count)
    }
    udp_endpoints = [PSCustomObject]@{
        total = $udpAll.Count
        returned = $udpReturned.Count
        limit = __MAX_UDP__
        truncated = ($udpAll.Count -gt $udpReturned.Count)
    }
    dns_cache = [PSCustomObject]@{
        total = $dnsAll.Count
        returned = $dnsReturned.Count
        limit = __MAX_DNS__
        truncated = ($dnsAll.Count -gt $dnsReturned.Count)
    }
    routes = [PSCustomObject]@{
        total = $routesAll.Count
        returned = $routesReturned.Count
        limit = __MAX_ROUTES__
        truncated = ($routesAll.Count -gt $routesReturned.Count)
    }
    neighbors = [PSCustomObject]@{
        total = $neighborsAll.Count
        returned = $neighborsReturned.Count
        limit = __MAX_NEIGHBORS__
        truncated = ($neighborsAll.Count -gt $neighborsReturned.Count)
    }
    firewall_rules = [PSCustomObject]@{
        total = $firewallRulesAll.Count
        returned = $firewallRulesReturned.Count
        limit = __MAX_FIREWALL_RULES__
        truncated = (
            $firewallRulesAll.Count -gt
            $firewallRulesReturned.Count
        )
    }
}

$isTruncated = @(
    $truncation.PSObject.Properties.Value |
        Where-Object { $_.truncated }
).Count -gt 0

$partialCapabilities = @(
    $capabilities |
        Where-Object {
            $_.status -in @('failed', 'partial')
        }
)

if ($focus -in @('firewall', 'full')) {
    foreach ($capability in @(
        $capabilities |
            Where-Object {
                $_.name -eq 'firewall_rules' -and
                $_.status -eq 'not_attempted'
            }
    )) {
        $errors.Add((
            '{0}: {1}; {2}' -f
            $capability.name,
            $capability.status,
            $capability.reason
        ))
    }
}

$collectionStatus = if (
    $errors.Count -gt 0 -or
    $isTruncated -or
    $partialCapabilities.Count -gt 0
) {
    'partial'
}
else {
    'complete'
}

[PSCustomObject]@{
    success = $true
    collector = 'axios_network_deep_review_raw'
    collection_status = $collectionStatus
    collection_errors = @($errors)
    execution_context = [PSCustomObject]@{
        administrator = $isAdministrator
        requested_profile = $requestedProfile
        effective_profile = $effectiveProfile
        focus = $focus
    }
    capabilities = @($capabilities)
    limits = [PSCustomObject]@{
        max_tcp = __MAX_TCP__
        max_udp = __MAX_UDP__
        max_dns = __MAX_DNS__
        max_routes = __MAX_ROUTES__
        max_neighbors = __MAX_NEIGHBORS__
        max_firewall_rules = __MAX_FIREWALL_RULES__
    }
    truncation = $truncation
    totals = [PSCustomObject]@{
        adapters = $adaptersAll.Count
        routes_total = $routesAll.Count
        routes_returned = $routesReturned.Count
        neighbors_total = $neighborsAll.Count
        neighbors_returned = $neighborsReturned.Count
        dns_total = $dnsAll.Count
        dns_returned = $dnsReturned.Count
        tcp_total = $tcpAll.Count
        tcp_returned = $tcpReturned.Count
        udp_total = $udpAll.Count
        udp_returned = $udpReturned.Count
        firewall_rules_total = $firewallRulesAll.Count
        firewall_rules_returned = $firewallRulesReturned.Count
        process_paths_unavailable = $processPathErrors
    }
    adapters = $adaptersAll
    ip_configuration = $ipConfiguration
    routes = $routesReturned
    neighbors = $neighborsReturned
    dns_cache = $dnsReturned
    tcp_connections = $tcpReturned
    udp_endpoints = $udpReturned
    processes = @($processes)
    firewall_profiles = $firewallProfiles
    firewall_rules = $firewallRulesReturned
    proxy = $proxy
    wireless = $wireless
} | ConvertTo-Json -Depth 12 -Compress
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn options(focus: Focus) -> Options {
        Options {
            profile: Profile::Auto,
            focus,
            target: Vec::new(),
            ports: Vec::new(),
            timeout_ms: 750,
            max_tcp: 2048,
            max_udp: 1024,
            max_dns: 1024,
            max_routes: 1024,
            max_neighbors: 1024,
            max_firewall_rules: 2048,
            output: None,
        }
    }

    #[test]
    fn explicit_targets_require_connections_targeted_or_full_focus() {
        let mut value = options(Focus::Dns);
        value.target.push("127.0.0.1".to_string());
        assert!(validate_options(&mut value).is_err());

        let mut connections = options(Focus::Connections);
        connections.target.push("127.0.0.1".to_string());
        validate_options(&mut connections).unwrap();
    }

    #[test]
    fn cidr_and_wildcard_targets_are_rejected() {
        for target in ["192.168.1.0/24", "*", "host name"] {
            let mut value = options(Focus::Targeted);
            value.target.push(target.to_string());
            assert!(validate_options(&mut value).is_err());
        }
    }

    #[test]
    fn targeted_checks_are_strictly_bounded() {
        let mut value = options(Focus::Targeted);
        value.target.push("127.0.0.1".to_string());
        validate_options(&mut value).unwrap();

        assert!(value.target.len() <= MAX_TARGETS);
        assert!(value.ports.len() <= MAX_PORTS);
        assert!(value.timeout_ms <= 10_000);
    }

    #[test]
    fn spaces_in_arguments_do_not_make_a_process_path_user_writable() {
        assert!(!is_user_writable_path(
            r"C:\Windows\System32\svchost.exe -k LocalService"
        ));
        assert!(is_user_writable_path(
            r"C:\Users\TestUser\AppData\Local\agent.exe"
        ));
    }

    #[test]
    fn private_and_loopback_addresses_are_not_public() {
        assert!(!is_public_address("127.0.0.1"));
        assert!(!is_public_address("10.0.0.1"));
        assert!(!is_public_address("192.168.1.10"));
        assert!(!is_public_address("::1"));
        assert!(is_public_address("8.8.8.8"));
    }

    #[test]
    fn reserved_and_documentation_addresses_are_not_public() {
        for address in [
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_address(address), "{address}");
        }
        assert!(is_public_address("::ffff:8.8.8.8"));
    }

    #[test]
    fn failed_target_resolution_is_partial_not_a_completed_check() {
        let active = [ActiveResult {
            target: "invalid.example".to_string(),
            resolved_address: String::new(),
            port: 443,
            transport: "tcp",
            state: "resolution_failed",
            error_kind: Some("NotFound".to_string()),
            error: Some("name was not resolved".to_string()),
            duration_ms: 0,
            service_hint: "https",
        }];
        let report = build_report(
            &json!({"success": true, "collection_status": "complete"}),
            &active,
            &options(Focus::Targeted),
        );
        assert_eq!(report["collection_status"], "partial");
        assert_eq!(report["summary"]["active_checks_completed"], 0);
        assert_eq!(report["summary"]["active_resolution_failures"], 1);
        assert_eq!(report["collection_errors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn open_target_port_is_an_observation_not_a_vulnerability_claim() {
        let report = build_report(
            &json!({
                "success": true,
                "collection_status": "complete",
                "tcp_connections": [],
                "processes": [],
                "totals": {}
            }),
            &[ActiveResult {
                target: "127.0.0.1".to_string(),
                resolved_address: "127.0.0.1".to_string(),
                port: 443,
                transport: "tcp",
                state: "open",
                error_kind: None,
                error: None,
                duration_ms: 1,
                service_hint: "https",
            }],
            &options(Focus::Targeted),
        );

        assert_eq!(report["summary"]["active_open_ports"], 1);
        assert_eq!(report["summary"]["findings"], 0);
        assert_eq!(report["observations"][0]["target"], "127.0.0.1");
        assert_eq!(report["observations"][0]["resolved_address"], "127.0.0.1");
        assert_eq!(report["observations"][0]["port"], 443);
        assert_eq!(report["claim_policy"]["vulnerability_confirmed"], false);
    }
}
