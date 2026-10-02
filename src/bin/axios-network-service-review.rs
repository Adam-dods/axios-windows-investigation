use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{fs, path::PathBuf, time::Instant};

#[cfg(windows)]
use axios_core::command::powershell;

#[derive(Parser, Debug)]
#[command(name = "axios-network-service-review")]
struct Options {
    #[arg(long)]
    network_exposure: PathBuf,

    #[arg(long, default_value_t = 1024)]
    max_rules: usize,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let input: Value = serde_json::from_slice(
        &fs::read(&options.network_exposure)
            .with_context(|| format!("failed to read {}", options.network_exposure.display()))?,
    )
    .context("network exposure input is not valid JSON")?;

    validate_success(&input, "network exposure")?;

    let firewall_collection_started = Instant::now();

    let (firewall, collection_error) = match collect_firewall_snapshot(options.max_rules) {
        Ok(snapshot) => (snapshot, None),
        Err(error) => (
            json!({
                "profiles": [],
                "inbound_allow_rules": [],
                "services": []
            }),
            Some(error.to_string()),
        ),
    };

    let firewall_collection_elapsed_ms = firewall_collection_started.elapsed().as_millis() as u64;

    let profiles = firewall["profiles"].as_array().cloned().unwrap_or_default();
    let rules = firewall["inbound_allow_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let services = firewall["services"].as_array().cloned().unwrap_or_default();

    let enabled_firewall_profiles = profiles
        .iter()
        .filter(|profile| firewall_profile_is_enabled(profile))
        .count();

    let default_inbound_allow_profiles = profiles
        .iter()
        .filter(|profile| firewall_profile_uses_default_inbound_allow(profile))
        .count();

    let source_artifacts = input["artifacts"].as_array().cloned().unwrap_or_default();
    let reviewable: Vec<Value> = source_artifacts
        .into_iter()
        .filter(|artifact| text(artifact.get("classification")) == "needs_review")
        .filter(|artifact| artifact.get("local_port").and_then(Value::as_u64).is_some())
        .collect();

    let mut artifacts = Vec::new();
    let mut context_count = 0_u64;
    let mut needs_review_count = 0_u64;
    let mut rule_match_count = 0_u64;

    for endpoint in reviewable {
        let protocol = text(endpoint.get("protocol")).to_lowercase();
        let port = endpoint["local_port"].as_u64().unwrap_or_default() as u16;
        let service_role = text(endpoint.get("service_role"));
        let service_name = system_service_for(port, &service_role);

        let matching_rules: Vec<Value> = rules
            .iter()
            .filter(|rule| {
                protocol_matches(&text(rule.get("protocol")), &protocol)
                    && port_matches(&text(rule.get("local_port")), port)
            })
            .take(24)
            .cloned()
            .collect();

        let externally_reachable = endpoint
            .get("externally_reachable")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let service_state = service_name
            .as_deref()
            .and_then(|name| {
                services
                    .iter()
                    .find(|service| text(service.get("name")).eq_ignore_ascii_case(name))
            })
            .cloned()
            .unwrap_or(Value::Null);

        let (classification, reason) = if collection_error.is_some() {
            ("needs_review", "firewall_correlation_unavailable")
        } else if default_inbound_allow_profiles > 0 {
            (
                "needs_review",
                "an_enabled_firewall_profile_uses_default_inbound_allow",
            )
        } else if !matching_rules.is_empty() {
            rule_match_count += 1;
            (
                "needs_review",
                "enabled_inbound_allow_rule_matches_listener",
            )
        } else {
            context_count += 1;
            (
                "context",
                "listener_has_no_matching_enabled_inbound_allow_rule",
            )
        };

        let risk_level = firewall_risk_level(
            collection_error.is_none(),
            default_inbound_allow_profiles,
            matching_rules.len(),
            externally_reachable,
        );

        if classification == "needs_review" {
            needs_review_count += 1;
        }

        artifacts.push(json!({
            "classification": classification,
            "risk_level": risk_level,
            "protocol": protocol,
            "local_address": endpoint.get("local_address").cloned().unwrap_or(Value::Null),
            "local_port": port,
            "service_role": service_role,
            "expected_system_service": service_name,
            "reason": reason,
            "evidence": {
                "firewall_collection_available": collection_error.is_none(),
                "externally_reachable": externally_reachable,
                "enabled_firewall_profile_count": enabled_firewall_profiles,
                "default_inbound_allow_profile_count": default_inbound_allow_profiles,
                "matching_inbound_allow_rule_count": matching_rules.len()
            },
            "process": endpoint.get("process").cloned().unwrap_or(Value::Null),
            "matching_inbound_allow_rules": matching_rules,
            "service_state": service_state
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "collector": "axios_network_service_review",
            "success": collection_error.is_none(),
            "collection_error": collection_error,
            "collection": {
                "firewall_collection_elapsed_ms": firewall_collection_elapsed_ms,
                "firewall_profiles_collected": profiles.len(),
                "inbound_allow_rules_collected": rules.len(),
                "system_services_collected": services.len()
            },
            "summary": {
                "endpoints_reviewed": artifacts.len(),
                "context": context_count,
                "needs_review": needs_review_count,
                "endpoints_with_matching_inbound_allow_rules": rule_match_count,
                "enabled_firewall_profiles": enabled_firewall_profiles,
                "default_inbound_allow_profiles": default_inbound_allow_profiles
            },
            "firewall_profiles": profiles,
            "artifacts": artifacts
        }))?
    );

    Ok(())
}

fn text(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_i64().unwrap_or_default() != 0,
        Some(Value::String(value)) => {
            value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("enabled")
                || value == "1"
        }
        _ => false,
    }
}

fn normalized_property_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn property_case_insensitive<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let expected = normalized_property_name(name);

    value
        .as_object()?
        .iter()
        .find(|(key, _)| normalized_property_name(key) == expected)
        .map(|(_, property)| property)
}

fn firewall_profile_is_enabled(profile: &Value) -> bool {
    truthy(property_case_insensitive(profile, "enabled"))
}

fn firewall_profile_uses_default_inbound_allow(profile: &Value) -> bool {
    firewall_profile_is_enabled(profile)
        && text(property_case_insensitive(profile, "default_inbound_action"))
            .eq_ignore_ascii_case("allow")
}

fn firewall_risk_level(
    collection_available: bool,
    default_inbound_allow_profiles: usize,
    matching_rule_count: usize,
    externally_reachable: bool,
) -> &'static str {
    if !collection_available {
        "unknown"
    } else if default_inbound_allow_profiles > 0 {
        "high"
    } else if matching_rule_count > 0 && externally_reachable {
        "medium"
    } else if matching_rule_count > 0 {
        "low"
    } else {
        "informational"
    }
}

fn validate_success(report: &Value, name: &str) -> Result<()> {
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }
    Ok(())
}

fn system_service_for(port: u16, service_role: &str) -> Option<String> {
    match (port, service_role.to_ascii_lowercase().as_str()) {
        (80, "http") => Some("HTTP".to_string()),
        (135, "rpc") => Some("RpcSs".to_string()),
        (139, "netbios_session") | (445, "smb") => Some("LanmanServer".to_string()),
        _ => None,
    }
}

fn protocol_matches(rule_protocol: &str, endpoint_protocol: &str) -> bool {
    let rule = rule_protocol.trim().to_ascii_lowercase();
    rule.is_empty()
        || rule == "any"
        || rule == "256"
        || rule == endpoint_protocol.to_ascii_lowercase()
}

fn port_matches(rule_ports: &str, endpoint_port: u16) -> bool {
    let ports = rule_ports.trim();

    if ports.is_empty()
        || ports.eq_ignore_ascii_case("any")
        || ports == "*"
        || ports.eq_ignore_ascii_case("rpc")
    {
        return true;
    }

    ports.split(',').any(|entry| {
        let entry = entry.trim();

        if let Some((start, end)) = entry.split_once('-') {
            return start.trim().parse::<u16>().ok().is_some_and(|start| {
                end.trim()
                    .parse::<u16>()
                    .ok()
                    .is_some_and(|end| endpoint_port >= start && endpoint_port <= end)
            });
        }

        entry
            .parse::<u16>()
            .ok()
            .is_some_and(|port| port == endpoint_port)
    })
}

#[cfg(any(windows, test))]
fn bounded_firewall_rule_limit(max_rules: usize) -> usize {
    max_rules.clamp(1, 4096)
}

#[cfg(windows)]
fn collect_firewall_snapshot(max_rules: usize) -> Result<Value> {
    let max_rules = bounded_firewall_rule_limit(max_rules);
    let script = r#"
$Limit = __AXIOS_FIREWALL_RULE_LIMIT__

$profiles = @(
    Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
)

$portFilters = @(
    Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop
)

$allRules = @(
    $portFilters | Get-NetFirewallRule -ErrorAction Stop
)

$rulesByName = @{}
foreach ($rule in $allRules) {
    $rulesByName[[string]$rule.Name] = $rule
}

$servicesByRule = @{}
Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore -ErrorAction Stop |
    ForEach-Object {
        $servicesByRule[[string]$_.InstanceID] = $_
    }

$applicationsByRule = @{}
Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop |
    ForEach-Object {
        $applicationsByRule[[string]$_.InstanceID] = $_
    }

$addressesByRule = @{}
Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop |
    ForEach-Object {
        $addressesByRule[[string]$_.InstanceID] = $_
    }

$candidateRules = @(
    foreach ($port in $portFilters) {
        $ruleKey = [string]$port.InstanceID
        $rule = $rulesByName[$ruleKey]

        if ($null -eq $rule) {
            continue
        }

        if (
            [string]$rule.Enabled -ne "True" -or
            [string]$rule.Direction -ne "Inbound" -or
            [string]$rule.Action -ne "Allow"
        ) {
            continue
        }

        [PSCustomObject]@{
            display_name = $rule.DisplayName
            name = $rule.Name
            profile = $rule.Profile
            protocol = $port.Protocol
            local_port = $port.LocalPort
            remote_port = $port.RemotePort
            service = if ($servicesByRule.ContainsKey($ruleKey)) {
                $servicesByRule[$ruleKey].Service
            } else {
                $null
            }
            program = if ($applicationsByRule.ContainsKey($ruleKey)) {
                $applicationsByRule[$ruleKey].Program
            } else {
                $null
            }
            remote_address = if ($addressesByRule.ContainsKey($ruleKey)) {
                $addressesByRule[$ruleKey].RemoteAddress
            } else {
                $null
            }
        }
    }
)

$rules = @(
    $candidateRules | Select-Object -First $Limit
)

$services = @(
    "HTTP", "RpcSs", "LanmanServer" |
        ForEach-Object {
            $name = $_
            $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop

            [PSCustomObject]@{
                name = $name
                exists = $null -ne $service
                state = if ($service) { $service.State } else { $null }
                start_mode = if ($service) { $service.StartMode } else { $null }
                path_name = if ($service) { $service.PathName } else { $null }
            }
        }
)

[PSCustomObject]@{
    profiles = $profiles
    inbound_allow_rules = $rules
    services = $services
} | ConvertTo-Json -Depth 8 -Compress
"#
    .replace("__AXIOS_FIREWALL_RULE_LIMIT__", &max_rules.to_string());

    let output =
        powershell(&script).context("failed to launch PowerShell for firewall collection")?;

    if !output.success {
        bail!("firewall collection failed: {}", output.stderr);
    }

    serde_json::from_str(&output.stdout).context("firewall collector returned invalid JSON")
}

#[cfg(not(windows))]
fn collect_firewall_snapshot(_max_rules: usize) -> Result<Value> {
    bail!("network service review is supported only on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_network_exposure_is_rejected() {
        assert!(validate_success(&json!({"success": false}), "network").is_err());
        assert!(validate_success(&json!({}), "network").is_err());
        assert!(validate_success(&json!({"success": true}), "network").is_ok());
    }

    #[test]
    fn firewall_rule_limit_is_bounded() {
        assert_eq!(bounded_firewall_rule_limit(0), 1);
        assert_eq!(bounded_firewall_rule_limit(1024), 1024);
        assert_eq!(bounded_firewall_rule_limit(usize::MAX), 4096);
    }

    #[test]
    fn firewall_collector_uses_utf8_powershell_wrapper() {
        let source = include_str!("axios-network-service-review.rs");

        assert!(source.contains("powershell(&script)"));
        assert!(!source.contains("\"-Limit\","));
        assert!(!source.contains("Command::new(\"powershell.exe\")"));
    }

    #[test]
    fn firewall_collector_uses_bulk_active_store_filters() {
        let source = include_str!("axios-network-service-review.rs");
        let collector = source
            .split("fn collect_firewall_snapshot(max_rules: usize)")
            .nth(1)
            .and_then(|section| section.split("#[cfg(not(windows))]").next())
            .expect("firewall collector must exist");

        assert!(collector.contains("Get-NetFirewallPortFilter -All -PolicyStore ActiveStore"));
        assert!(collector.contains("$portFilters | Get-NetFirewallRule"));
        assert!(!collector.contains("Get-NetFirewallPortFilter -AssociatedNetFirewallRule"));
        assert!(!collector.contains("Get-NetFirewallServiceFilter -AssociatedNetFirewallRule"));
        assert!(!collector.contains("Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule"));
        assert!(!collector.contains("Get-NetFirewallAddressFilter -AssociatedNetFirewallRule"));
    }

    #[test]
    fn firewall_profile_properties_are_case_insensitive() {
        let powershell_profile = json!({
            "Enabled": true,
            "DefaultInboundAction": "Allow"
        });
        let normalized_profile = json!({
            "enabled": true,
            "default_inbound_action": "block"
        });

        assert!(firewall_profile_is_enabled(&powershell_profile));
        assert!(firewall_profile_uses_default_inbound_allow(
            &powershell_profile
        ));
        assert!(firewall_profile_is_enabled(&normalized_profile));
        assert!(!firewall_profile_uses_default_inbound_allow(
            &normalized_profile
        ));
    }

    #[test]
    fn firewall_risk_level_explains_exposure_context() {
        assert_eq!(firewall_risk_level(false, 0, 0, false), "unknown");
        assert_eq!(firewall_risk_level(true, 1, 0, false), "high");
        assert_eq!(firewall_risk_level(true, 0, 1, true), "medium");
        assert_eq!(firewall_risk_level(true, 0, 1, false), "low");
        assert_eq!(firewall_risk_level(true, 0, 0, false), "informational");
    }

    #[test]
    fn port_match_handles_any_single_and_ranges() {
        assert!(port_matches("Any", 445));
        assert!(port_matches("80,135,139-140", 139));
        assert!(!port_matches("80,135,139-140", 445));
    }

    #[test]
    fn protocol_match_handles_windows_any() {
        assert!(protocol_matches("TCP", "tcp"));
        assert!(protocol_matches("256", "udp"));
        assert!(!protocol_matches("UDP", "tcp"));
    }

    #[test]
    fn system_ports_map_to_expected_services() {
        assert_eq!(system_service_for(135, "rpc").as_deref(), Some("RpcSs"));
        assert_eq!(
            system_service_for(445, "smb").as_deref(),
            Some("LanmanServer")
        );
    }

    #[test]
    fn service_correlation_does_not_suppress_wmi_errors() {
        let source = include_str!("axios-network-service-review.rs");
        let suppressed = concat!(
            "Get-CimInstance Win32_Service -Filter \"Name='$name'\" -ErrorAction ",
            "SilentlyContinue"
        );

        assert!(!source.contains(suppressed));
        assert!(source
            .contains("Get-CimInstance Win32_Service -Filter \"Name='$name'\" -ErrorAction Stop"));
    }
}
