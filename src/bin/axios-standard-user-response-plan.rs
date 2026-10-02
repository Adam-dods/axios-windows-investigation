use anyhow::{bail, Result};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-standard-user-response-plan")]
struct Options {
    #[arg(long)]
    scope: PathBuf,
    #[arg(long)]
    exposure: PathBuf,
    #[arg(long)]
    network: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    let scope = read_successful_report(&options.scope, "scope")?;
    let exposure = read_successful_report(&options.exposure, "exposure")?;
    let network = read_successful_report(&options.network, "network")?;
    let report = build_report(&scope, &exposure, &network);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn read_successful_report(path: &PathBuf, name: &str) -> Result<Value> {
    let report = json_file::read_value(path)?;

    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{name} report must explicitly declare success=true");
    }

    Ok(report)
}

fn findings_by_priority(report: &Value, priority: &str) -> Vec<Value> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|finding| finding.get("priority").and_then(Value::as_str) == Some(priority))
        .cloned()
        .collect()
}

fn array_count(report: &Value, name: &str) -> usize {
    report
        .get(name)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn build_report(scope: &Value, exposure: &Value, network: &Value) -> Value {
    let mut actions = Vec::new();
    let high_scope = findings_by_priority(scope, "high");
    let high_exposure = findings_by_priority(exposure, "high");

    for finding in high_scope.iter().chain(high_exposure.iter()) {
        actions.push(json!({
            "priority": "high",
            "classification": "requires_verification",
            "title": finding.get("title").cloned().unwrap_or_else(|| json!("User-scope exposure requires verification")),
            "evidence": finding,
            "next_check": finding.get("next_check").cloned().unwrap_or_else(|| json!("Verify provenance, effective permissions, and change history before any remediation."))
        }));
    }

    let powershell_profiles = array_count(scope, "powershell_profiles");
    if powershell_profiles > 0 {
        actions.push(json!({
            "priority": "medium",
            "classification": "configuration_review",
            "title": "Current-user PowerShell profiles require baseline review",
            "evidence": {
                "profile_count": powershell_profiles
            },
            "next_check": "Review profile content and compare each SHA-256 hash to an approved baseline. Presence alone is not malicious."
        }));
    }

    let ssh_files = array_count(scope, "ssh_persistence_files");
    if ssh_files > 0 {
        actions.push(json!({
            "priority": "medium",
            "classification": "access_review",
            "title": "Current-user SSH access files require ownership review",
            "evidence": {
                "file_count": ssh_files
            },
            "next_check": "Confirm every authorized key and SSH configuration entry is expected. Preserve metadata before changing access configuration."
        }));
    }

    if scope.get("collection_status").and_then(Value::as_str) == Some("partial")
        || exposure.get("collection_status").and_then(Value::as_str) == Some("partial")
        || network.get("collection_status").and_then(Value::as_str) == Some("partial")
    {
        actions.push(json!({
            "priority": "medium",
            "classification": "visibility_limited",
            "title": "Standard-user evidence collection is partially limited",
            "next_check": "Review collection_errors and use an approved Administrator audit for system-wide verification. Limited visibility is not evidence of compromise."
        }));
    }

    let proxy_enabled = network
        .pointer("/user_proxy/ProxyEnable")
        .and_then(Value::as_i64)
        .is_some_and(|value| value != 0);

    if proxy_enabled {
        actions.push(json!({
            "priority": "low",
            "classification": "network_configuration_review",
            "title": "Current-user proxy is enabled",
            "evidence": {
                "proxy_server": network.pointer("/user_proxy/ProxyServer").cloned().unwrap_or(Value::Null),
                "auto_config_url": network.pointer("/user_proxy/AutoConfigURL").cloned().unwrap_or(Value::Null)
            },
            "next_check": "Confirm the proxy configuration belongs to the approved network environment. A proxy setting alone is not malicious."
        }));
    }

    actions.truncate(200);

    json!({
        "success": true,
        "collector": "axios_standard_user_response_plan",
        "execution_context": {
            "administrator": false,
            "scope": "read_only_standard_user_assessment",
            "claim_policy": {
                "malware_confirmed": false,
                "intrusion_confirmed": false,
                "privilege_escalation_confirmed": false
            }
        },
        "summary": {
            "high_scope_findings": high_scope.len(),
            "high_exposure_findings": high_exposure.len(),
            "response_actions": actions.len()
        },
        "actions": actions
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn successful_report() -> Value {
        json!({
            "success": true,
            "collection_status": "complete",
            "findings": []
        })
    }

    #[test]
    fn high_exposure_becomes_high_verification_action() {
        let scope = successful_report();
        let exposure = json!({
            "success": true,
            "collection_status": "complete",
            "findings": [{
                "priority": "high",
                "title": "System service has a potentially broad write permission",
                "next_check": "Verify effective permissions."
            }]
        });
        let network = successful_report();

        let report = build_report(&scope, &exposure, &network);

        assert_eq!(report["summary"]["high_exposure_findings"], 1);
        assert_eq!(report["actions"][0]["priority"], "high");
        assert_eq!(
            report["execution_context"]["claim_policy"]["malware_confirmed"],
            false
        );
    }

    #[test]
    fn partial_visibility_becomes_medium_action() {
        let scope = json!({
            "success": true,
            "collection_status": "partial",
            "findings": []
        });
        let exposure = successful_report();
        let network = successful_report();

        let report = build_report(&scope, &exposure, &network);

        assert!(report["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| { action["classification"].as_str() == Some("visibility_limited") }));
    }
}
