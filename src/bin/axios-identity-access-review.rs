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
#[command(name = "axios-identity-access-review")]
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

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$users = @(
    Get-LocalUser -ErrorAction Stop |
        Select-Object Name, Enabled, PasswordRequired, PasswordExpires, LastLogon, PrincipalSource
)

[PSCustomObject]@{
    success = $true
    users = $users
    lsa = [PSCustomObject]@{
        limit_blank_password_use = Read-AxiosRegistryValue $lsaPath "LimitBlankPasswordUse"
        no_lm_hash = Read-AxiosRegistryValue $lsaPath "NoLMHash"
        disable_domain_creds = Read-AxiosRegistryValue $lsaPath "DisableDomainCreds"
        cached_logons_count = Read-AxiosRegistryValue $winlogonPath "CachedLogonsCount"
    }
} | ConvertTo-Json -Depth 7 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("identity access collector failed: {}", output.stderr);
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

    for user in snapshot
        .get("users")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let name = user.get("Name").and_then(Value::as_str).unwrap_or("");
        let enabled_account = user.get("Enabled").and_then(Value::as_bool) == Some(true);

        if enabled_account && name.eq_ignore_ascii_case("Guest") {
            findings.push(json!({
                "priority": "high",
                "id": "guest_account_enabled",
                "classification": "local_account_exposure",
                "account": name,
                "reason": "built-in Guest account is enabled"
            }));
        }

        if enabled_account && user.get("PasswordRequired").and_then(Value::as_bool) == Some(false) {
            findings.push(json!({
                "priority": "medium",
                "id": format!("password_not_required:{name}"),
                "classification": "local_account_hardening_gap",
                "account": name,
                "reason": "enabled local account does not require a password; verify the account purpose and policy"
            }));
        }
    }

    if snapshot
        .pointer("/lsa/limit_blank_password_use")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "high",
            "id": "blank_password_network_restriction_disabled",
            "classification": "credential_control_disabled",
            "reason": "local accounts with blank passwords are not restricted to console logon by observed configuration"
        }));
    }

    if snapshot
        .pointer("/lsa/no_lm_hash")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "lm_hash_prevention_not_enabled",
            "classification": "legacy_credential_protection_gap",
            "reason": "LM hash prevention is not enabled by observed configuration"
        }));
    }

    if snapshot
        .pointer("/lsa/disable_domain_creds")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "context",
            "id": "domain_credentials_may_be_cached",
            "classification": "credential_exposure_context",
            "reason": "Windows is not configured to block cached domain credentials; review only when the device uses domain authentication"
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
        "collector": "axios_identity_access_review",
        "read_only": true,
        "database_used": false,
        "credential_theft_confirmed": false,
        "policy": {
            "guest_enabled": "high_priority_configuration_finding_not_intrusion_proof",
            "blank_password_restriction_disabled": "high_priority_review",
            "credential_cache": "context_requires_identity_environment_review"
        },
        "summary": {
            "local_accounts_observed": snapshot.get("users").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
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
        let source = include_str!("axios-identity-access-review.rs");

        assert!(source.contains("catch {\n        throw\n    }"));
        assert!(!source.contains("catch {\n        $null\n    }"));
    }
    use super::*;

    #[test]
    fn enabled_guest_account_is_high_priority() {
        let report = build_report(&json!({
            "users": [{
                "Name": "Guest",
                "Enabled": true,
                "PasswordRequired": true
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "high");
    }

    #[test]
    fn blank_password_network_restriction_is_high_priority() {
        let report = build_report(&json!({
            "lsa": {
                "limit_blank_password_use": 0
            }
        }));

        assert_eq!(report["summary"]["high_priority_findings"], 1);
    }

    #[test]
    fn unavailable_lsa_controls_are_not_claimed_disabled() {
        let report = build_report(&serde_json::json!({
            "lsa": {
                "limit_blank_password_use": null,
                "no_lm_hash": null,
                "disable_domain_creds": null
            },
            "users": []
        }));

        assert!(report["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn collector_does_not_hide_local_user_enumeration_failure() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bin/axios-identity-access-review.rs"
        ));

        assert!(source.contains("Get-LocalUser -ErrorAction Stop"));

        let suppressed_form = concat!("Get-LocalUser -ErrorAction ", "SilentlyContinue");

        assert!(!source.contains(suppressed_form));
    }
}
