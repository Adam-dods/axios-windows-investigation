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
#[command(name = "axios-security-controls-review")]
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

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$smartScreenPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$preference = if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    Get-MpPreference -ErrorAction Stop
}
else {
    $null
}

$firewallProfiles = @(
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, LogAllowed, LogBlocked, LogFileName
    }
    else {
        $legacyFirewall = New-Object -ComObject HNetCfg.FwPolicy2

        foreach ($legacyProfile in @(
            [PSCustomObject]@{ Name = "Domain"; Id = 1 },
            [PSCustomObject]@{ Name = "Private"; Id = 2 },
            [PSCustomObject]@{ Name = "Public"; Id = 4 }
        )) {
            [PSCustomObject]@{
                Name = $legacyProfile.Name
                Enabled = [bool]$legacyFirewall.FirewallEnabled(
                    [int]$legacyProfile.Id
                )
                LogAllowed = $null
                LogBlocked = $null
                LogFileName = $null
                source = "HNetCfg.FwPolicy2"
            }
        }
    }
)

[PSCustomObject]@{
    success = $true
    uac = [PSCustomObject]@{
        enable_lua = Read-AxiosRegistryValue $uacPath "EnableLUA"
        secure_desktop = Read-AxiosRegistryValue $uacPath "PromptOnSecureDesktop"
    }
    smartscreen = [PSCustomObject]@{
        explorer = Read-AxiosRegistryValue $smartScreenPath "SmartScreenEnabled"
        policy_enabled = Read-AxiosRegistryValue $smartScreenPolicyPath "EnableSmartScreen"
        policy_level = Read-AxiosRegistryValue $smartScreenPolicyPath "ShellSmartScreenLevel"
    }
    lsa = [PSCustomObject]@{
        run_as_ppl = Read-AxiosRegistryValue $lsaPath "RunAsPPL"
        run_as_ppl_boot = Read-AxiosRegistryValue $lsaPath "RunAsPPLBoot"
        credential_guard = Read-AxiosRegistryValue $lsaPath "LsaCfgFlags"
    }
    defender = [PSCustomObject]@{
        disable_realtime = $preference.DisableRealtimeMonitoring
        disable_behavior = $preference.DisableBehaviorMonitoring
        disable_ioav = $preference.DisableIOAVProtection
        disable_script = $preference.DisableScriptScanning
        enable_network_protection = $preference.EnableNetworkProtection
        pua_protection = $preference.PUAProtection
        exclusions = @($preference.ExclusionPath)
    }
    firewall_profiles = $firewallProfiles
} | ConvertTo-Json -Depth 8 -Compress
"#;

    let output = powershell(script)?;
    if !output.success {
        bail!("security controls collector failed: {}", output.stderr);
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

fn number_is_enabled(value: &Value) -> bool {
    value
        .as_i64()
        .map(|number| number != 0)
        .unwrap_or_else(|| value.as_bool().unwrap_or(false))
}

fn is_user_writable_exclusion(path: &str) -> bool {
    let value = path.replace('/', "\\").to_ascii_lowercase();

    value.contains(r"\users\")
        || value.contains(r"\temp\")
        || value.contains(r"\downloads\")
        || value.contains(r"\appdata\")
}

fn observed_enabled(value: &Value) -> Option<bool> {
    if let Some(value) = value.as_bool() {
        Some(value)
    } else if value.is_null() {
        None
    } else {
        Some(number_is_enabled(value))
    }
}

fn build_report(snapshot: &Value) -> Value {
    let mut findings = Vec::new();

    if snapshot
        .pointer("/uac/enable_lua")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "high",
            "id": "uac_disabled",
            "classification": "security_control_disabled",
            "reason": "EnableLUA is disabled; UAC protections are materially reduced"
        }));
    }

    if snapshot
        .pointer("/uac/secure_desktop")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "uac_secure_desktop_disabled",
            "classification": "security_control_weakened",
            "reason": "UAC prompts do not require the secure desktop"
        }));
    }

    let smart_screen = snapshot
        .pointer("/smartscreen/explorer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();

    if smart_screen == "off"
        || snapshot
            .pointer("/smartscreen/policy_enabled")
            .and_then(observed_enabled)
            == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "smartscreen_disabled",
            "classification": "security_control_weakened",
            "reason": "SmartScreen is disabled by observed local configuration"
        }));
    }

    for control in [
        "disable_realtime",
        "disable_behavior",
        "disable_ioav",
        "disable_script",
    ] {
        if snapshot
            .pointer(&format!("/defender/{control}"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            findings.push(json!({
                "priority": "high",
                "id": format!("defender_{control}"),
                "classification": "defender_protection_disabled",
                "reason": "a Defender protection control is disabled"
            }));
        }
    }

    if snapshot
        .pointer("/defender/enable_network_protection")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "defender_network_protection_disabled",
            "classification": "security_control_weakened",
            "reason": "Defender network protection is disabled"
        }));
    }

    if snapshot
        .pointer("/defender/pua_protection")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "defender_pua_protection_disabled",
            "classification": "security_control_weakened",
            "reason": "Defender potentially unwanted application protection is disabled"
        }));
    }

    for exclusion in snapshot
        .pointer("/defender/exclusions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let path = exclusion.as_str().unwrap_or("");

        if is_user_writable_exclusion(path) {
            findings.push(json!({
                "priority": "high",
                "id": "defender_user_writable_exclusion",
                "classification": "defender_exclusion_requires_review",
                "path": path,
                "reason": "Defender excludes a user-writable location"
            }));
        }
    }

    if snapshot
        .pointer("/lsa/run_as_ppl")
        .and_then(observed_enabled)
        == Some(false)
    {
        findings.push(json!({
            "priority": "medium",
            "id": "lsa_protection_not_enabled",
            "classification": "credential_protection_gap",
            "reason": "LSA protected process is not enabled by observed configuration"
        }));
    }

    for profile in snapshot
        .get("firewall_profiles")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let name = profile
            .get("Name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        if profile.get("Enabled").and_then(observed_enabled) == Some(false) {
            findings.push(json!({
                "priority": "high",
                "id": format!("firewall_profile_disabled:{name}"),
                "classification": "firewall_disabled",
                "reason": "Windows Firewall profile is disabled"
            }));
        } else if profile.get("LogAllowed").and_then(observed_enabled) == Some(false)
            && profile.get("LogBlocked").and_then(observed_enabled) == Some(false)
        {
            findings.push(json!({
                "priority": "context",
                "id": format!("firewall_logging_disabled:{name}"),
                "classification": "forensic_visibility_reduced",
                "reason": "Firewall allowed and blocked connection logging are both disabled"
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

    let context = findings
        .iter()
        .filter(|finding| finding["priority"] == "context")
        .count();

    json!({
        "success": true,
        "collector": "axios_security_controls_review",
        "read_only": true,
        "database_used": false,
        "security_compromise_confirmed": false,
        "policy": {
            "control_disabled": "confirmed_configuration_finding_not_intrusion_proof",
            "user_writable_defender_exclusion": "high_priority_review",
            "firewall_logging_disabled": "visibility_context"
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

    #[test]
    fn registry_read_failure_is_not_silently_converted_to_clean_data() {
        let source = include_str!("axios-security-controls-review.rs");

        assert!(source.contains("catch {\n        throw\n    }"));
        assert!(!source.contains("catch {\n        $null\n    }"));
    }
    use super::*;

    #[test]
    fn user_writable_defender_exclusion_is_high_priority() {
        let report = build_report(&json!({
            "defender": {
                "exclusions": [r"C:\Users\Test\AppData\Local\Temp"]
            }
        }));

        assert_eq!(report["summary"]["high_priority_findings"], 1);
    }

    #[test]
    fn disabled_firewall_logging_is_context_not_intrusion() {
        let report = build_report(&json!({
            "firewall_profiles": [{
                "Name": "Public",
                "Enabled": true,
                "LogAllowed": false,
                "LogBlocked": false
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "context");
    }

    #[test]
    fn null_smartscreen_values_are_visibility_not_disabled() {
        let report = build_report(&serde_json::json!({
            "smartscreen": {"explorer": null, "policy_enabled": null}
        }));

        assert!(!report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"].as_str() == Some("smartscreen_disabled")));
    }
}
