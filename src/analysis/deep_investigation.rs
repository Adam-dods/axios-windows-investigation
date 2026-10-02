use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    persistence,
    system::{access_surface, health_posture, network_posture},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationClassification {
    Context,
    ConfirmedChange,
    NeedsReview,
    SuspiciousActivity,
}

#[derive(Debug, Serialize)]
pub struct InvestigationFinding {
    pub id: String,
    pub classification: InvestigationClassification,
    pub confidence: &'static str,
    pub title: String,
    pub summary: String,
    pub evidence: Value,
}

#[derive(Debug, Serialize)]
pub struct InvestigationSummary {
    pub context: usize,
    pub confirmed_changes: usize,
    pub needs_review: usize,
    pub suspicious_activity: usize,
}

#[derive(Debug, Serialize)]
pub struct DeepInvestigationReport {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub collector: &'static str,
    pub success: bool,
    pub summary: InvestigationSummary,
    pub findings: Vec<InvestigationFinding>,
    pub sources: InvestigationSources,
}

#[derive(Debug, Serialize)]
pub struct InvestigationSources {
    pub access_surface: Value,
    pub network_posture: Value,
    pub registry_persistence: Value,
    pub extended_persistence: Value,
    pub health_posture: Value,
}

pub fn investigate() -> DeepInvestigationReport {
    let sources = InvestigationSources {
        access_surface: access_surface::collect(),
        network_posture: network_posture::collect(),
        registry_persistence: persistence::registry::collect(),
        extended_persistence: persistence::extended::collect(),
        health_posture: health_posture::collect(),
    };

    let success = sources_succeeded(&sources);
    let findings = analyze_sources(&sources);
    let summary = summarize(&findings);

    DeepInvestigationReport {
        schema_version: 1,
        generated_at: Utc::now(),
        collector: "axios_deep_investigation",
        success,
        summary,
        findings,
        sources,
    }
}

fn sources_succeeded(sources: &InvestigationSources) -> bool {
    [
        &sources.access_surface,
        &sources.network_posture,
        &sources.registry_persistence,
        &sources.extended_persistence,
        &sources.health_posture,
    ]
    .into_iter()
    .all(|source| source.get("success").and_then(Value::as_bool) == Some(true))
}

fn analyze_sources(sources: &InvestigationSources) -> Vec<InvestigationFinding> {
    let mut findings = Vec::new();

    add_collection_failure(&mut findings, "access-surface", &sources.access_surface);
    add_collection_failure(&mut findings, "network-posture", &sources.network_posture);
    add_collection_failure(
        &mut findings,
        "registry-persistence",
        &sources.registry_persistence,
    );
    add_collection_failure(
        &mut findings,
        "extended-persistence",
        &sources.extended_persistence,
    );
    add_collection_failure(&mut findings, "health-posture", &sources.health_posture);

    analyze_access_surface(&mut findings, &sources.access_surface);
    analyze_network_posture(&mut findings, &sources.network_posture);
    analyze_registry_persistence(&mut findings, &sources.registry_persistence);
    analyze_extended_persistence(&mut findings, &sources.extended_persistence);
    analyze_health_posture(&mut findings, &sources.health_posture);

    findings
}

fn add_collection_failure(findings: &mut Vec<InvestigationFinding>, source: &str, value: &Value) {
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        findings.push(finding(
            format!("collection-failure-{source}"),
            InvestigationClassification::NeedsReview,
            "low",
            format!("{source} collection failed"),
            "This source could not be collected, so AXIOS cannot assess it.",
            value.clone(),
        ));
    }
}

fn analyze_access_surface(findings: &mut Vec<InvestigationFinding>, value: &Value) {
    if value.get("remote_desktop_enabled").and_then(Value::as_bool) == Some(true) {
        findings.push(finding(
            "remote-desktop-enabled",
            InvestigationClassification::Context,
            "high",
            "Remote Desktop is enabled",
            "Remote Desktop is enabled. This is a configuration fact, not a malware verdict.",
            json!({
                "remote_desktop_enabled": true,
                "remote_services": value.get("remote_services")
            }),
        ));
    }

    let hosts_entries = value
        .get("hosts_entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if !hosts_entries.is_empty() {
        findings.push(finding(
            "hosts-file-entries",
            InvestigationClassification::Context,
            "high",
            "Hosts file contains active entries",
            "Active hosts-file mappings exist and should be reviewed only when unexpected.",
            json!({
                "hosts_path": value.get("hosts_path"),
                "entry_count": hosts_entries.len(),
                "entries": hosts_entries
            }),
        ));
    }
}

fn analyze_network_posture(findings: &mut Vec<InvestigationFinding>, value: &Value) {
    let proxy_server = value
        .get("user_proxy")
        .and_then(|proxy| proxy.get("ProxyServer"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let auto_config = value
        .get("user_proxy")
        .and_then(|proxy| proxy.get("AutoConfigURL"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    if !proxy_server.is_empty() || !auto_config.is_empty() {
        findings.push(finding(
            "proxy-configuration-present",
            InvestigationClassification::NeedsReview,
            "medium",
            "Proxy configuration is present",
            "A proxy or automatic proxy configuration is configured. Confirm it is expected for this device or network.",
            json!({
                "proxy_server": proxy_server,
                "auto_config_url": auto_config,
                "winhttp_proxy": value.get("winhttp_proxy")
            }),
        ));
    }
}

fn analyze_registry_persistence(findings: &mut Vec<InvestigationFinding>, value: &Value) {
    let entries = value
        .get("run_key_entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if !entries.is_empty() {
        findings.push(finding(
            "registry-run-entries",
            InvestigationClassification::Context,
            "high",
            "Registry startup entries were collected",
            "Startup entries are normal Windows configuration until a specific entry has independent evidence of concern.",
            json!({
                "entry_count": entries.len(),
                "entries": entries
            }),
        ));
    }

    let bindings = value
        .get("wmi_filter_bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if !bindings.is_empty() {
        findings.push(finding(
            "wmi-persistence-bindings",
            InvestigationClassification::Context,
            "high",
            "WMI permanent event bindings were collected",
            "WMI event bindings can be legitimate system automation. Review the referenced filter and consumer when they are not recognized.",
            json!({
                "binding_count": bindings.len(),
                "bindings": bindings
            }),
        ));
    }
}

fn analyze_extended_persistence(findings: &mut Vec<InvestigationFinding>, value: &Value) {
    let shell = value
        .get("winlogon")
        .and_then(|winlogon| winlogon.get("Shell"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    if !shell.is_empty() && !shell.eq_ignore_ascii_case("explorer.exe") {
        findings.push(finding(
            "nonstandard-winlogon-shell",
            InvestigationClassification::SuspiciousActivity,
            "high",
            "Winlogon shell differs from explorer.exe",
            "The configured Winlogon shell differs from the standard Windows Explorer shell and requires immediate review.",
            json!({
                "shell": shell,
                "winlogon": value.get("winlogon")
            }),
        ));
    }

    let userinit = value
        .get("winlogon")
        .and_then(|winlogon| winlogon.get("Userinit"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    if !userinit.is_empty() && !userinit.to_ascii_lowercase().contains("userinit.exe") {
        findings.push(finding(
            "nonstandard-winlogon-userinit",
            InvestigationClassification::NeedsReview,
            "high",
            "Winlogon Userinit does not reference userinit.exe",
            "The Userinit value does not contain the standard userinit.exe reference.",
            json!({
                "userinit": userinit,
                "winlogon": value.get("winlogon")
            }),
        ));
    }

    let app_init = value.get("app_init").cloned().unwrap_or(Value::Null);
    let app_init_dlls = app_init
        .get("AppInit_DLLs")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let load_app_init = app_init
        .get("LoadAppInit_DLLs")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    if !app_init_dlls.is_empty() || load_app_init != 0 {
        findings.push(finding(
            "appinit-dll-configuration",
            InvestigationClassification::NeedsReview,
            "high",
            "AppInit DLL configuration is active",
            "AppInit DLL loading is enabled or configured. This is a high-value persistence setting and should be verified.",
            app_init,
        ));
    }

    let ifeo = value
        .get("image_file_execution_options")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if !ifeo.is_empty() {
        findings.push(finding(
            "ifeo-debugger-entries",
            InvestigationClassification::NeedsReview,
            "medium",
            "Image File Execution Options debugger entries exist",
            "IFEO debugger entries can be used for debugging or interception. Review each image name and debugger command.",
            json!({
                "entry_count": ifeo.len(),
                "entries": ifeo
            }),
        ));
    }
}

fn analyze_health_posture(findings: &mut Vec<InvestigationFinding>, value: &Value) {
    let dirty_volumes = value
        .get("dirty_volumes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let dirty = dirty_volumes
        .iter()
        .filter(|volume| volume.get("volume_dirty").and_then(Value::as_bool) == Some(true))
        .cloned()
        .collect::<Vec<_>>();

    if !dirty.is_empty() {
        findings.push(finding(
            "dirty-volumes",
            InvestigationClassification::NeedsReview,
            "high",
            "One or more volumes are marked dirty",
            "Windows reports one or more volumes as dirty. Check the disks and repair the filesystem only after reviewing the result.",
            json!({
                "volumes": dirty
            }),
        ));
    }
}

fn finding(
    id: impl Into<String>,
    classification: InvestigationClassification,
    confidence: &'static str,
    title: impl Into<String>,
    summary: impl Into<String>,
    evidence: Value,
) -> InvestigationFinding {
    InvestigationFinding {
        id: id.into(),
        classification,
        confidence,
        title: title.into(),
        summary: summary.into(),
        evidence,
    }
}

fn summarize(findings: &[InvestigationFinding]) -> InvestigationSummary {
    let mut summary = InvestigationSummary {
        context: 0,
        confirmed_changes: 0,
        needs_review: 0,
        suspicious_activity: 0,
    };

    for finding in findings {
        match finding.classification {
            InvestigationClassification::Context => summary.context += 1,
            InvestigationClassification::ConfirmedChange => summary.confirmed_changes += 1,
            InvestigationClassification::NeedsReview => summary.needs_review += 1,
            InvestigationClassification::SuspiciousActivity => summary.suspicious_activity += 1,
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_success_requires_every_source_to_succeed() {
        let mut sources = InvestigationSources {
            access_surface: json!({ "success": true }),
            network_posture: json!({ "success": true }),
            registry_persistence: json!({ "success": true }),
            extended_persistence: json!({ "success": true }),
            health_posture: json!({ "success": true }),
        };

        assert!(sources_succeeded(&sources));

        sources.health_posture = json!({ "success": false });
        assert!(!sources_succeeded(&sources));
    }

    #[test]
    fn nonstandard_winlogon_shell_requires_review() {
        let sources = InvestigationSources {
            access_surface: json!({ "success": true }),
            network_posture: json!({ "success": true }),
            registry_persistence: json!({ "success": true }),
            extended_persistence: json!({
                "success": true,
                "winlogon": {
                    "Shell": "cmd.exe",
                    "Userinit": "C:\\Windows\\System32\\userinit.exe,"
                }
            }),
            health_posture: json!({ "success": true }),
        };

        let findings = analyze_sources(&sources);

        assert!(findings.iter().any(|finding| {
            finding.id == "nonstandard-winlogon-shell"
                && finding.classification == InvestigationClassification::SuspiciousActivity
        }));
    }

    #[test]
    fn ordinary_startup_entry_is_context_not_malware() {
        let sources = InvestigationSources {
            access_surface: json!({ "success": true }),
            network_posture: json!({ "success": true }),
            registry_persistence: json!({
                "success": true,
                "run_key_entries": [{ "name": "OneDrive" }]
            }),
            extended_persistence: json!({ "success": true }),
            health_posture: json!({ "success": true }),
        };

        let findings = analyze_sources(&sources);

        assert!(findings.iter().any(|finding| {
            finding.id == "registry-run-entries"
                && finding.classification == InvestigationClassification::Context
        }));
    }
}
