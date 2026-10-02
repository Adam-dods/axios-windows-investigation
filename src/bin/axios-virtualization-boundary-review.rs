use anyhow::{bail, Result};
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-virtualization-boundary-review")]
struct Options {
    #[arg(long, default_value_t = 64)]
    max_vms: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_vms == 0 || options.max_vms > 256 {
        bail!("max-vms must be between 1 and 256");
    }

    let snapshot = collect_snapshot(options.max_vms)?;
    let report = build_report(&snapshot);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_snapshot(max_vms: usize) -> Result<Value> {
    let script = format!(
        r#"
$ErrorActionPreference = "Stop"

$roots = @(
    (Join-Path $env:USERPROFILE "VirtualBox VMs"),
    (Join-Path $env:PUBLIC "Documents\VirtualBox VMs")
) | Where-Object {{ Test-Path -LiteralPath $_ }}

$rootCollectionErrors = @()
$configurations = @(
    foreach ($root in $roots) {{
        try {{
            Get-ChildItem -LiteralPath $root -Filter "*.vbox" -File -Recurse -ErrorAction Stop
        }}
        catch {{
            $rootCollectionErrors += [PSCustomObject]@{{
                path = $root
                collection_error = $_.Exception.Message
            }}
        }}
    }}
) | Sort-Object FullName -Unique | Select-Object -First {max_vms}

$vms = foreach ($configuration in $configurations) {{
    try {{
        [xml]$document = [IO.File]::ReadAllText($configuration.FullName)

        $sharedFolders = @(
            $document.SelectNodes("//*[local-name()='SharedFolder']") |
                ForEach-Object {{
                    [PSCustomObject]@{{
                        name = $_.GetAttribute("name")
                        host_path = $_.GetAttribute("hostPath")
                        writable = $_.GetAttribute("writable")
                    }}
                }}
        )

        $clipboardNode = $document.SelectSingleNode("//*[local-name()='Clipboard']")
        $dragNode = $document.SelectSingleNode("//*[local-name()='DragAndDrop']")

        $hostOnlyAdapters = @(
            $document.SelectNodes("//*[local-name()='HostOnlyInterface']") |
                ForEach-Object {{ $_.GetAttribute("name") }}
        )

        [PSCustomObject]@{{
            available = $true
            name = [IO.Path]::GetFileNameWithoutExtension($configuration.Name)
            path = $configuration.FullName
            shared_folders = $sharedFolders
            clipboard_mode = if ($null -eq $clipboardNode) {{ $null }} else {{ $clipboardNode.GetAttribute("mode") }}
            drag_and_drop_mode = if ($null -eq $dragNode) {{ $null }} else {{ $dragNode.GetAttribute("mode") }}
            host_only_adapters = $hostOnlyAdapters
        }}
    }}
    catch {{
        [PSCustomObject]@{{
            available = $false
            path = $configuration.FullName
            collection_error = $_.Exception.Message
        }}
    }}
}}

[PSCustomObject]@{{
    success = $true
    vm_configurations = @($vms)
    root_collection_errors = @($rootCollectionErrors)
    collection_limited = (
        $configurations.Count -ge {max_vms} -or
        $rootCollectionErrors.Count -gt 0
    )
}} | ConvertTo-Json -Depth 10 -Compress
"#
    );

    let output = powershell(&script)?;
    if !output.success {
        bail!(
            "virtualization boundary collector failed: {}",
            output.stderr
        );
    }

    Ok(parse_json_output(output))
}

#[cfg(not(windows))]
fn collect_snapshot(_max_vms: usize) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collection_status": "windows_only"
    }))
}

fn is_isolation_sensitive_vm(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("whonix") || name.contains("gateway") || name.contains("workstation")
}

fn is_bidirectional(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("Bidirectional")
}

fn build_report(snapshot: &Value) -> Value {
    let mut findings = Vec::new();

    for root_error in snapshot
        .get("root_collection_errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        findings.push(json!({
            "priority": "context",
            "classification": "vm_root_visibility_limited",
            "path": root_error.get("path").cloned().unwrap_or(Value::Null),
            "reason": "VirtualBox configuration root could not be enumerated",
            "collection_error": root_error.get("collection_error").cloned().unwrap_or(Value::Null)
        }));
    }

    for vm in snapshot
        .get("vm_configurations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if vm.get("available").and_then(Value::as_bool) != Some(true) {
            findings.push(json!({
                "priority": "context",
                "classification": "vm_configuration_visibility_limited",
                "path": vm.get("path").cloned().unwrap_or(Value::Null),
                "reason": "VirtualBox configuration could not be parsed"
            }));
            continue;
        }

        let name = vm.get("name").and_then(Value::as_str).unwrap_or("");
        let sensitive = is_isolation_sensitive_vm(name);

        let shared_folder_count = vm
            .get("shared_folders")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);

        if shared_folder_count > 0 {
            findings.push(json!({
                "priority": if sensitive { "high" } else { "medium" },
                "id": format!("vm_shared_folders:{name}"),
                "classification": "vm_host_guest_data_sharing",
                "vm": name,
                "shared_folder_count": shared_folder_count,
                "reason": if sensitive {
                    "isolation-sensitive VM has host/guest shared folders configured"
                } else {
                    "VirtualBox VM has host/guest shared folders configured"
                }
            }));
        }

        let clipboard = vm
            .get("clipboard_mode")
            .and_then(Value::as_str)
            .unwrap_or("");

        if is_bidirectional(clipboard) {
            findings.push(json!({
                "priority": if sensitive { "high" } else { "medium" },
                "id": format!("vm_bidirectional_clipboard:{name}"),
                "classification": "vm_host_guest_data_sharing",
                "vm": name,
                "reason": "VirtualBox bidirectional clipboard is enabled"
            }));
        }

        let drag_and_drop = vm
            .get("drag_and_drop_mode")
            .and_then(Value::as_str)
            .unwrap_or("");

        if is_bidirectional(drag_and_drop) {
            findings.push(json!({
                "priority": if sensitive { "high" } else { "medium" },
                "id": format!("vm_bidirectional_drag_and_drop:{name}"),
                "classification": "vm_host_guest_data_sharing",
                "vm": name,
                "reason": "VirtualBox bidirectional drag-and-drop is enabled"
            }));
        }

        let host_only_count = vm
            .get("host_only_adapters")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);

        if host_only_count > 0 {
            findings.push(json!({
                "priority": "context",
                "id": format!("vm_host_only_network:{name}"),
                "classification": "virtualization_network_context",
                "vm": name,
                "host_only_adapter_count": host_only_count,
                "reason": "host-only adapter is configured; this is common for lab and gateway VMs"
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
        "collector": "axios_virtualization_boundary_review",
        "read_only": true,
        "database_used": false,
        "vm_escape_confirmed": false,
        "policy": {
            "shared_folders": "host_guest_boundary_exposure_not_vm_escape_proof",
            "bidirectional_clipboard": "host_guest_boundary_exposure_not_vm_escape_proof",
            "host_only_adapter": "normal_virtualization_context"
        },
        "summary": {
            "vms_examined": snapshot.get("vm_configurations").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "high_priority_findings": high,
            "medium_priority_findings": medium,
            "context_findings": context,
            "collection_limited": snapshot.get("collection_limited").and_then(Value::as_bool).unwrap_or(false)
        },
        "findings": findings,
        "snapshot": snapshot
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whonix_shared_folder_is_high_priority() {
        let report = build_report(&json!({
            "vm_configurations": [{
                "available": true,
                "name": "Whonix-Workstation",
                "shared_folders": [{"name": "shared"}]
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "high");
    }

    #[test]
    fn host_only_network_is_context() {
        let report = build_report(&json!({
            "vm_configurations": [{
                "available": true,
                "name": "Lab",
                "host_only_adapters": ["VirtualBox Host-Only Ethernet Adapter"]
            }]
        }));

        assert_eq!(report["findings"][0]["priority"], "context");
    }

    #[test]
    fn inaccessible_vm_root_is_visibility_limited() {
        let report = build_report(&serde_json::json!({
            "collection_limited": true,
            "root_collection_errors": [{
                "path": "C:\\Users\\Test\\VirtualBox VMs",
                "collection_error": "access denied"
            }],
            "vm_configurations": []
        }));

        assert_eq!(report["summary"]["collection_limited"], true);
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["classification"] == "vm_root_visibility_limited" }));
    }

    #[test]
    fn vm_root_enumeration_does_not_suppress_errors() {
        let source = include_str!("axios-virtualization-boundary-review.rs");
        let suppressed = concat!(
            "Get-ChildItem -LiteralPath $root -Filter \"*.vbox\" -File -Recurse -ErrorAction ",
            "SilentlyContinue"
        );

        assert!(!source.contains(suppressed));
        assert!(source.contains(
            "Get-ChildItem -LiteralPath $root -Filter \"*.vbox\" -File -Recurse -ErrorAction Stop"
        ));
    }
}
