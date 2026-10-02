use anyhow::{bail, Result};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-memory-execution-review")]
struct Options {
    #[arg(long)]
    processes: PathBuf,
    #[arg(long)]
    persistence: PathBuf,
    #[arg(long)]
    network: PathBuf,
    #[arg(long, default_value_t = 256)]
    max_processes: usize,
    #[arg(long, default_value_t = 4096)]
    max_regions: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_processes == 0 || options.max_processes > 1024 {
        bail!("max-processes must be between 1 and 1024");
    }

    if options.max_regions == 0 || options.max_regions > 16384 {
        bail!("max-regions must be between 1 and 16384");
    }

    let processes = read_success(&options.processes, "processes")?;

    let persistence = read_persistence_success(&options.persistence)?;

    let network = read_success(&options.network, "network")?;

    let report = build_report(
        &processes,
        &persistence,
        &network,
        options.max_processes,
        options.max_regions,
    );

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn read_success(path: &PathBuf, label: &str) -> Result<Value> {
    let report = json_file::read_value(path)?;

    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!("{label} report is not successful");
    }

    Ok(report)
}

fn read_persistence_success(path: &PathBuf) -> Result<Value> {
    let report = json_file::read_value(path)?;

    if !persistence_report_succeeded(&report) {
        bail!(
            "persistence report must have successful registry, extended, and coverage components"
        );
    }

    Ok(report)
}

fn persistence_report_succeeded(report: &Value) -> bool {
    ["registry", "extended", "coverage"]
        .iter()
        .all(|component| {
            report
                .pointer(&format!("/{component}/success"))
                .and_then(Value::as_bool)
                == Some(true)
        })
}

fn build_report(
    processes: &Value,
    persistence: &Value,
    network: &Value,
    max_processes: usize,
    max_regions: usize,
) -> Value {
    let records = processes
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut artifacts = Vec::new();
    let mut processes_scanned = 0usize;
    let mut visibility_limited = 0usize;
    let mut scan_truncated_processes = 0usize;
    let mut private_executable_regions = 0usize;
    let mut rwx_regions = 0usize;
    let mut context_only = 0usize;
    let mut high_priority = 0usize;
    let mut medium_priority = 0usize;

    for process in records.into_iter().take(max_processes) {
        let Some(pid) = process.get("pid").and_then(Value::as_u64) else {
            continue;
        };

        let path = process
            .get("executable_path")
            .and_then(Value::as_str)
            .unwrap_or("");

        if path.is_empty() {
            continue;
        }

        if process.get("analysis_context").and_then(Value::as_str) == Some("self") {
            continue;
        }

        processes_scanned += 1;

        let scan = scan_process_memory(pid as u32, max_regions);
        let private_exec = scan
            .get("private_executable_regions")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let rwx = scan.get("rwx_regions").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limited = scan
            .get("visibility_limited")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let scan_truncated = scan
            .get("scan_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        private_executable_regions += private_exec;
        rwx_regions += rwx;

        if limited || scan_truncated {
            visibility_limited += 1;
            if scan_truncated {
                scan_truncated_processes += 1;
            }
            continue;
        }

        if private_exec == 0 && rwx == 0 {
            continue;
        }

        let persistence_match = value_references_path(persistence, path);
        let network_match = value_references_path(network, path);
        let suspicious_process = process.get("classification").and_then(Value::as_str)
            == Some("needs_review")
            || process
                .get("user_writable_location")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || process
                .get("parent_mismatch")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let priority = assess_priority(
            private_exec,
            rwx,
            suspicious_process,
            persistence_match,
            network_match,
        );

        match priority {
            "high" => high_priority += 1,
            "medium" => medium_priority += 1,
            _ => {
                context_only += 1;
                continue;
            }
        }

        artifacts.push(json!({
            "priority": priority,
            "pid": pid,
            "name": process.get("name").cloned().unwrap_or(Value::Null),
            "path": path,
            "identity": process_identity(&process),
            "evidence": {
                "private_executable_regions": private_exec,
                "rwx_regions": rwx,
                "suspicious_process_evidence": suspicious_process,
                "persistence_or_startup": persistence_match,
                "network_activity": network_match,
                "regions_examined": scan.get("regions_examined").cloned().unwrap_or(Value::Null),
                "scan_truncated": scan.get("scan_truncated").cloned().unwrap_or(Value::Null)
            },
            "reason": "memory_execution_signal_requires_cross-layer_evidence"
        }));
    }

    artifacts.sort_by(|left, right| {
        priority_rank(
            right
                .get("priority")
                .and_then(Value::as_str)
                .unwrap_or("context"),
        )
        .cmp(&priority_rank(
            left.get("priority")
                .and_then(Value::as_str)
                .unwrap_or("context"),
        ))
    });

    json!({
        "success": true,
        "collector": "axios_memory_execution_review",
        "read_only": true,
        "memory_contents_read": false,
        "remediation_performed": false,
        "malware_confirmed": false,
        "rootkit_confirmed": false,
        "zero_day_confirmed": false,
        "policy": {
            "rwx_memory_alone": "context_only",
            "private_executable_memory_alone": "context_only",
            "access_denied": "visibility_limited",
            "high_requires": "memory_execution_signal AND suspicious_process AND (persistence_or_startup OR network_activity)"
        },
        "summary": {
            "processes_scanned": processes_scanned,
            "visibility_limited_processes": visibility_limited,
            "scan_truncated_processes": scan_truncated_processes,
            "private_executable_regions": private_executable_regions,
            "rwx_regions": rwx_regions,
            "high_priority_findings": high_priority,
            "medium_priority_findings": medium_priority,
            "context_only_memory_signals": context_only,
            "reported_high_or_medium_findings": artifacts.len()
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
        "normalized_path": path.map(normalize_path),
        "sha256": sha256.map(str::to_ascii_lowercase),
        "identity_quality": quality
    })
}

fn assess_priority(
    private_executable_regions: usize,
    rwx_regions: usize,
    suspicious_process: bool,
    persistence_or_startup: bool,
    network_activity: bool,
) -> &'static str {
    let execution_signal = private_executable_regions > 0 || rwx_regions > 0;
    let runtime_context = persistence_or_startup || network_activity;

    if execution_signal && suspicious_process && runtime_context {
        "high"
    } else if execution_signal && suspicious_process {
        "medium"
    } else {
        "context"
    }
}

fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn value_references_path(value: &Value, path: &str) -> bool {
    let wanted = normalize_path(path);

    match value {
        Value::String(text) => normalize_path(text) == wanted,
        Value::Array(items) => items.iter().any(|item| value_references_path(item, path)),
        Value::Object(items) => items.values().any(|item| value_references_path(item, path)),
        _ => false,
    }
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(windows)]
fn scan_process_memory(pid: u32, max_regions: usize) -> Value {
    use std::ffi::c_void;

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn VirtualQueryEx(
            process: *mut c_void,
            address: *const c_void,
            information: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x20000;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };

    if handle.is_null() {
        return json!({
            "visibility_limited": true,
            "private_executable_regions": 0,
            "rwx_regions": 0,
            "regions_examined": 0,
            "scan_truncated": false
        });
    }

    let mut address = 0usize;
    let mut examined = 0usize;
    let mut private_executable = 0usize;
    let mut rwx = 0usize;

    while examined < max_regions {
        let mut mbi = MemoryBasicInformation {
            base_address: std::ptr::null_mut(),
            allocation_base: std::ptr::null_mut(),
            allocation_protect: 0,
            partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            type_: 0,
        };

        let returned = unsafe {
            VirtualQueryEx(
                handle,
                address as *const c_void,
                &mut mbi,
                std::mem::size_of::<MemoryBasicInformation>(),
            )
        };

        if returned == 0 || mbi.region_size == 0 {
            break;
        }

        examined += 1;

        let executable = matches!(
            mbi.protect & 0xff,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );

        if mbi.state == MEM_COMMIT && mbi.type_ == MEM_PRIVATE && executable {
            private_executable += 1;
        }

        if mbi.state == MEM_COMMIT && (mbi.protect & 0xff) == PAGE_EXECUTE_READWRITE {
            rwx += 1;
        }

        let next = (mbi.base_address as usize).saturating_add(mbi.region_size);
        if next <= address {
            break;
        }

        address = next;
    }

    unsafe {
        CloseHandle(handle);
    }

    json!({
        "visibility_limited": false,
        "private_executable_regions": private_executable,
        "rwx_regions": rwx,
        "regions_examined": examined,
        "scan_truncated": examined >= max_regions
    })
}

#[cfg(not(windows))]
fn scan_process_memory(_pid: u32, _max_regions: usize) -> Value {
    json!({
        "visibility_limited": true,
        "private_executable_regions": 0,
        "rwx_regions": 0,
        "regions_examined": 0,
        "scan_truncated": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_requires_memory_process_and_runtime_evidence() {
        assert_eq!(assess_priority(1, 1, true, true, false), "high");
        assert_eq!(assess_priority(1, 0, true, false, true), "high");
        assert_eq!(assess_priority(1, 1, true, false, false), "medium");
        assert_eq!(assess_priority(1, 1, false, true, true), "context");
        assert_eq!(assess_priority(0, 0, true, true, true), "context");
    }

    #[test]
    fn path_matching_is_case_insensitive() {
        let report = json!({
            "items": [{ "path": r"C:\Users\Test\AppData\Local\tool.exe" }]
        });

        assert!(value_references_path(
            &report,
            r"c:\users\test\appdata\local\tool.exe"
        ));
    }

    #[test]
    fn path_matching_does_not_accept_a_substring() {
        let report = json!({
            "items": [{ "path": r"C:\\Users\\Test\\AppData\\Local\\tool.exe.bak" }]
        });

        assert!(!value_references_path(
            &report,
            r"C:\Users\Test\AppData\Local\tool.exe"
        ));
    }

    #[test]
    fn failed_persistence_component_is_rejected() {
        assert!(persistence_report_succeeded(&serde_json::json!({
            "registry": {"success": true},
            "extended": {"success": true},
            "coverage": {"success": true}
        })));

        assert!(!persistence_report_succeeded(&serde_json::json!({
            "registry": {"success": true},
            "extended": {"success": false},
            "coverage": {"success": true}
        })));

        assert!(!persistence_report_succeeded(&serde_json::json!({
            "registry": {"success": true},
            "extended": {"success": true}
        })));
    }

    #[test]
    fn process_identity_preserves_hash_and_start_time() {
        let identity = process_identity(&json!({
            "pid": 4242,
            "creation_date": "20260915010101.000000+000",
            "executable_path": r"C:\Program Files\Sample\sample.exe",
            "sha256": "AABBCC"
        }));

        assert_eq!(identity["pid"], 4242);
        assert_eq!(identity["start_time"], "20260915010101.000000+000");
        assert_eq!(identity["sha256"], "aabbcc");
        assert_eq!(identity["identity_quality"], "strong");
    }

    #[test]
    fn missing_identity_values_remain_partial() {
        let identity = process_identity(&json!({
            "pid": 4242,
            "executable_path": r"C:\Sample\sample.exe"
        }));

        assert!(identity["start_time"].is_null());
        assert!(identity["sha256"].is_null());
        assert_eq!(identity["identity_quality"], "partial");
    }
}
