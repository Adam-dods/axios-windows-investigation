use serde_json::{json, Value};
use sysinfo::System;

pub fn collect(system: &System) -> Value {
    let cpu = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    json!({
        "operating_system": {
            "name": System::name(),
            "version": System::long_os_version(),
            "kernel": System::kernel_version(),
            "hostname": System::host_name(),
            "uptime_seconds": System::uptime()
        },
        "hardware": {
            "cpu": cpu,
            "logical_cpu_count": system.cpus().len(),
            "total_memory_bytes": system.total_memory(),
            "used_memory_bytes": system.used_memory(),
            "available_memory_bytes": system.available_memory(),
            "total_swap_bytes": system.total_swap(),
            "used_swap_bytes": system.used_swap()
        }
    })
}
