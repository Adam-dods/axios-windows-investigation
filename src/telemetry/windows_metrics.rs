use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'SilentlyContinue'

$network = Get-CimInstance `
    -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface |
    Select-Object Name, BytesReceivedPersec, BytesSentPersec,
        CurrentBandwidth, PacketsReceivedPersec, PacketsSentPersec

$disk = Get-CimInstance `
    -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk |
    Select-Object Name, DiskReadBytesPersec, DiskWriteBytesPersec,
        DiskReadsPersec, DiskWritesPersec, PercentDiskTime

$power = Get-CimInstance `
    -Namespace 'root\CIMV2\power' `
    -ClassName Win32_Battery `
    -ErrorAction SilentlyContinue |
    Select-Object EstimatedChargeRemaining, EstimatedRunTime,
        BatteryStatus

[PSCustomObject]@{
    success = $true
    collection_status = 'complete'
    collection_errors = @()
    collector = 'windows_performance_counters'
    gpu = [PSCustomObject]@{
        collection_status = 'deferred_on_demand'
        reason = 'GPU engine enumeration is not part of the background sampler'
    }
    network_interfaces = @($network)
    physical_disks = @($disk)
    battery = @($power)
} | ConvertTo-Json -Depth 6 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_performance_counters",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_performance_counters",
            "reason": "Windows-only collector"
        })
    }
}

pub fn collect_gpu_engine_summary() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'SilentlyContinue'

$gpu = @(
    Get-CimInstance `
        -Namespace 'root\CIMV2' `
        -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine |
    Where-Object {
        $_.Name -notmatch 'engtype_3D.*pid_0'
    }
)

$top = @(
    $gpu |
    Sort-Object UtilizationPercentage -Descending |
    Select-Object -First 8 Name, UtilizationPercentage
)

$active = @(
    $gpu |
    Where-Object {
        $_.UtilizationPercentage -gt 0
    }
)

$maximum = (
    $gpu |
    Measure-Object -Property UtilizationPercentage -Maximum
).Maximum

[PSCustomObject]@{
    success = $true
    collection_status = 'complete'
    collection_errors = @()
    collector = 'windows_gpu_engine_summary'
    engine_count = @($gpu).Count
    active_engine_count = @($active).Count
    maximum_utilization_percent = $maximum
    top_engines = @($top)
} | ConvertTo-Json -Depth 5 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_gpu_engine_summary",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_gpu_engine_summary",
            "reason": "Windows-only collector"
        })
    }
}

pub fn classify_utilization(percent: f64) -> &'static str {
    match percent {
        value if value.is_nan() || value < 0.0 => "unknown",
        0.0..=69.99 => "normal",
        70.0..=84.99 => "elevated",
        85.0..=94.99 => "high",
        _ => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utilization_is_classified() {
        assert_eq!(classify_utilization(0.0), "normal");
        assert_eq!(classify_utilization(73.5), "elevated");
        assert_eq!(classify_utilization(91.0), "high");
        assert_eq!(classify_utilization(99.0), "critical");
    }

    #[test]
    fn invalid_utilization_is_unknown() {
        assert_eq!(classify_utilization(-1.0), "unknown");
        assert_eq!(classify_utilization(f64::NAN), "unknown");
    }
}
