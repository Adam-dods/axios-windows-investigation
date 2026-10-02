use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'

$operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
    Select-Object Caption, Version, BuildNumber, LastBootUpTime,
        TotalVisibleMemorySize, FreePhysicalMemory

$processors = @(
    Get-CimInstance Win32_Processor -ErrorAction Stop |
        Select-Object -First 16 Name, Manufacturer,
            NumberOfCores, NumberOfLogicalProcessors,
            MaxClockSpeed, CurrentClockSpeed, LoadPercentage
)

$graphicsAdapters = @(
    Get-CimInstance Win32_VideoController -ErrorAction Stop |
        Select-Object -First 16 Name, VideoProcessor,
            AdapterRAM, DriverVersion, DriverDate,
            CurrentHorizontalResolution,
            CurrentVerticalResolution, Status
)

$battery = @(
    Get-CimInstance Win32_Battery -ErrorAction Stop |
        Select-Object Name, BatteryStatus, EstimatedChargeRemaining,
            EstimatedRunTime, DesignCapacity, FullChargeCapacity
)

$physicalDisks = @(
    Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
        Select-Object Model, SerialNumber, Status, Size,
            InterfaceType, MediaType
)

$logicalDisks = @(
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop |
        Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
)

$dirtyVolumes = @(
    Get-CimInstance Win32_Volume -Filter 'DriveType = 3' -ErrorAction Stop |
        ForEach-Object {
            [PSCustomObject]@{
                drive = [string]$_.DriveLetter
                volume_dirty = [bool]$_.DirtyBitSet
            }
        }
)

$allProcesses = @(Get-Process -ErrorAction Stop)
$topMemoryProcesses = @(
    $allProcesses |
        Sort-Object WorkingSet64 -Descending |
        Select-Object -First 10 Id, ProcessName,
            CPU, WorkingSet64, Handles
)

[PSCustomObject]@{
    collector = 'windows_health_posture'
    operating_system = $operatingSystem
    processors = $processors
    graphics_adapters = $graphicsAdapters
    battery = $battery
    physical_disks = $physicalDisks
    logical_disks = $logicalDisks
    dirty_volumes = $dirtyVolumes
    process_summary = [PSCustomObject]@{
        process_count = $allProcesses.Count
        top_memory_processes = $topMemoryProcesses
    }
    limits = [PSCustomObject]@{
        maximum_processors = 16
        maximum_graphics_adapters = 16
        maximum_top_processes = 10
    }
    success = $true
} | ConvertTo-Json -Depth 8 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_health_posture",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_health_posture",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn health_posture_uses_structured_dirty_bit_not_localized_fsutil_text() {
        let source = include_str!("health_posture.rs");

        assert!(source.contains("Get-CimInstance Win32_Volume"));
        assert!(source.contains("DirtyBitSet"));
        assert!(source.contains("$ErrorActionPreference = 'Stop'"));
        assert!(!source.contains(concat!("fsutil", " dirty query")));
        assert!(!source.contains(concat!("Silently", "Continue")));
    }
}
