use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub fn collect() -> Value {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'

$status = Get-MpComputerStatus
$preferences = Get-MpPreference
$threats = Get-MpThreatDetection |
    Select-Object InitialDetectionTime, LastThreatStatusChangeTime, ThreatID,
        ThreatStatusID, ActionSuccess, Resources

[PSCustomObject]@{
    service_enabled = $status.AMServiceEnabled
    antivirus_enabled = $status.AntivirusEnabled
    antispyware_enabled = $status.AntispywareEnabled
    behavior_monitor_enabled = $status.BehaviorMonitorEnabled
    real_time_protection_enabled = $status.RealTimeProtectionEnabled
    ioav_protection_enabled = $status.IoavProtectionEnabled
    network_inspection_enabled = $status.NISEnabled
    on_access_protection_enabled = $status.OnAccessProtectionEnabled
    tamper_protection_enabled = $status.IsTamperProtected
    signatures_last_updated = $status.AntivirusSignatureLastUpdated
    signatures_version = $status.AntivirusSignatureVersion
    quick_scan_age_days = $status.QuickScanAge
    full_scan_age_days = $status.FullScanAge
    exclusions = @{
        paths = @($preferences.ExclusionPath)
        processes = @($preferences.ExclusionProcess)
        extensions = @($preferences.ExclusionExtension)
        ip_addresses = @($preferences.ExclusionIpAddress)
    }
    threats = @($threats)
} | ConvertTo-Json -Depth 8 -Compress
"#;

    match powershell(script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "error": error.to_string()
        }),
    }
}
