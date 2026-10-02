use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub const MAX_SYSTEM_DRIVERS: usize = 4096;

pub fn collect() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxDrivers = {MAX_SYSTEM_DRIVERS}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

$allDrivers = @(
    try {{
        Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
            Select-Object Name, DisplayName, State, StartMode, ServiceType,
                PathName, Description |
            Sort-Object Name
    }}
    catch {{
        $collectionErrors.Add(("system_drivers: {{0}}" -f $_.Exception.Message))
        @()
    }}
)

$drivers = @($allDrivers | Select-Object -First $maxDrivers)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_system_drivers'
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_system_drivers = $maxDrivers
        system_drivers_total = $allDrivers.Count
        system_drivers_truncated = ($allDrivers.Count -gt $drivers.Count)
    }}
    drivers = $drivers
}} | ConvertTo-Json -Depth 6 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "windows_system_drivers",
            "error": error.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_collection_is_bounded_and_truthful() {
        let source = include_str!("drivers.rs");

        assert_eq!(MAX_SYSTEM_DRIVERS, 4096);
        assert!(source.contains("Get-CimInstance Win32_SystemDriver -ErrorAction Stop"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("system_drivers_truncated"));
    }
}
