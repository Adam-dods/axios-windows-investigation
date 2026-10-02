use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub const MAX_RUNNING_DRIVERS: usize = 512;
pub const MAX_CODE_INTEGRITY_EVENTS: usize = 100;

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$maxDrivers = {MAX_RUNNING_DRIVERS}
$maxEvents = {MAX_CODE_INTEGRITY_EVENTS}

function Invoke-AxiosOptional {{
    param([scriptblock]$Action)

    try {{
        & $Action
    }}
    catch {{
        [PSCustomObject]@{{
            available = $false
            error = $_.Exception.Message
        }}
    }}
}}

$bcd = Invoke-AxiosOptional {{
    (& bcdedit.exe /enum '{{current}}' 2>&1 | Out-String)
}}

$bcdText = if ($bcd -is [string]) {{ $bcd }} else {{ '' }}

$bcdSecurity = [PSCustomObject]@{{
    available = ($bcd -is [string])
    test_signing = ($bcdText -match '(?im)^\s*testsigning\s+Yes\s*$')
    no_integrity_checks = ($bcdText -match '(?im)^\s*nointegritychecks\s+Yes\s*$')
    kernel_debugger = ($bcdText -match '(?im)^\s*debug\s+Yes\s*$')
    boot_debugger = ($bcdText -match '(?im)^\s*bootdebug\s+Yes\s*$')
}}

$drivers = Invoke-AxiosOptional {{
    @(
        Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
            Where-Object {{ $_.State -eq 'Running' }} |
            Sort-Object Name |
            Select-Object `
                Name,
                DisplayName,
                State,
                StartMode,
                PathName,
                ServiceType |
            Select-Object -First $maxDrivers
    )
}}

$driverCount = if ($drivers -is [System.Array]) {{
    $drivers.Count
}}
elseif ($null -eq $drivers -or $drivers.available -eq $false) {{
    0
}}
else {{
    1
}}

$ciEvents = Invoke-AxiosOptional {{
    @(
        Get-WinEvent `
            -LogName 'Microsoft-Windows-CodeIntegrity/Operational' `
            -MaxEvents $maxEvents `
            -ErrorAction Stop |
            Select-Object `
                TimeCreated,
                Id,
                LevelDisplayName,
                ProviderName,
                Message
    )
}}

$ciEventCount = if ($ciEvents -is [System.Array]) {{
    $ciEvents.Count
}}
elseif ($null -eq $ciEvents -or $ciEvents.available -eq $false) {{
    0
}}
else {{
    1
}}

[PSCustomObject]@{{
    schema_version = 1
    collector = 'axios_kernel_posture'
    success = $true
    limits = @{{
        max_running_drivers = $maxDrivers
        max_code_integrity_events = $maxEvents
    }}
    bcd_security = $bcdSecurity
    running_driver_count = $driverCount
    running_drivers = $drivers
    code_integrity_event_count = $ciEventCount
    code_integrity_events = $ciEvents
}} | ConvertTo-Json -Depth 10 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "schema_version": 1,
                "collector": "axios_kernel_posture",
                "success": false,
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "schema_version": 1,
            "collector": "axios_kernel_posture",
            "success": false,
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_collection_limits_are_bounded() {
        assert_eq!(MAX_RUNNING_DRIVERS, 512);
        assert_eq!(MAX_CODE_INTEGRITY_EVENTS, 100);
    }
}
