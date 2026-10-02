use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub const MAX_REGISTRY_STARTUP_ENTRIES: usize = 2048;
pub const MAX_STARTUP_COMMANDS: usize = 2048;

pub fn collect() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxRegistryEntries = {MAX_REGISTRY_STARTUP_ENTRIES}
$maxStartupCommands = {MAX_STARTUP_COMMANDS}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

$registryLocations = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$allRegistryEntries = @(
    foreach ($location in $registryLocations) {{
        try {{
            if (-not (Test-Path -LiteralPath $location -ErrorAction Stop)) {{
                continue
            }}

            $item = Get-ItemProperty -LiteralPath $location -ErrorAction Stop

            foreach ($property in $item.PSObject.Properties) {{
                if ($property.Name -notmatch '^PS') {{
                    [PSCustomObject]@{{
                        source = $location
                        name = $property.Name
                        command = [string]$property.Value
                    }}
                }}
            }}
        }}
        catch {{
            $collectionErrors.Add(("registry_startup:{{0}}: {{1}}" -f $location, $_.Exception.Message))
        }}
    }}
)
$registryEntries = @(
    $allRegistryEntries |
        Select-Object -First $maxRegistryEntries
)

$allStartupCommands = @(
    try {{
        Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
            Select-Object Name, Command, Location, User |
            Sort-Object Location, Name
    }}
    catch {{
        $collectionErrors.Add(("startup_commands: {{0}}" -f $_.Exception.Message))
        @()
    }}
)
$startupCommands = @(
    $allStartupCommands |
        Select-Object -First $maxStartupCommands
)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_startup_entries'
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_registry_startup_entries = $maxRegistryEntries
        registry_startup_entries_total = $allRegistryEntries.Count
        registry_startup_entries_truncated = ($allRegistryEntries.Count -gt $registryEntries.Count)
        max_startup_commands = $maxStartupCommands
        startup_commands_total = $allStartupCommands.Count
        startup_commands_truncated = ($allStartupCommands.Count -gt $startupCommands.Count)
    }}
    registry = $registryEntries
    startup_commands = $startupCommands
}} | ConvertTo-Json -Depth 8 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "windows_startup_entries",
            "error": error.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_collection_is_bounded_and_truthful() {
        let source = include_str!("startup.rs");

        assert_eq!(MAX_REGISTRY_STARTUP_ENTRIES, 2048);
        assert_eq!(MAX_STARTUP_COMMANDS, 2048);
        assert!(source.contains("Get-CimInstance Win32_StartupCommand -ErrorAction Stop"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("registry_startup_entries_truncated"));
        assert!(source.contains("startup_commands_truncated"));
    }
}
