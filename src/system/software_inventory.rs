use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub const MAX_SOFTWARE_ENTRIES: usize = 2000;

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$maxEntries = {MAX_SOFTWARE_ENTRIES}

$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$collectionErrors = [System.Collections.Generic.List[string]]::new()
$entries = [System.Collections.Generic.List[object]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($path in $paths) {{
    $scope = if ($path.StartsWith('HKCU:')) {{
        'current_user'
    }}
    elseif ($path.Contains('WOW6432Node')) {{
        'local_machine_32bit'
    }}
    else {{
        'local_machine'
    }}

    try {{
        $items = @(Get-ItemProperty -Path $path -ErrorAction Stop)
    }}
    catch {{
        $collectionErrors.Add(("{{0}}: {{1}}" -f $path, $_.Exception.Message))
        $items = @()
    }}

    foreach ($item in $items) {{
        $displayName = [string]$item.DisplayName

        if ([string]::IsNullOrWhiteSpace($displayName)) {{
            continue
        }}

        $displayVersion = [string]$item.DisplayVersion
        $publisher = [string]$item.Publisher
        $identity = "$scope|$displayName|$displayVersion|$publisher"

        if (-not $seen.Add($identity)) {{
            continue
        }}

        $entries.Add([PSCustomObject]@{{
            name = $displayName
            version = $displayVersion
            publisher = $publisher
            install_date = [string]$item.InstallDate
            install_location = [string]$item.InstallLocation
            scope = $scope
            system_component = [bool]$item.SystemComponent
            uninstall_available =
                -not [string]::IsNullOrWhiteSpace([string]$item.UninstallString)
            quiet_uninstall_available =
                -not [string]::IsNullOrWhiteSpace([string]$item.QuietUninstallString)
        }})
    }}
}}

$sorted = @(
    $entries |
        Sort-Object name, version, publisher |
        Select-Object -First $maxEntries
)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_software_inventory'
    entry_count = $sorted.Count
    truncated = $entries.Count -gt $sorted.Count
    limit = $maxEntries
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    entries = $sorted
}} | ConvertTo-Json -Depth 6 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_software_inventory",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_software_inventory",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_inventory_limit_is_bounded() {
        assert_eq!(MAX_SOFTWARE_ENTRIES, 2000);
    }
}
