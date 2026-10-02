use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'

$locations = @(
    [PSCustomObject]@{
        source = 'current_user_run'
        path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    },
    [PSCustomObject]@{
        source = 'current_user_run_once'
        path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    },
    [PSCustomObject]@{
        source = 'local_machine_run'
        path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    },
    [PSCustomObject]@{
        source = 'local_machine_run_once'
        path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    },
    [PSCustomObject]@{
        source = 'local_machine_wow6432_run'
        path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    },
    [PSCustomObject]@{
        source = 'local_machine_wow6432_run_once'
        path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    }
)

$runEntries = foreach ($location in $locations) {
    if (-not (Test-Path -LiteralPath $location.path)) {
        continue
    }

    $properties = Get-ItemProperty -LiteralPath $location.path

    foreach ($property in $properties.PSObject.Properties) {
        if ($property.Name -like 'PS*') {
            continue
        }

        [PSCustomObject]@{
            source = $location.source
            registry_path = $location.path
            name = $property.Name
            command = [string]$property.Value
        }
    }
}

$filters = Get-CimInstance `
    -Namespace 'root\subscription' `
    -ClassName '__EventFilter' |
    Select-Object Name, Query, QueryLanguage, EventNamespace

$consumers = Get-CimInstance `
    -Namespace 'root\subscription' `
    -ClassName '__EventConsumer' |
    Select-Object Name, __CLASS, CommandLineTemplate,
        ExecutablePath, ScriptText, ScriptingEngine

$bindings = @(
    Get-WmiObject `
        -Namespace 'root\subscription' `
        -Class '__FilterToConsumerBinding' |
        ForEach-Object {
            [PSCustomObject]@{
                filter_path = [string]$_.Properties["Filter"].Value
                consumer_path = [string]$_.Properties["Consumer"].Value
            }
        }
)


[PSCustomObject]@{
    success = $true
    collector = 'windows_persistence_registry_wmi'
    run_key_entries = @($runEntries)
    wmi_event_filters = @($filters)
    wmi_event_consumers = @($consumers)
    wmi_filter_bindings = @($bindings)
} | ConvertTo-Json -Depth 8 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_persistence_registry_wmi",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_persistence_registry_wmi",
            "reason": "Windows-only collector"
        })
    }
}

pub fn is_internal_property_name(name: &str) -> bool {
    name.starts_with("PS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_metadata_properties_are_excluded() {
        assert!(is_internal_property_name("PSPath"));
        assert!(is_internal_property_name("PSProvider"));
        assert!(!is_internal_property_name("OneDrive"));
    }
}
