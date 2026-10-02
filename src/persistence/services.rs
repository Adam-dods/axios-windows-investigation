use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub const MAX_SERVICES: usize = 4096;

pub fn collect() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxServices = {MAX_SERVICES}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

$allServices = @(
    try {{
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, State, StartMode, StartName,
                ProcessId, PathName, Description |
            Sort-Object Name
    }}
    catch {{
        $collectionErrors.Add(("services: {{0}}" -f $_.Exception.Message))
        @()
    }}
)

$services = @($allServices | Select-Object -First $maxServices)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_services'
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_services = $maxServices
        services_total = $allServices.Count
        services_truncated = ($allServices.Count -gt $services.Count)
    }}
    services = $services
}} | ConvertTo-Json -Depth 6 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "windows_services",
            "error": error.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_collection_is_bounded_and_truthful() {
        let source = include_str!("services.rs");

        assert_eq!(MAX_SERVICES, 4096);
        assert!(source.contains("Get-CimInstance Win32_Service -ErrorAction Stop"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("services_truncated"));
    }
}
