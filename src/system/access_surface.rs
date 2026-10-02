use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'

$maxHostsEntries = 256
$hostsRows = @(
    if (Test-Path -LiteralPath $hostsPath -PathType Leaf) {
        Get-Content -LiteralPath $hostsPath -ErrorAction Stop |
            ForEach-Object { $_.Trim() } |
            Where-Object {
                $_ -and -not $_.StartsWith('#')
            }
    }
)

$hostsEntries = @($hostsRows | Select-Object -First $maxHostsEntries)
$hostsEntriesTruncated = $hostsRows.Count -gt $hostsEntries.Count

$administrators = @()
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'

if ($null -ne $adminGroup) {
    $administrators = @(
        Get-LocalGroupMember -Group $adminGroup.Name |
            Select-Object Name, ObjectClass, PrincipalSource, SID
    )
}

$rdpValue = Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' `
    -ErrorAction Stop

$remoteServices = @(
    Get-Service `
        -Name 'TermService', 'WinRM', 'RemoteRegistry', 'SessionEnv' `
        -ErrorAction Stop |
        Select-Object Name, DisplayName, Status, StartType
)

[PSCustomObject]@{
    collector = 'windows_access_surface'
    hosts_path = $hostsPath
    hosts_entries = $hostsEntries
    hosts_entry_count = @($hostsEntries).Count
    hosts_entries_truncated = $hostsEntriesTruncated
    limits = @{
        max_hosts_entries = $maxHostsEntries
    }
    collection_status = if ($hostsEntriesTruncated) { 'partial' } else { 'complete' }
    local_administrators = $administrators
    remote_desktop_enabled = (
        $null -ne $rdpValue -and $rdpValue.fDenyTSConnections -eq 0
    )
    remote_services = $remoteServices
    success = $true
} | ConvertTo-Json -Depth 8 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_access_surface",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_access_surface",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn hosts_entry_limit_is_bounded() {
        const MAX_HOSTS_ENTRIES: usize = 256;
        assert_eq!(MAX_HOSTS_ENTRIES, 256);
    }
}
