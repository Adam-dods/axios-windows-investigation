#[cfg(windows)]
use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub const MAX_HOTFIXES: usize = 100;
pub const MAX_PENDING_UPDATES: usize = 50;

pub fn collect() -> Value {
    #[cfg(windows)]
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxHotfixes = {MAX_HOTFIXES}
$maxPendingUpdates = {MAX_PENDING_UPDATES}
$axiosCollectionErrors = New-Object System.Collections.Generic.List[string]

function Invoke-AxiosOptional {{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,
        [Parameter(Mandatory = $true)]
        [object]$Fallback
    )

    try {{
        & $Action
    }}
    catch {{
        $axiosCollectionErrors.Add("$Name collection failed: $($_.Exception.Message)")
        $Fallback
    }}
}}

$rebootReasons = New-Object System.Collections.Generic.List[string]

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {{
    $rebootReasons.Add('component_based_servicing')
}}

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {{
    $rebootReasons.Add('windows_update')
}}

$pendingFileRenameOperations = Invoke-AxiosOptional 'pending file rename operations' {{
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $property = $item.PSObject.Properties['PendingFileRenameOperations']

    $null -ne $property -and $null -ne $property.Value
}} $false

if ($pendingFileRenameOperations) {{
    $rebootReasons.Add('pending_file_rename_operations')
}}

$operatingSystem = Invoke-AxiosOptional 'operating system' {{
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $currentVersion = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        -ErrorAction Stop

    [PSCustomObject]@{{
        caption = [string]$os.Caption
        version = [string]$os.Version
        build_number = [string]$os.BuildNumber
        display_version = [string]$currentVersion.DisplayVersion
        release_id = [string]$currentVersion.ReleaseId
        ubr = [int]$currentVersion.UBR
        last_boot_up_time = [string]$os.LastBootUpTime
    }}
}} ([PSCustomObject]@{{ available = $false }})

$allHotfixes = @(
    Invoke-AxiosOptional 'hotfixes' {{
        Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop |
            Sort-Object InstalledOn -Descending |
            Select-Object HotFixID, Description, InstalledBy, InstalledOn
    }} @()
)
$hotfixes = @($allHotfixes | Select-Object -First $maxHotfixes)

$updateService = Invoke-AxiosOptional 'Windows Update service' {{
    Get-Service -Name wuauserv -ErrorAction Stop |
        Select-Object Name, Status, StartType
}} ([PSCustomObject]@{{ available = $false }})

$allPendingUpdates = @(
    Invoke-AxiosOptional 'Windows Update Agent' {{
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search(
        "IsInstalled=0 and IsHidden=0 and Type='Software'"
    )

    $updateEntries = @(
        foreach ($update in $result.Updates) {{
            [PSCustomObject]@{{
                title = [string]$update.Title
                kb_articles = @(
                    $update.KBArticleIDs |
                        ForEach-Object {{ [string]$_ }}
                )
                severity = [string]$update.MsrcSeverity
                reboot_required = [bool]$update.RebootRequired
                downloaded = [bool]$update.IsDownloaded
                mandatory = [bool]$update.IsMandatory
            }}
        }}
    )

    $updateEntries
}} @()
)
$pendingUpdates = @($allPendingUpdates | Select-Object -First $maxPendingUpdates)

$defender = Invoke-AxiosOptional 'Microsoft Defender' {{
    $status = Get-MpComputerStatus -ErrorAction Stop

    [PSCustomObject]@{{
        available = $true
        antivirus_enabled = [bool]$status.AntivirusEnabled
        real_time_protection_enabled = [bool]$status.RealTimeProtectionEnabled
        tamper_protected = [bool]$status.IsTamperProtected
        antivirus_signature_version = [string]$status.AntivirusSignatureVersion
        antivirus_signature_last_updated = [string]$status.AntivirusSignatureLastUpdated
        antivirus_signature_age_days = [int]$status.AntivirusSignatureAge
        engine_version = [string]$status.AMEngineVersion
        platform_version = [string]$status.AMProductVersion
    }}
}} ([PSCustomObject]@{{ available = $false }})

[PSCustomObject]@{{
    schema_version = 2
    collector = 'axios_update_exposure'
    success = $true
    collection_status = if ($axiosCollectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($axiosCollectionErrors)
    limits = @{{
        max_hotfixes = $maxHotfixes
        hotfixes_total = $allHotfixes.Count
        hotfixes_truncated = ($allHotfixes.Count -gt $hotfixes.Count)
        max_pending_updates = $maxPendingUpdates
        pending_updates_total = $allPendingUpdates.Count
        pending_updates_truncated = ($allPendingUpdates.Count -gt $pendingUpdates.Count)
    }}
    operating_system = $operatingSystem
    reboot = [PSCustomObject]@{{
        required = ($rebootReasons.Count -gt 0)
        reasons = @($rebootReasons)
    }}
    windows_update_service = $updateService
    installed_hotfixes = $hotfixes
    pending_software_updates = $pendingUpdates
    pending_software_update_count = @($pendingUpdates).Count
    defender = $defender
}} | ConvertTo-Json -Depth 10 -Compress
"#
    );

    #[cfg(windows)]
    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "axios_update_exposure",
            "error": error.to_string()
        }),
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "axios_update_exposure",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_collection_limits_are_bounded() {
        assert_eq!(MAX_HOTFIXES, 100);
        assert_eq!(MAX_PENDING_UPDATES, 50);
    }

    #[test]
    fn update_collection_reports_truthful_limits_and_no_silent_registry_read() {
        let source = include_str!("updates.rs");
        let silent_read = [
            "PendingFileRenameOperations",
            " `\n        -ErrorAction ",
            "SilentlyContinue",
        ]
        .concat();

        assert!(source.contains("Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop"));
        assert!(source.contains("hotfixes_truncated"));
        assert!(source.contains("pending_updates_truncated"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(!source.contains(&silent_read));
    }
}
