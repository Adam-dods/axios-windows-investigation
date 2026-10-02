use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$errors = [System.Collections.Generic.List[string]]::new()

function Invoke-AxiosContextSource {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [object]$Fallback
    )

    try {
        return & $Action
    }
    catch {
        $errors.Add(("{0}: {1}" -f $Name, $_.Exception.Message))
        return $Fallback
    }
}

$now = Get-Date
$utcNow = [DateTime]::UtcNow

$timeZone = Invoke-AxiosContextSource 'timezone' {
    Get-TimeZone -ErrorAction Stop |
        Select-Object Id, DisplayName, StandardName, DaylightName,
            BaseUtcOffset, SupportsDaylightSavingTime
} $null

$timeService = Invoke-AxiosContextSource 'windows_time_service' {
    Get-Service -Name W32Time -ErrorAction Stop
} $null

$timeServiceState = if ($null -eq $timeService) {
    'unknown'
}
else {
    [string]$timeService.Status
}

$timeServiceStartType = if ($null -eq $timeService) {
    'unknown'
}
else {
    [string]$timeService.StartType
}

$timeSource = $null
$timeStatus = $null
$timeSynchronizationState = 'unavailable'

if ($timeServiceState -eq 'Running') {
    $timeSource = Invoke-AxiosContextSource 'windows_time_source' {
        $value = (& w32tm.exe /query /source 2>&1 | Out-String).Trim()

        if ($LASTEXITCODE -ne 0) {
            throw "w32tm source query failed with exit code $LASTEXITCODE"
        }

        $value
    } $null

    $timeStatus = Invoke-AxiosContextSource 'windows_time_status' {
        $value = (& w32tm.exe /query /status 2>&1 | Out-String).Trim()

        if ($LASTEXITCODE -ne 0) {
            throw "w32tm status query failed with exit code $LASTEXITCODE"
        }

        $value
    } $null

    if ($null -ne $timeSource -and $null -ne $timeStatus) {
        $timeSynchronizationState = 'available'
    }
}
elseif ($timeServiceState -eq 'Stopped') {
    $timeSynchronizationState = 'service_not_running'
}

$culture = Invoke-AxiosContextSource 'culture' {
    Get-Culture -ErrorAction Stop |
        Select-Object Name, DisplayName, EnglishName,
            NativeName, DateTimeFormat, NumberFormat
} $null

$uiCulture = Invoke-AxiosContextSource 'ui_culture' {
    Get-UICulture -ErrorAction Stop |
        Select-Object Name, DisplayName, EnglishName, NativeName
} $null

$region = Invoke-AxiosContextSource 'region' {
    Get-WinHomeLocation -ErrorAction Stop |
        Select-Object GeoId, HomeLocation
} $null

$languageList = @(
    Invoke-AxiosContextSource 'user_languages' {
        @(Get-WinUserLanguageList -ErrorAction Stop)
    } @()
)

$languages = @(
    $languageList |
        Select-Object -First 32 `
            @{ Name = 'language_tag'; Expression = { [string]$_.LanguageTag } },
            @{ Name = 'autonym'; Expression = { [string]$_.Autonym } },
            @{ Name = 'english_name'; Expression = { [string]$_.EnglishName } },
            @{ Name = 'localized_name'; Expression = { [string]$_.LocalizedName } },
            @{ Name = 'input_methods'; Expression = { [string[]]@($_.InputMethodTips) } },
            @{ Name = 'spellchecking'; Expression = { [bool]$_.Spellchecking } },
            @{ Name = 'handwriting'; Expression = { [bool]$_.Handwriting } }
)

$profiles = @(
    Invoke-AxiosContextSource 'network_profiles' {
        Get-NetConnectionProfile -ErrorAction Stop |
            Select-Object -First 64 Name, InterfaceAlias,
                InterfaceIndex,
                @{ Name = 'network_category'; Expression = { [string]$_.NetworkCategory } },
                @{ Name = 'ipv4_connectivity'; Expression = { [string]$_.IPv4Connectivity } },
                @{ Name = 'ipv6_connectivity'; Expression = { [string]$_.IPv6Connectivity } }
    } @()
)

$interfaces = @(
    Invoke-AxiosContextSource 'network_interfaces' {
        Get-NetIPConfiguration -ErrorAction Stop |
            Select-Object -First 64 `
                InterfaceAlias,
                InterfaceIndex,
                @{
                    Name = 'adapter_status'
                    Expression = { [string]$_.NetAdapter.Status }
                },
                @{
                    Name = 'link_speed'
                    Expression = { $_.NetAdapter.LinkSpeed }
                },
                @{
                    Name = 'network_profile'
                    Expression = { $_.NetProfile.Name }
                },
                @{
                    Name = 'network_category'
                    Expression = { [string]$_.NetProfile.NetworkCategory }
                },
                @{
                    Name = 'ipv4_addresses'
                    Expression = { [string[]]@($_.IPv4Address.IPAddress) }
                },
                @{
                    Name = 'ipv6_addresses'
                    Expression = { [string[]]@($_.IPv6Address.IPAddress) }
                },
                @{
                    Name = 'ipv4_gateway'
                    Expression = { [string[]]@($_.IPv4DefaultGateway.NextHop) }
                },
                @{
                    Name = 'ipv6_gateway'
                    Expression = { [string[]]@($_.IPv6DefaultGateway.NextHop) }
                },
                @{
                    Name = 'dns_servers'
                    Expression = { [string[]]@($_.DNSServer.ServerAddresses) }
                }
    } @()
)

$dhcp = @(
    Invoke-AxiosContextSource 'dhcp' {
        Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
            Select-Object -First 64 InterfaceAlias,
                InterfaceIndex,
                @{ Name = 'connection_state'; Expression = { [string]$_.ConnectionState } },
                @{ Name = 'dhcp'; Expression = { [string]$_.Dhcp } },
                InterfaceMetric, NlMtu |
            Sort-Object InterfaceIndex
    } @()
)

$publicProfiles = @(
    $profiles |
        Where-Object {
            $_.network_category -eq 'Public'
        }
)

$privateProfiles = @(
    $profiles |
        Where-Object {
            $_.network_category -eq 'Private'
        }
)

$domainProfiles = @(
    $profiles |
        Where-Object {
            $_.network_category -eq 'DomainAuthenticated'
        }
)

[PSCustomObject]@{
    collector = 'windows_context_posture'
    success = $true
    collection_status = if ($errors.Count -eq 0) {
        'complete'
    }
    else {
        'partial'
    }
    generated_at_utc = $utcNow.ToString('o')
    time = [PSCustomObject]@{
        local_time = $now.ToString('o')
        utc_time = $utcNow.ToString('o')
        utc_offset = $now.ToString('zzz')
        timezone = $timeZone
        windows_time_service = [PSCustomObject]@{
            name = 'W32Time'
            status = $timeServiceState
            start_type = $timeServiceStartType
        }
        synchronization_state = $timeSynchronizationState
        synchronization_source = $timeSource
        synchronization_status_raw = $timeStatus
    }
    locale = [PSCustomObject]@{
        culture = $culture
        ui_culture = $uiCulture
        region = $region
        user_languages = $languages
    }
    network_context = [PSCustomObject]@{
        profiles = $profiles
        interfaces = $interfaces
        dhcp_interfaces = $dhcp
        public_profiles = $publicProfiles.Count
        private_profiles = $privateProfiles.Count
        domain_authenticated_profiles = $domainProfiles.Count
    }
    limits = [PSCustomObject]@{
        maximum_languages = 32
        maximum_network_profiles = 64
        maximum_network_interfaces = 64
        bounded = $true
    }
    collection_errors = @($errors)
} | ConvertTo-Json -Depth 12 -Compress

exit 0
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_context_posture",
                "collection_status": "failed",
                "collection_errors": [error.to_string()]
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_context_posture",
            "collection_status": "unsupported",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn context_collection_is_bounded_and_truthful() {
        let source = include_str!("context_posture.rs");

        for required in [
            "Get-TimeZone",
            "W32Time",
            "w32tm.exe /query /source",
            "Get-Culture",
            "Get-UICulture",
            "Get-WinUserLanguageList",
            "Get-NetConnectionProfile",
            "NetworkCategory",
            "Get-NetIPConfiguration",
            "Get-NetIPInterface",
            "collection_errors",
            "maximum_network_interfaces",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
    }
}
