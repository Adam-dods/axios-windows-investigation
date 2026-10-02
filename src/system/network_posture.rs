use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$maxDnsInterfaces = 128
$maxFirewallProfiles = 32

function Invoke-AxiosNetworkSource {
    param(
        [string]$Source,
        [scriptblock]$Action,
        [object]$Fallback
    )

    try {
        return & $Action
    }
    catch {
        $collectionErrors.Add(("{0}: {1}" -f $Source, $_.Exception.Message))
        return $Fallback
    }
}

$userProxy = Invoke-AxiosNetworkSource 'user_proxy' {
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
        return $null
    }

    Get-ItemProperty -LiteralPath $path -ErrorAction Stop |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect
} $null

$winHttpProxy = Invoke-AxiosNetworkSource 'winhttp_proxy' {
    $output = (& netsh.exe winhttp show proxy 2>&1 | Out-String)

    if ($LASTEXITCODE -ne 0) {
        throw "netsh.exe winhttp show proxy failed with exit code ${LASTEXITCODE}: $output"
    }

    $output.Trim()
} $null

$allDnsServers = @(
    Invoke-AxiosNetworkSource 'dns_servers' {
        if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
            Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object {
                    $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0
                } |
                Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses |
                Sort-Object InterfaceIndex
        }
        else {
            $configurations = if (
                Get-Command Get-CimInstance -ErrorAction SilentlyContinue
            ) {
                Get-CimInstance Win32_NetworkAdapterConfiguration `
                    -Filter "IPEnabled=True" `
                    -ErrorAction Stop
            }
            elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
                Get-WmiObject Win32_NetworkAdapterConfiguration `
                    -Filter "IPEnabled=True" `
                    -ErrorAction Stop
            }
            else {
                throw "Network adapter management instrumentation is unavailable."
            }

            $configurations |
                Where-Object {
                    $_.DNSServerSearchOrder -and
                    @($_.DNSServerSearchOrder).Count -gt 0
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        InterfaceAlias = [string]$_.Description
                        InterfaceIndex = [int]$_.InterfaceIndex
                        ServerAddresses = @($_.DNSServerSearchOrder)
                        Source = "Win32_NetworkAdapterConfiguration"
                    }
                } |
                Sort-Object InterfaceIndex
        }
    } @()
)
$dnsServers = @($allDnsServers | Select-Object -First $maxDnsInterfaces)

$allFirewallProfiles = @(
    Invoke-AxiosNetworkSource 'firewall_profiles' {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name,
                    @{ Name = 'Enabled'; Expression = { [bool]$_.Enabled } },
                    @{ Name = 'DefaultInboundAction'; Expression = { [string]$_.DefaultInboundAction } },
                    @{ Name = 'DefaultOutboundAction'; Expression = { [string]$_.DefaultOutboundAction } } |
                Sort-Object Name
        }
        else {
            $legacyFirewall = New-Object -ComObject HNetCfg.FwPolicy2

            foreach ($profile in @(
                [PSCustomObject]@{ Name = "Domain"; Id = 1 },
                [PSCustomObject]@{ Name = "Private"; Id = 2 },
                [PSCustomObject]@{ Name = "Public"; Id = 4 }
            )) {
                [PSCustomObject]@{
                    Name = $profile.Name
                    Enabled = [bool]$legacyFirewall.FirewallEnabled(
                        [int]$profile.Id
                    )
                    DefaultInboundAction = $null
                    DefaultOutboundAction = $null
                    Source = "HNetCfg.FwPolicy2"
                }
            }
        }
    } @()
)
$firewallProfiles = @(
    $allFirewallProfiles |
        Select-Object -First $maxFirewallProfiles
)

[PSCustomObject]@{
    collector = 'windows_network_posture'
    success = $true
    collection_status = if ($collectionErrors.Count -eq 0) { 'complete' } else { 'partial' }
    collection_errors = @($collectionErrors)
    limits = @{
        max_dns_interfaces = $maxDnsInterfaces
        dns_interfaces_total = $allDnsServers.Count
        dns_interfaces_truncated = ($allDnsServers.Count -gt $dnsServers.Count)
        max_firewall_profiles = $maxFirewallProfiles
        firewall_profiles_total = $allFirewallProfiles.Count
        firewall_profiles_truncated = ($allFirewallProfiles.Count -gt $firewallProfiles.Count)
    }
    user_proxy = $userProxy
    winhttp_proxy = $winHttpProxy
    dns_servers = $dnsServers
    firewall_profiles = $firewallProfiles
} | ConvertTo-Json -Depth 8 -Compress
exit 0
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_network_posture",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_network_posture",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn network_posture_visibility_and_limits_are_explicit() {
        let source = include_str!("network_posture.rs");

        assert!(source.contains("Invoke-AxiosNetworkSource"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("dns_interfaces_truncated"));
        assert!(source.contains("firewall_profiles_truncated"));
        assert!(source.contains("exit code ${LASTEXITCODE}"));
    }
}
