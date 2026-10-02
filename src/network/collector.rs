use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

const MAX_ENDPOINTS_PER_PROTOCOL: usize = 1024;

pub fn collect() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxEndpoints = {MAX_ENDPOINTS_PER_PROTOCOL}
$errors = [System.Collections.Generic.List[string]]::new()
$processes = @{{}}

try {{
    Get-Process -ErrorAction Stop | ForEach-Object {{
        $path = $null

        try {{
            $path = $_.Path
        }}
        catch {{
        }}

        $processes[[int]$_.Id] = [PSCustomObject]@{{
            process_id = [int]$_.Id
            process_name = $_.ProcessName
            executable = $path
        }}
    }}
}}
catch {{
    $errors.Add("process inventory failed: $($_.Exception.Message)")
}}

function Get-ProcessContext {{
    param([uint32]$ProcessId)

    $context = $processes[[int]$ProcessId]

    if ($null -eq $context) {{
        return [PSCustomObject]@{{
            process_id = [int]$ProcessId
            process_name = $null
            executable = $null
        }}
    }}

    return $context
}}

function Get-AddressScope {{
    param([string]$Address)

    if ($Address -in @('127.0.0.1', '::1')) {{
        return 'loopback'
    }}

    if ($Address -in @('0.0.0.0', '::', '*')) {{
        return 'wildcard'
    }}

    if ([string]::IsNullOrWhiteSpace($Address)) {{
        return 'unknown'
    }}

    return 'network'
}}

$tcpRows = @()
$udpRows = @()
$adapters = @()

try {{
    $tcpRows = @(
        Get-NetTCPConnection -ErrorAction Stop |
            ForEach-Object {{
                $localAddress = [string]$_.LocalAddress
                $remoteAddress = [string]$_.RemoteAddress
                $state = [string]$_.State
                $isListener = $state -eq 'Listen'

                [PSCustomObject]@{{
                    protocol = 'tcp'
                    observation = if ($isListener) {{
                        'local_listener'
                    }}
                    elseif ($remoteAddress -in @('0.0.0.0', '::', '*', '')) {{
                        'local_endpoint'
                    }}
                    else {{
                        'network_connection'
                    }}
                    local_address = $localAddress
                    local_port = [int]$_.LocalPort
                    local_scope = Get-AddressScope $localAddress
                    remote_address = $remoteAddress
                    remote_port = [int]$_.RemotePort
                    remote_scope = Get-AddressScope $remoteAddress
                    state = $state
                    process = Get-ProcessContext ([uint32]$_.OwningProcess)
                }}
            }}
    )
}}
catch {{
    $errors.Add("TCP collection failed: $($_.Exception.Message)")
}}

try {{
    $udpRows = @(
        Get-NetUDPEndpoint -ErrorAction Stop |
            ForEach-Object {{
                $localAddress = [string]$_.LocalAddress

                [PSCustomObject]@{{
                    protocol = 'udp'
                    observation = 'local_datagram_endpoint'
                    local_address = $localAddress
                    local_port = [int]$_.LocalPort
                    local_scope = Get-AddressScope $localAddress
                    remote_address = $null
                    remote_port = $null
                    remote_scope = 'not_applicable'
                    state = $null
                    process = Get-ProcessContext ([uint32]$_.OwningProcess)
                }}
            }}
    )
}}
catch {{
    $errors.Add("UDP collection failed: $($_.Exception.Message)")
}}

try {{
    $adapters = @(
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {{
            Get-NetAdapter -ErrorAction Stop |
                Select-Object Name, InterfaceDescription, Status,
                    MacAddress, LinkSpeed, MediaType
        }}
        else {{
            $legacyAdapters = if (
                Get-Command Get-CimInstance -ErrorAction SilentlyContinue
            ) {{
                Get-CimInstance Win32_NetworkAdapter `
                    -Filter "PhysicalAdapter=True" `
                    -ErrorAction Stop
            }}
            elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {{
                Get-WmiObject Win32_NetworkAdapter `
                    -Filter "PhysicalAdapter=True" `
                    -ErrorAction Stop
            }}
            else {{
                throw "Network adapter management instrumentation is unavailable."
            }}

            $legacyAdapters |
                ForEach-Object {{
                    [PSCustomObject]@{{
                        Name = [string]$_.NetConnectionID
                        InterfaceDescription = [string]$_.Name
                        Status = if ($_.NetEnabled -eq $true) {{
                            "Up"
                        }}
                        elseif ($_.NetEnabled -eq $false) {{
                            "Disconnected"
                        }}
                        else {{
                            "Unknown"
                        }}
                        MacAddress = [string]$_.MACAddress
                        LinkSpeed = [uint64]$_.Speed
                        MediaType = [string]$_.AdapterType
                        Source = "Win32_NetworkAdapter"
                    }}
                }}
        }}
    )
}}
catch {{
    $errors.Add("adapter collection failed: $($_.Exception.Message)")
}}

$tcpTruncated = $tcpRows.Count -gt $maxEndpoints
$udpTruncated = $udpRows.Count -gt $maxEndpoints

$tcp = @($tcpRows | Select-Object -First $maxEndpoints)
$udp = @($udpRows | Select-Object -First $maxEndpoints)

$listenerCount = @(
    $tcp | Where-Object {{ $_.observation -eq 'local_listener' }}
).Count

$collectionStatus = if ($errors.Count -eq 0) {{
    'complete'
}}
elseif (($tcp.Count + $udp.Count + $adapters.Count) -gt 0) {{
    'partial'
}}
else {{
    'failed'
}}

[PSCustomObject]@{{
    success = $collectionStatus -ne 'failed'
    collector = 'windows_network_inventory'
    collection_status = $collectionStatus
    limits = @{{
        max_endpoints_per_protocol = $maxEndpoints
        tcp_truncated = $tcpTruncated
        udp_truncated = $udpTruncated
    }}
    summary = @{{
        tcp_endpoints_returned = $tcp.Count
        udp_endpoints_returned = $udp.Count
        local_tcp_listeners_returned = $listenerCount
        adapters_returned = $adapters.Count
    }}
    tcp = $tcp
    udp = $udp
    adapters = $adapters
    errors = @($errors)
}} | ConvertTo-Json -Depth 8 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "windows_network_inventory",
            "collection_status": "failed",
            "error": error.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_limit_is_bounded() {
        assert_eq!(MAX_ENDPOINTS_PER_PROTOCOL, 1024);
    }
}
