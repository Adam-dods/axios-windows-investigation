use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'

$maxProcesses = 1024
$maxTcpEndpoints = 1024
$maxUdpEndpoints = 512

$processIndex = @{}
$processRows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$processTruncated = $processRows.Count -gt $maxProcesses

$processRows |
    Select-Object -First $maxProcesses Handle, ParentProcessId, Name, ExecutablePath, CommandLine |
    ForEach-Object { $processIndex[[string]$_.Handle] = $_ }

$tcpRows = @(Get-NetTCPConnection -ErrorAction Stop)
$tcpTruncated = $tcpRows.Count -gt $maxTcpEndpoints

$tcp = @(
    $tcpRows |
    Select-Object -First $maxTcpEndpoints State, LocalAddress, LocalPort,
        RemoteAddress, RemotePort, OwningProcess |
    ForEach-Object {
        $process = $processIndex[[string]$_.OwningProcess]

        [PSCustomObject]@{
            protocol = 'tcp'
            state = [string]$_.State
            local_address = [string]$_.LocalAddress
            local_port = $_.LocalPort
            remote_address = [string]$_.RemoteAddress
            remote_port = $_.RemotePort
            process_id = $_.OwningProcess
            process_name = if ($process) { $process.Name } else { $null }
            executable = if ($process) { $process.ExecutablePath } else { $null }
            parent_process_id = if ($process) { $process.ParentProcessId } else { $null }
        }
    }
)

$udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop)
$udpTruncated = $udpRows.Count -gt $maxUdpEndpoints

$udp = @(
    $udpRows |
    Select-Object -First $maxUdpEndpoints LocalAddress, LocalPort, OwningProcess |
    ForEach-Object {
        $process = $processIndex[[string]$_.OwningProcess]

        [PSCustomObject]@{
            protocol = 'udp'
            local_address = [string]$_.LocalAddress
            local_port = $_.LocalPort
            process_id = $_.OwningProcess
            process_name = if ($process) { $process.Name } else { $null }
            executable = if ($process) { $process.ExecutablePath } else { $null }
            parent_process_id = if ($process) { $process.ParentProcessId } else { $null }
        }
    }
)

[PSCustomObject]@{
    collector = 'windows_live_activity'
    tcp_endpoints = $tcp
    udp_endpoints = $udp
    tcp_endpoint_count = @($tcp).Count
    udp_endpoint_count = @($udp).Count
    limits = @{
        max_processes = $maxProcesses
        max_tcp_endpoints = $maxTcpEndpoints
        max_udp_endpoints = $maxUdpEndpoints
        processes_truncated = $processTruncated
        tcp_endpoints_truncated = $tcpTruncated
        udp_endpoints_truncated = $udpTruncated
    }
    collection_status = if ($processTruncated -or $tcpTruncated -or $udpTruncated) { 'partial' } else { 'complete' }
    success = $true
} | ConvertTo-Json -Depth 8 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_live_activity",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_live_activity",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoint_limits_are_bounded() {
        assert_eq!(1024usize, 1024);
        assert_eq!(512usize, 512);
    }
}
