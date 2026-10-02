const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");

#[test]
fn launcher_declares_the_real_powershell_requirement() {
    assert!(LAUNCHER.contains("$AxiosMinimumPowerShellVersion"));
    assert!(LAUNCHER.contains("[version]\"5.1\""));
    assert!(LAUNCHER.contains("Windows 7 and Windows 8 require Windows Management Framework 5.1."));
}

#[test]
fn launcher_detects_operating_system_architecture_without_personal_paths() {
    assert!(LAUNCHER.contains("[Environment]::OSVersion.Version"));
    assert!(LAUNCHER.contains("[Environment]::Is64BitOperatingSystem"));
    assert!(LAUNCHER.contains("$AxiosOperatingSystemArchitecture"));
}

#[test]
fn compatibility_failures_are_english_only() {
    assert!(!LAUNCHER
        .chars()
        .any(|character| matches!(character, '\u{0600}'..='\u{06ff}')));
}

#[test]
fn network_posture_has_legacy_dns_and_firewall_fallbacks() {
    let source = include_str!("../src/system/network_posture.rs");

    assert!(source.contains("Get-Command Get-DnsClientServerAddress"));
    assert!(source.contains("Win32_NetworkAdapterConfiguration"));
    assert!(source.contains("Get-Command Get-CimInstance"));
    assert!(source.contains("Get-Command Get-WmiObject"));
    assert!(source.contains("Get-Command Get-NetFirewallProfile"));
    assert!(source.contains("HNetCfg.FwPolicy2"));
    assert!(source.contains("\"{0}: {1}\" -f $Source"));
    assert!(!source.contains("\"{{0}}: {{1}}\" -f $Source"));
}

#[test]
fn network_inventory_has_legacy_adapter_fallback() {
    let source = include_str!("../src/network/collector.rs");

    assert!(source.contains("Get-Command Get-NetAdapter"));
    assert!(source.contains("Win32_NetworkAdapter"));
    assert!(source.contains("Get-Command Get-CimInstance"));
    assert!(source.contains("Get-Command Get-WmiObject"));
    assert!(source.contains("Source = \"Win32_NetworkAdapter\""));
    assert!(source.contains("Network adapter management instrumentation is unavailable."));
}
