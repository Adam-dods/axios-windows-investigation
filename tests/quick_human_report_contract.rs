const RUNNER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn quick_mode_has_a_human_readable_console_report() {
    for required in [
        "RAPID SECURITY ASSESSMENT",
        "SECURITY CONTROLS",
        "SYSTEM AND RUNTIME ACTIVITY",
        "SECURITY CONTROL STATE",
        "VISIBILITY LIMITATIONS",
        "Detailed TXT report",
        "Structured JSON result",
        "Raw evidence directory",
    ] {
        assert!(
            RUNNER.contains(required),
            "missing Quick report element: {required}"
        );
    }
}

#[test]
fn quick_report_preserves_machine_readable_receipt() {
    assert!(RUNNER.contains("Write-AxiosQuickHumanReport"));
    assert!(RUNNER.contains("ConvertTo-Json -Depth 6 -Compress"));
    assert!(RUNNER.contains("Write-Host"));
}

#[test]
fn quick_detailed_report_contains_every_raw_report() {
    assert!(RUNNER.contains("$ReportData[$Command] = $Report"));
    assert!(RUNNER.contains("$ReportData.GetEnumerator()"));
    assert!(RUNNER.contains("ConvertTo-Json -Depth 30"));
    assert!(RUNNER.contains("[System.IO.File]::WriteAllText("));
}

#[test]
fn quick_security_state_is_evidence_based() {
    for field in [
        "antivirus_enabled",
        "real_time_protection_enabled",
        "behavior_monitor_enabled",
        "ioav_protection_enabled",
        "antivirus_signature_last_updated",
        "secure_boot",
        "enable_lua",
    ] {
        assert!(RUNNER.contains(field), "missing evidence field: {field}");
    }

    assert!(RUNNER.contains("no critical control failure observed in Quick scope"));
}

#[test]
fn quick_summary_reads_ordered_dictionary_values() {
    assert!(RUNNER.contains("$Value -is [System.Collections.IDictionary]"));
    assert!(RUNNER.contains("$Value.Contains($Name)"));
    assert!(RUNNER.contains("Physical memory"));
    assert!(RUNNER.contains("Firewall {0,-10}"));
}

#[test]
fn quick_dns_handles_zero_one_or_many_addresses() {
    assert!(RUNNER.contains("(Get-AxiosCount $DnsAddresses) -eq 0"));
    assert!(RUNNER.contains("@($DnsAddresses) -join \", \""));
    assert!(!RUNNER.contains("$DnsAddresses.Count -eq 0"));
}
