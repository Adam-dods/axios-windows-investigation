const NETWORK: &str = include_str!("../src/bin/axios-network-deep-review.rs");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const ADMIN: &str = include_str!("../installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1");

#[test]
fn generated_network_ip_configuration_uses_real_powershell_braces() {
    let start = NETWORK
        .find("$ipConfiguration = @(")
        .expect("IP configuration block");
    let end = NETWORK[start..]
        .find("Add-AxiosCapability 'ip_configuration' 'collected'")
        .map(|offset| start + offset)
        .expect("IP configuration block end");
    let block = &NETWORK[start..end];

    for invalid in ["ForEach-Object {{", "[PSCustomObject]@{{", ") {{", "}}"] {
        assert!(
            !block.contains(invalid),
            "escaped PowerShell syntax remained: {invalid}"
        );
    }

    assert!(block.contains("ForEach-Object {"));
    assert!(block.contains("[PSCustomObject]@{"));
}

#[test]
fn results_searches_all_supported_artifacts_in_one_pass() {
    assert!(LAYER.contains("foreach ($File in @("));
    assert!(LAYER.contains("if ($File.Name -like $Pattern)"));
    assert!(LAYER.contains("AXIOS-Investigation-Results-*.json"));
    assert!(LAYER.contains("AXIOS-Layer-*.json"));
    assert!(LAYER.contains("AXIOS-Network-Deep-Review-*.json"));
    assert!(LAYER.contains("AXIOS-Administrator-Exposure-Audit-*.json"));
}

#[test]
fn high_signal_prefix_is_literal_and_not_a_wildcard_class() {
    assert!(LAYER.contains(".StartsWith("));
    assert!(LAYER.contains("\"[HIGH]\""));
    assert!(!LAYER.contains("$_ -like \"[HIGH]*\""));
}

#[test]
fn tamper_state_is_consistent_across_quick_system_and_software() {
    assert!(LAYER.contains("tamper_protection_source"));
    assert!(LAYER.contains("tamper_protected"));
    assert!(LAYER.contains("Microsoft Defender tamper protection is disabled"));
    assert!(LAYER.contains("\"Tamper protection      : {0}\""));
}

#[test]
fn administrator_display_falls_back_to_finding_priority() {
    assert!(ADMIN.contains("-Name \"severity\""));
    assert!(ADMIN.contains("-Name \"priority\""));
    assert!(ADMIN.contains("-DefaultValue \"review\""));
}
