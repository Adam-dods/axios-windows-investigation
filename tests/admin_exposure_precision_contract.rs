use std::fs;

#[test]
fn administrator_exposure_audit_is_precise_cached_and_localization_safe() {
    let source = fs::read_to_string("src/bin/axios-admin-exposure-audit.rs")
        .expect("administrator exposure source should be readable");

    assert!(source.contains("$fileAclCache = @{}"));
    assert!(source.contains("$registryAclCache = @{}"));

    assert!(source.contains(r"HKLM:\SYSTEM\CurrentControlSet\Services\{0}"));

    assert_eq!(
        source.matches(r"Registry::HKEY_LOCAL_MACHINE").count(),
        1,
        "legacy prefix should only exist in input normalization"
    );

    let resolver_start = source
        .find("function Get-AxiosServiceRegistryPath")
        .expect("service registry resolver should exist");

    let resolver_end = source[resolver_start..]
        .find("function Get-AxiosUnquotedCandidates")
        .map(|offset| resolver_start + offset)
        .expect("service registry resolver end should exist");

    let resolver = &source[resolver_start..resolver_end];

    assert!(resolver.contains(r"HKLM:\SYSTEM\CurrentControlSet\Services\{0}"));

    assert!(!resolver.contains(r"Registry::HKEY_LOCAL_MACHINE"));

    let assessment_start = source
        .find("function Get-AxiosRegistryAclAssessment")
        .expect("registry ACL assessment should exist");

    let assessment_end = source[assessment_start..]
        .find("function Get-AxiosServiceRegistryPath")
        .map(|offset| assessment_start + offset)
        .expect("registry ACL assessment end should exist");

    let assessment = &source[assessment_start..assessment_end];

    assert!(assessment.contains("[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("));
    assert!(assessment.contains("$nativeKey.GetAccessControl()"));
    assert!(assessment.contains("$nativeKey.Dispose()"));
    assert!(assessment.contains("finally {"));

    assert!(!assessment.contains("Get-Acl -LiteralPath $RegistryPath"));

    assert!(source.contains("Get-LocalGroupMember -SID 'S-1-5-32-544'"));
    assert!(source.contains("unquoted_service_path_writable_candidate"));
    assert!(source.contains("$executablePath -match '\\s'"));
    assert!(source.contains("parent_potential_broad_write"));
    assert!(source.contains("allow_and_deny_evaluated = $true"));
    assert!(source.contains("file_acl_cache_entries"));
    assert!(source.contains("total_ms = $totalTimer.ElapsedMilliseconds"));

    assert!(!source.contains("System service has an unquoted executable path"));
    assert!(!source.contains("FileSystemRights]::FullControl -bor"));
    assert!(!source.contains("FileSystemRights]::Write -bor"));
    assert!(!source.contains("RegistryRights]::FullControl"));
    assert!(!source.contains("RegistryRights]::WriteKey -bor"));

    assert!(source.contains("FileSystemRights]::WriteData -bor"));
    assert!(source.contains("RegistryRights]::SetValue -bor"));
}
