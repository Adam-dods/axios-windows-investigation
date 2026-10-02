const ADMIN_AUDIT: &str = include_str!("../src/bin/axios-admin-exposure-audit.rs");

const PERSISTENCE_COVERAGE: &str = include_str!("../src/persistence/coverage.rs");

fn registry_acl_block() -> &'static str {
    let start = ADMIN_AUDIT
        .find("function Get-AxiosRegistryAclAssessment")
        .expect("registry ACL function should exist");

    let end = ADMIN_AUDIT
        .find("function Get-AxiosServiceRegistryPath")
        .expect("service registry resolver should exist");

    &ADMIN_AUDIT[start..end]
}

#[test]
fn registry_acl_uses_native_windows_api() {
    let block = registry_acl_block();

    assert!(block.contains("[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("));
    assert!(block.contains("$nativeKey.GetAccessControl()"));
    assert!(block.contains("$nativeKey.Dispose()"));
    assert!(block.contains("finally {"));

    assert!(!block.contains("Get-Acl -LiteralPath $RegistryPath"));
    assert!(!block.contains("Test-Path -LiteralPath $RegistryPath"));
}

#[test]
fn registry_paths_are_normalized_without_localization() {
    let block = registry_acl_block();

    assert!(block.contains("'Registry::HKEY_LOCAL_MACHINE\\'"));
    assert!(block.contains("'HKEY_LOCAL_MACHINE\\'"));
    assert!(block.contains("'HKLM:\\'"));
    assert!(block.contains("[StringComparison]::OrdinalIgnoreCase"));
}

#[test]
fn registry_not_found_is_not_a_collection_error() {
    let block = registry_acl_block();

    let open = block
        .find("OpenSubKey(")
        .expect("native registry open should exist");

    let missing = block
        .find("if ($null -eq $nativeKey)")
        .expect("missing key handling should exist");

    let not_found = block
        .find("status = 'not_found'")
        .expect("not-found status should exist");

    let catch = block
        .find("catch {")
        .expect("real error handling should exist");

    let collection_error = block
        .find("Add-AxiosCollectionError $Source $_")
        .expect("real errors should be recorded");

    assert!(open < missing);
    assert!(missing < not_found);
    assert!(not_found < catch);
    assert!(catch < collection_error);
}

#[test]
fn native_registry_handles_are_always_released() {
    let block = registry_acl_block();

    let finally = block.find("finally {").expect("finally block should exist");

    let dispose = block
        .find("$nativeKey.Dispose()")
        .expect("native registry handle should be disposed");

    assert!(finally < dispose);
}

#[test]
fn persistence_format_placeholders_are_runtime_correct() {
    assert!(PERSISTENCE_COVERAGE.contains(r#""{0}: {1}" -f $Source, $_.Exception.Message"#));

    assert!(PERSISTENCE_COVERAGE
        .contains(r#""run_key:{0}: {1}" -f $location.source, $_.Exception.Message"#));

    assert!(PERSISTENCE_COVERAGE
        .contains(r#""startup_folder:{0}: {1}" -f $folder, $_.Exception.Message"#));

    assert!(!PERSISTENCE_COVERAGE.contains("{{0}}"));
    assert!(!PERSISTENCE_COVERAGE.contains("{{1}}"));
}
