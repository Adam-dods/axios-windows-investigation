use std::fs;

const SOURCE_PATH: &str = "src/bin/axios-user-exposure-audit.rs";

fn source() -> String {
    fs::read_to_string(SOURCE_PATH).expect("standard-user exposure source should be readable")
}

#[test]
fn standard_user_acl_paths_are_normalized_once() {
    let source = source();

    assert!(source.contains("function Resolve-AxiosFilesystemPath"));
    assert!(source.contains("[Environment]::ExpandEnvironmentVariables("));
    assert!(source.contains("$Path.Trim().Trim('\"')"));
    assert!(source.contains("[System.IO.Path]::GetFullPath($normalized)"));
    assert!(source.contains("$normalizedPath = Resolve-AxiosFilesystemPath $Path"));
}

#[test]
fn executable_paths_are_normalized_before_acl_collection() {
    let source = source();

    assert!(source.contains("return Resolve-AxiosFilesystemPath $candidate"));
    assert!(source.contains("Get-Acl `\n                    -LiteralPath $normalizedPath"));
    assert!(!source.contains("Get-Acl -LiteralPath $Path -ErrorAction Stop"));
}

#[test]
fn windows_root_relative_paths_are_resolved() {
    let source = source();

    assert!(source.contains("$normalized.StartsWith('\\SystemRoot\\'"));
    assert!(source.contains("$normalized.StartsWith('System32\\'"));
    assert!(source.contains("Join-Path $env:SystemRoot"));
}

#[test]
fn path_failures_remain_explicit_and_traceable() {
    let source = source();

    assert!(source.contains("path_normalization:{{0}}: {{1}}"));
    assert!(source.contains("acl:{{0}}: {{1}}"));
    assert!(source.contains("$collectionErrors"));
    assert!(source.contains("collection_status"));
    assert!(source.contains("collection_errors"));
}
