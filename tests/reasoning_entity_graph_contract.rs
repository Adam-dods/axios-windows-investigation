use axios_core::reasoning::{
    graph::match_artifact_identities, ArtifactIdentity, IdentityMatchStrength,
};

fn identity(
    path: &str,
    hash: Option<&str>,
    pid: Option<u64>,
    start: Option<&str>,
) -> ArtifactIdentity {
    ArtifactIdentity::normalized(Some(path), hash, pid, start)
}

#[test]
fn same_path_and_hash_with_same_process_instance_is_strong() {
    let result = match_artifact_identities(&[
        identity(r"C:\Sample.exe", Some("AABB"), None, None),
        identity(r"c:/sample.exe", Some("aabb"), Some(42), Some("100")),
        identity(r"C:\SAMPLE.EXE", Some("AABB"), Some(42), Some("100")),
    ]);

    assert_eq!(result.strength, IdentityMatchStrength::Strong);
}

#[test]
fn same_path_different_hash_is_not_same_artifact() {
    let result = match_artifact_identities(&[
        identity(r"C:\sample.exe", Some("aaaa"), Some(42), Some("100")),
        identity(r"C:\sample.exe", Some("bbbb"), Some(42), Some("100")),
    ]);

    assert_eq!(result.strength, IdentityMatchStrength::Conflict);
}

#[test]
fn same_pid_different_start_time_is_not_strong() {
    let result = match_artifact_identities(&[
        identity(r"C:\sample.exe", Some("aaaa"), Some(42), Some("100")),
        identity(r"C:\sample.exe", Some("aaaa"), Some(42), Some("200")),
    ]);

    assert_eq!(result.strength, IdentityMatchStrength::Partial);
    assert!(!result.process_instance_confirmed);
}

#[test]
fn path_only_match_is_never_strong() {
    let result = match_artifact_identities(&[
        identity(r"C:\sample.exe", None, None, None),
        identity(r"c:/sample.exe", None, None, None),
    ]);

    assert_eq!(result.strength, IdentityMatchStrength::Partial);
}
