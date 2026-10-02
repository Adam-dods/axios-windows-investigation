use std::fs;
use std::path::PathBuf;

fn runner_source() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("installer/windows/Run-AXIOS-Complete-Investigation.ps1"))
        .expect("complete investigation runner should be readable")
}

#[test]
fn portable_artifact_projection_tolerates_optional_fields() {
    let source = runner_source();

    assert!(source.contains("-Name \"artifacts\" `\n                -DefaultValue @()"));
    assert!(source.contains("-Value $PortableArtifact `\n                    -Name \"name\""));
    assert!(source.contains("-Value $PortableArtifact `\n                    -Name \"role\""));
    assert!(source.contains("-Value $PortableArtifact `\n                    -Name \"path\""));
    assert!(
        source.contains("-Name \"success\" `\n                            -DefaultValue $false")
    );

    assert!(!source.contains("$ForensicReport.artifacts"));
    assert!(!source.contains("$PortableArtifact.name"));
    assert!(!source.contains("$PortableArtifact.role"));
    assert!(!source.contains("$PortableArtifact.path"));
    assert!(!source.contains("$PortableArtifact.size_bytes"));
    assert!(!source.contains("$PortableArtifact.sha256"));
    assert!(!source.contains("$PortableArtifact.success"));
}

#[test]
fn unnamed_artifacts_receive_a_stable_fallback_name() {
    let source = runner_source();

    assert!(source.contains("$PortableArtifactName = \"unnamed_artifact\""));
    assert!(source.contains("$PortableArtifactName = $PortableArtifactRole"));
    assert!(source.contains("$PortableArtifactName = [IO.Path]::GetFileName("));
}
