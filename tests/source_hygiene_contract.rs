const DEVELOPER: &str = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");

use std::fs;
use std::path::{Path, PathBuf};

fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("source directory must be readable") {
            let path = entry.expect("directory entry must be readable").path();

            if path.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) != Some("target") {
                    pending.push(path);
                }
            } else if matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("rs" | "ps1" | "sh" | "toml" | "md" | "txt")
            ) {
                files.push(path);
            }
        }
    }

    files
}

#[test]
fn shipped_source_contains_no_arabic_output_or_personal_machine_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in source_files(root) {
        let content =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));

        assert!(
            !content
                .chars()
                .any(|character| matches!(character, '\u{0600}'..='\u{06ff}')),
            "{} contains Arabic text",
            path.display()
        );

        let normalized = content.replace("\\\\", "\\");
        let windows_user_prefix = "C:\\Users\\";
        let unix_home_prefix = ["/", "home", "/"].concat();

        assert!(
            !normalized.contains(&unix_home_prefix),
            "{} contains a development-machine home path",
            path.display()
        );

        let mut remaining = normalized.as_str();

        while let Some(position) = remaining.find(windows_user_prefix) {
            let tail = &remaining[position + windows_user_prefix.len()..];

            let end = tail
                .find(|character: char| {
                    character == '\\'
                        || character == '/'
                        || character == '"'
                        || character == '\''
                        || character.is_whitespace()
                })
                .unwrap_or(tail.len());

            let username = &tail[..end];

            if !username.is_empty() {
                assert!(
                    matches!(username, "Test" | "TestUser"),
                    "{} contains a non-synthetic Windows user path",
                    path.display()
                );
            }

            if tail.is_empty() {
                break;
            }

            remaining = &tail[1.min(tail.len())..];
        }
    }
}

#[test]
fn developer_exposure_uses_professional_evidence_sections() {
    for heading in [
        "ADVANCED EXPOSURE ASSESSMENT",
        "SYSTEM AND SECURITY PROFILE",
        "CONFIGURATION EXPOSURES",
        "VISIBILITY LIMITATIONS",
    ] {
        assert!(
            DEVELOPER.contains(heading),
            "missing professional section: {heading}"
        );
    }

    for field in [
        "Assessment status",
        "Collectors returned",
        "Assessment observations",
        "Evidence source",
        "Verification",
        "Finding class",
    ] {
        assert!(DEVELOPER.contains(field), "missing evidence field: {field}");
    }

    for obsolete_flag in [
        "\"SUCCESS=",
        "\"STATUS=",
        "\"FINDINGS=",
        "\"GAP=",
        "\"SOURCE=",
        "\"CLASSIFICATION=",
        "\"FINDING=",
    ] {
        assert!(
            !DEVELOPER.contains(obsolete_flag),
            "obsolete debug flag remains: {obsolete_flag}"
        );
    }
}
