use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFingerprint {
    pub path: String,
    pub size_bytes: u64,
    pub modified_at: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub schema_version: u32,
    pub created_at: String,
    pub root_paths: Vec<String>,
    pub files: Vec<FileFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityChange {
    pub path: String,
    pub kind: String,
    pub previous_sha256: Option<String>,
    pub current_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub unchanged: usize,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub changes: Vec<IntegrityChange>,
}

pub fn create_manifest(roots: &[PathBuf]) -> Result<IntegrityManifest> {
    let mut files = Vec::new();

    for root in roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            match fingerprint_file(entry.path()) {
                Ok(fingerprint) => files.push(fingerprint),
                Err(_) => continue,
            }
        }
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(IntegrityManifest {
        schema_version: 1,
        created_at: Utc::now().to_rfc3339(),
        root_paths: roots
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        files,
    })
}

pub fn fingerprint_file(path: impl AsRef<Path>) -> Result<FileFingerprint> {
    let path = path.as_ref();

    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to read {}", path.display()))?;

    let modified_at = metadata.modified().ok().and_then(format_system_time);

    Ok(FileFingerprint {
        path: path.to_string_lossy().to_string(),
        size_bytes: metadata.len(),
        modified_at,
        sha256: sha256_file(path)?,
    })
}

pub fn compare(baseline: &IntegrityManifest, current: &IntegrityManifest) -> IntegrityReport {
    let before = file_map(&baseline.files);
    let after = file_map(&current.files);
    let mut changes = Vec::new();
    let mut unchanged = 0;

    for (path, previous) in &before {
        match after.get(path) {
            None => changes.push(IntegrityChange {
                path: path.clone(),
                kind: "removed".to_string(),
                previous_sha256: Some(previous.sha256.clone()),
                current_sha256: None,
            }),

            Some(current) if current.sha256 != previous.sha256 => changes.push(IntegrityChange {
                path: path.clone(),
                kind: "modified".to_string(),
                previous_sha256: Some(previous.sha256.clone()),
                current_sha256: Some(current.sha256.clone()),
            }),

            Some(_) => unchanged += 1,
        }
    }

    for (path, current) in &after {
        if !before.contains_key(path) {
            changes.push(IntegrityChange {
                path: path.clone(),
                kind: "added".to_string(),
                previous_sha256: None,
                current_sha256: Some(current.sha256.clone()),
            });
        }
    }

    changes.sort_by(|left, right| left.path.cmp(&right.path));

    IntegrityReport {
        unchanged,
        added: changes
            .iter()
            .filter(|change| change.kind == "added")
            .count(),
        removed: changes
            .iter()
            .filter(|change| change.kind == "removed")
            .count(),
        modified: changes
            .iter()
            .filter(|change| change.kind == "modified")
            .count(),
        changes,
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];

    loop {
        let count = reader.read(&mut buffer)?;

        if count == 0 {
            break;
        }

        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn file_map(files: &[FileFingerprint]) -> BTreeMap<String, &FileFingerprint> {
    files.iter().map(|file| (file.path.clone(), file)).collect()
}

fn format_system_time(time: SystemTime) -> Option<String> {
    let datetime: DateTime<Utc> = time.into();
    Some(datetime.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, hash: &str) -> FileFingerprint {
        FileFingerprint {
            path: path.to_string(),
            size_bytes: 1,
            modified_at: None,
            sha256: hash.to_string(),
        }
    }

    fn manifest(files: Vec<FileFingerprint>) -> IntegrityManifest {
        IntegrityManifest {
            schema_version: 1,
            created_at: "2026-08-01T00:00:00Z".to_string(),
            root_paths: vec!["C:\\Test".to_string()],
            files,
        }
    }

    #[test]
    fn detects_added_removed_and_modified_files() {
        let before = manifest(vec![
            file("C:\\Test\\a.exe", "aaa"),
            file("C:\\Test\\b.dll", "bbb"),
        ]);

        let after = manifest(vec![
            file("C:\\Test\\a.exe", "changed"),
            file("C:\\Test\\c.sys", "ccc"),
        ]);

        let report = compare(&before, &after);

        assert_eq!(report.added, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.modified, 1);
        assert_eq!(report.unchanged, 0);
    }

    #[test]
    fn identical_manifests_have_no_changes() {
        let manifest = manifest(vec![file("C:\\Test\\a.exe", "aaa")]);

        let report = compare(&manifest, &manifest);

        assert_eq!(report.changes.len(), 0);
        assert_eq!(report.unchanged, 1);
    }
}
