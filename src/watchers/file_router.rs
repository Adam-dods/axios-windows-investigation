use std::path::{Path, PathBuf};

use crate::runtime::scheduler::TaskKind;

use super::file_policy::{FileWatchPolicy, WatchImportance};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: PathBuf,
    pub kind: FileChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedFileTask {
    pub kind: TaskKind,
    pub path: PathBuf,
    pub importance: WatchImportance,
}

pub struct FileEventRouter {
    policy: FileWatchPolicy,
}

impl FileEventRouter {
    pub fn windows_default() -> Self {
        Self::with_policy(FileWatchPolicy::windows_default())
    }

    pub fn with_policy(policy: FileWatchPolicy) -> Self {
        Self { policy }
    }

    pub fn route(&mut self, change: FileChange, now: std::time::Instant) -> Option<RoutedFileTask> {
        if self.is_axios_data(&change.path)
            || !self.is_in_watched_target(&change.path)
            || !is_security_relevant(&change.path)
            || !self.policy.should_process(&change.path, now)
        {
            return None;
        }

        let importance = self.importance_for(&change.path)?;

        let kind = match change.kind {
            FileChangeKind::Removed => TaskKind::FileIntegrity,
            FileChangeKind::Created | FileChangeKind::Modified => {
                if is_executable_or_driver(&change.path) {
                    TaskKind::SignatureVerification
                } else {
                    TaskKind::FileIntegrity
                }
            }
        };

        Some(RoutedFileTask {
            kind,
            path: change.path,
            importance,
        })
    }

    fn is_in_watched_target(&self, path: &Path) -> bool {
        self.policy
            .targets()
            .iter()
            .any(|target| windows_path_is_under(path, &target.path))
    }

    fn importance_for(&self, path: &Path) -> Option<WatchImportance> {
        self.policy
            .targets()
            .iter()
            .filter(|target| windows_path_is_under(path, &target.path))
            .map(|target| target.importance)
            .max_by_key(|importance| match importance {
                WatchImportance::Normal => 1,
                WatchImportance::High => 2,
                WatchImportance::Critical => 3,
            })
    }

    fn is_axios_data(&self, path: &Path) -> bool {
        windows_path_is_under(path, Path::new(r"C:\ProgramData\AXIOS"))
    }
}

fn windows_path_is_under(path: &Path, root: &Path) -> bool {
    let path = normalize_windows_path(path);
    let root = normalize_windows_path(root);

    path == root || path.starts_with(&(root + "\\"))
}

fn normalize_windows_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn is_security_relevant(path: &Path) -> bool {
    if windows_path_is_under(path, Path::new(r"C:\Windows\System32\Tasks")) {
        return true;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    matches!(
        extension.as_deref(),
        Some("exe" | "dll" | "sys" | "ps1" | "bat" | "cmd" | "vbs" | "js" | "jar" | "msi")
    )
}

fn is_executable_or_driver(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    matches!(extension.as_deref(), Some("exe" | "dll" | "sys" | "msi"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_change_requests_signature_check() {
        let mut router = FileEventRouter::windows_default();

        let task = router
            .route(
                FileChange {
                    path: PathBuf::from(
                        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\example.exe",
                    ),
                    kind: FileChangeKind::Created,
                },
                std::time::Instant::now(),
            )
            .expect("event should be routed");

        assert_eq!(task.kind, TaskKind::SignatureVerification);
        assert_eq!(task.importance, WatchImportance::Critical);
    }

    #[test]
    fn driver_removal_requests_integrity_check() {
        let mut router = FileEventRouter::windows_default();

        let task = router
            .route(
                FileChange {
                    path: PathBuf::from(r"C:\Windows\System32\drivers\bad.sys"),
                    kind: FileChangeKind::Removed,
                },
                std::time::Instant::now(),
            )
            .expect("event should be routed");

        assert_eq!(task.kind, TaskKind::FileIntegrity);
        assert_eq!(task.importance, WatchImportance::Critical);
    }

    #[test]
    fn unrelated_files_are_ignored() {
        let mut router = FileEventRouter::windows_default();

        assert!(router
            .route(
                FileChange {
                    path: PathBuf::from(r"C:\ProgramData\notes.txt",),
                    kind: FileChangeKind::Modified,
                },
                std::time::Instant::now(),
            )
            .is_none());
    }

    #[test]
    fn axios_own_logs_are_ignored() {
        let mut router = FileEventRouter::windows_default();

        assert!(router
            .route(
                FileChange {
                    path: PathBuf::from(r"C:\ProgramData\AXIOS\timeline.jsonl",),
                    kind: FileChangeKind::Modified,
                },
                std::time::Instant::now(),
            )
            .is_none());
    }

    #[test]
    fn axios_data_filter_is_case_insensitive_and_uses_directory_boundaries() {
        let router = FileEventRouter::windows_default();
        assert!(router.is_axios_data(Path::new(r"c:\programdata\axios\TIMELINE.jsonl")));
        assert!(!router.is_axios_data(Path::new(r"C:\ProgramData\AXIOS-extra\test.exe")));
    }
}
