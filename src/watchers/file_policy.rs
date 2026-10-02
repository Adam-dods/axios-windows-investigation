use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_TRACKED_PATHS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTarget {
    pub path: PathBuf,
    pub recursive: bool,
    pub importance: WatchImportance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchImportance {
    Critical,
    High,
    Normal,
}

#[derive(Clone)]
pub struct FileWatchPolicy {
    targets: Vec<WatchTarget>,
    cooldown: Duration,
    last_event: HashMap<PathBuf, Instant>,
}

impl FileWatchPolicy {
    pub fn windows_default() -> Self {
        Self {
            targets: vec![
                target(
                    r"C:\Windows\System32\Tasks",
                    true,
                    WatchImportance::Critical,
                ),
                target(
                    r"C:\Windows\System32\drivers",
                    true,
                    WatchImportance::Critical,
                ),
                target(
                    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                    true,
                    WatchImportance::Critical,
                ),
            ],
            cooldown: Duration::from_secs(2),
            last_event: HashMap::new(),
        }
    }

    pub fn targets(&self) -> &[WatchTarget] {
        &self.targets
    }

    pub fn should_process(&mut self, path: impl AsRef<Path>, now: Instant) -> bool {
        // Windows paths are case insensitive; normalize only the debounce key.
        let path = PathBuf::from(
            path.as_ref()
                .to_string_lossy()
                .replace('/', "\\")
                .to_ascii_lowercase(),
        );

        if self
            .last_event
            .get(&path)
            .is_some_and(|previous| now.saturating_duration_since(*previous) < self.cooldown)
        {
            return false;
        }

        if !self.last_event.contains_key(&path) && self.last_event.len() >= MAX_TRACKED_PATHS {
            self.last_event
                .retain(|_, previous| now.saturating_duration_since(*previous) < self.cooldown);

            if self.last_event.len() >= MAX_TRACKED_PATHS {
                if let Some(oldest) = self
                    .last_event
                    .iter()
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(path, _)| path.clone())
                {
                    self.last_event.remove(&oldest);
                }
            }
        }

        self.last_event.insert(path, now);
        true
    }

    pub fn add_target(&mut self, target: WatchTarget) {
        if !self
            .targets
            .iter()
            .any(|existing| existing.path == target.path)
        {
            self.targets.push(target);
        }
    }
}

fn target(path: impl Into<PathBuf>, recursive: bool, importance: WatchImportance) -> WatchTarget {
    WatchTarget {
        path: path.into(),
        recursive,
        importance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_event_is_debounced() {
        let mut policy = FileWatchPolicy::windows_default();
        let now = Instant::now();
        let path = Path::new(r"C:\ProgramData\test.exe");

        assert!(policy.should_process(path, now));

        assert!(!policy.should_process(path, now + Duration::from_millis(500)));

        assert!(policy.should_process(path, now + Duration::from_secs(3)));
    }

    #[test]
    fn default_policy_is_selective() {
        let policy = FileWatchPolicy::windows_default();

        assert_eq!(policy.targets().len(), 3);

        assert!(policy
            .targets()
            .iter()
            .any(|target| { target.importance == WatchImportance::Critical }));
    }

    #[test]
    fn duplicate_target_is_not_added_twice() {
        let mut policy = FileWatchPolicy::windows_default();
        let count = policy.targets().len();

        policy.add_target(WatchTarget {
            path: PathBuf::from(r"C:\Windows\System32\Tasks"),
            recursive: true,
            importance: WatchImportance::Critical,
        });

        assert_eq!(policy.targets().len(), count);
    }

    #[test]
    fn debounce_uses_case_insensitive_windows_paths() {
        let mut policy = FileWatchPolicy::windows_default();
        let now = Instant::now();
        assert!(policy.should_process(r"C:\Windows\System32\Tasks\Example.exe", now));
        assert!(!policy.should_process(
            r"c:/windows/system32/tasks/EXAMPLE.EXE",
            now + Duration::from_millis(200),
        ));
    }

    #[test]
    fn debounce_state_remains_bounded_after_many_distinct_paths() {
        let mut policy = FileWatchPolicy::windows_default();
        let now = Instant::now();
        for index in 0..(MAX_TRACKED_PATHS + 100) {
            assert!(policy.should_process(format!(r"C:\Windows\Tasks\{index}.exe"), now));
        }
        assert!(policy.last_event.len() <= MAX_TRACKED_PATHS);
    }
}
