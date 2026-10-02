use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    time::Instant,
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::{
    file_policy::FileWatchPolicy,
    file_router::{FileChange, FileChangeKind, FileEventRouter, RoutedFileTask},
};

const MAX_PENDING_EVENTS: usize = 128;
const MAX_EVENTS_PER_POLL: usize = 32;
const MAX_ROUTED_TASKS_PER_POLL: usize = 16;

pub struct FileWatcherService {
    _watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<Event>>,
    router: FileEventRouter,
}

impl FileWatcherService {
    pub fn windows_default() -> notify::Result<Self> {
        Self::start(FileWatchPolicy::windows_default())
    }

    pub fn start(policy: FileWatchPolicy) -> notify::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_EVENTS);

        let mut watcher = notify::recommended_watcher(move |event| {
            // A busy filesystem must never block the watcher thread.
            let _ = sender.try_send(event);
        })?;

        for target in policy.targets() {
            let mode = if target.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };

            watcher.watch(&target.path, mode)?;
        }

        Ok(Self {
            _watcher: watcher,
            receiver,
            router: FileEventRouter::with_policy(policy),
        })
    }

    pub fn poll(&mut self) -> Vec<RoutedFileTask> {
        let mut tasks = Vec::with_capacity(MAX_ROUTED_TASKS_PER_POLL);

        for _ in 0..MAX_EVENTS_PER_POLL {
            let event = match self.receiver.try_recv() {
                Ok(Ok(event)) => event,
                Ok(Err(_)) => continue,
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            };

            let Some(kind) = classify_event_kind(&event) else {
                continue;
            };

            for path in event.paths {
                if tasks.len() >= MAX_ROUTED_TASKS_PER_POLL {
                    return tasks;
                }

                if let Some(task) = self.router.route(FileChange { path, kind }, Instant::now()) {
                    tasks.push(task);
                }
            }
        }

        tasks
    }
}

fn classify_event_kind(event: &Event) -> Option<FileChangeKind> {
    match event.kind {
        EventKind::Create(_) => Some(FileChangeKind::Created),
        EventKind::Modify(_) => Some(FileChangeKind::Modified),
        EventKind::Remove(_) => Some(FileChangeKind::Removed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use notify::event::{CreateKind, EventAttributes};

    use super::*;

    #[test]
    fn create_event_is_classified() {
        let event = Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![PathBuf::from(r"C:\ProgramData\sample.exe")],
            attrs: EventAttributes::default(),
        };

        assert_eq!(classify_event_kind(&event), Some(FileChangeKind::Created));
    }

    #[test]
    fn access_event_is_ignored() {
        let event = Event {
            kind: EventKind::Access(notify::event::AccessKind::Any),
            paths: Vec::new(),
            attrs: EventAttributes::default(),
        };

        assert_eq!(classify_event_kind(&event), None);
    }
}
