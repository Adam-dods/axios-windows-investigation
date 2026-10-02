use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet},
    fmt,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    ProcessInspection,
    SignatureVerification,
    NetworkInspection,
    ResourceSample,
    WindowsEventLog,
    WindowsMetrics,
    DefenderStatus,
    FileIntegrity,
    BaselineComparison,
    RepairPlan,
}

impl TaskKind {
    pub fn is_implemented(self) -> bool {
        matches!(
            self,
            Self::ProcessInspection
                | Self::SignatureVerification
                | Self::NetworkInspection
                | Self::ResourceSample
                | Self::WindowsEventLog
                | Self::WindowsMetrics
                | Self::DefenderStatus
                | Self::FileIntegrity
        )
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskPriority {
    Background = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTarget {
    System,
    Process(u32),
    File(String),
    NetworkEndpoint(String),
}

#[derive(Debug, Clone)]
pub struct TaskRequest {
    pub kind: TaskKind,
    pub priority: TaskPriority,
    pub target: TaskTarget,
    pub requested_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct TaskBudget {
    pub max_runtime: Duration,
    pub min_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleDecision {
    Enqueued,
    Coalesced,
    RejectedCooldown,
    RejectedQueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SchedulerStats {
    pub queued: usize,
    pub in_flight: usize,
    pub completed: u64,
    pub failed: u64,
    pub coalesced: u64,
    pub rejected_cooldown: u64,
    pub rejected_queue_full: u64,
}

#[derive(Debug, Clone)]
pub struct ScheduledTask {
    pub id: u64,
    pub request: TaskRequest,
    pub budget: TaskBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaskKey {
    kind: TaskKind,
    target: TaskTarget,
}

#[derive(Debug, Clone)]
struct QueueEntry {
    sequence: u64,
    task: ScheduledTask,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
    }
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.task
            .request
            .priority
            .cmp(&other.task.request.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

pub struct TaskScheduler {
    queue: BinaryHeap<QueueEntry>,
    pending: HashSet<TaskKey>,
    in_flight: HashSet<TaskKey>,
    completed_at: HashMap<TaskKey, Instant>,
    sequence: u64,
    completed: u64,
    failed: u64,
    coalesced: u64,
    rejected_cooldown: u64,
    rejected_queue_full: u64,
    max_queue_size: usize,
}

impl TaskScheduler {
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            queue: BinaryHeap::new(),
            pending: HashSet::new(),
            in_flight: HashSet::new(),
            completed_at: HashMap::new(),
            sequence: 0,
            completed: 0,
            failed: 0,
            coalesced: 0,
            rejected_cooldown: 0,
            rejected_queue_full: 0,
            max_queue_size: max_queue_size.max(1),
        }
    }

    pub fn enqueue(
        &mut self,
        request: TaskRequest,
        budget: TaskBudget,
        now: Instant,
    ) -> ScheduleDecision {
        let key = TaskKey {
            kind: request.kind,
            target: request.target.clone(),
        };

        if self.pending.contains(&key) || self.in_flight.contains(&key) {
            self.coalesced += 1;
            return ScheduleDecision::Coalesced;
        }

        if self.queue.len() >= self.max_queue_size {
            self.rejected_queue_full += 1;
            return ScheduleDecision::RejectedQueueFull;
        }

        if let Some(last_completed) = self.completed_at.get(&key) {
            if now.duration_since(*last_completed) < budget.min_interval {
                self.rejected_cooldown += 1;
                return ScheduleDecision::RejectedCooldown;
            }
        }

        self.sequence += 1;

        let task = ScheduledTask {
            id: self.sequence,
            request,
            budget,
        };

        self.pending.insert(key);

        self.queue.push(QueueEntry {
            sequence: self.sequence,
            task,
        });

        ScheduleDecision::Enqueued
    }

    pub fn dequeue(&mut self) -> Option<ScheduledTask> {
        let entry = self.queue.pop()?;

        let key = TaskKey {
            kind: entry.task.request.kind,
            target: entry.task.request.target.clone(),
        };

        self.pending.remove(&key);
        self.in_flight.insert(key);

        Some(entry.task)
    }

    pub fn complete(&mut self, task: &ScheduledTask, now: Instant) {
        let key = TaskKey {
            kind: task.request.kind,
            target: task.request.target.clone(),
        };

        self.in_flight.remove(&key);
        self.completed_at.insert(key, now);
        self.completed += 1;
    }

    pub fn fail(&mut self, task: &ScheduledTask, now: Instant) {
        let key = TaskKey {
            kind: task.request.kind,
            target: task.request.target.clone(),
        };

        self.in_flight.remove(&key);
        self.completed_at.insert(key, now);
        self.failed += 1;
    }

    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            queued: self.queue.len(),
            in_flight: self.in_flight.len(),
            completed: self.completed,
            failed: self.failed,
            coalesced: self.coalesced,
            rejected_cooldown: self.rejected_cooldown,
            rejected_queue_full: self.rejected_queue_full,
        }
    }
}

impl fmt::Display for TaskKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::ProcessInspection => "process_inspection",
            Self::SignatureVerification => "signature_verification",
            Self::NetworkInspection => "network_inspection",
            Self::ResourceSample => "resource_sample",
            Self::WindowsEventLog => "windows_event_log",
            Self::WindowsMetrics => "windows_metrics",
            Self::DefenderStatus => "defender_status",
            Self::FileIntegrity => "file_integrity",
            Self::BaselineComparison => "baseline_comparison",
            Self::RepairPlan => "repair_plan",
        };

        formatter.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        kind: TaskKind,
        priority: TaskPriority,
        target: TaskTarget,
        now: Instant,
    ) -> TaskRequest {
        TaskRequest {
            kind,
            priority,
            target,
            requested_at: now,
        }
    }

    fn budget() -> TaskBudget {
        TaskBudget {
            max_runtime: Duration::from_secs(10),
            min_interval: Duration::from_secs(30),
        }
    }

    #[test]
    fn only_registered_task_kinds_are_externally_schedulable() {
        assert!(TaskKind::ProcessInspection.is_implemented());
        assert!(TaskKind::NetworkInspection.is_implemented());
        assert!(TaskKind::SignatureVerification.is_implemented());
        assert!(!TaskKind::BaselineComparison.is_implemented());
        assert!(!TaskKind::RepairPlan.is_implemented());
    }

    #[test]
    fn critical_tasks_run_before_background_tasks() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(10);

        scheduler.enqueue(
            request(
                TaskKind::ResourceSample,
                TaskPriority::Background,
                TaskTarget::System,
                now,
            ),
            budget(),
            now,
        );

        scheduler.enqueue(
            request(
                TaskKind::ProcessInspection,
                TaskPriority::Critical,
                TaskTarget::Process(4455),
                now,
            ),
            budget(),
            now,
        );

        let next = scheduler.dequeue().unwrap();

        assert_eq!(next.request.kind, TaskKind::ProcessInspection);
    }

    #[test]
    fn identical_pending_tasks_are_coalesced() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(10);

        let task = request(
            TaskKind::NetworkInspection,
            TaskPriority::Normal,
            TaskTarget::Process(100),
            now,
        );

        assert_eq!(
            scheduler.enqueue(task.clone(), budget(), now),
            ScheduleDecision::Enqueued
        );

        assert_eq!(
            scheduler.enqueue(task, budget(), now),
            ScheduleDecision::Coalesced
        );

        assert_eq!(scheduler.stats().queued, 1);
        assert_eq!(scheduler.stats().coalesced, 1);
    }

    #[test]
    fn cooldown_prevents_repeated_work() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(10);

        let task = request(
            TaskKind::DefenderStatus,
            TaskPriority::Normal,
            TaskTarget::System,
            now,
        );

        scheduler.enqueue(task.clone(), budget(), now);

        let running = scheduler.dequeue().unwrap();

        scheduler.complete(&running, now);

        assert_eq!(
            scheduler.enqueue(task, budget(), now + Duration::from_secs(5),),
            ScheduleDecision::RejectedCooldown
        );
    }

    #[test]
    fn queue_size_is_bounded() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(1);

        scheduler.enqueue(
            request(
                TaskKind::ResourceSample,
                TaskPriority::Background,
                TaskTarget::System,
                now,
            ),
            budget(),
            now,
        );

        assert_eq!(
            scheduler.enqueue(
                request(
                    TaskKind::ProcessInspection,
                    TaskPriority::High,
                    TaskTarget::Process(1),
                    now,
                ),
                budget(),
                now,
            ),
            ScheduleDecision::RejectedQueueFull
        );
    }

    #[test]
    fn failed_tasks_record_failure_statistics() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(10);

        scheduler.enqueue(
            request(
                TaskKind::DefenderStatus,
                TaskPriority::High,
                TaskTarget::System,
                now,
            ),
            budget(),
            now,
        );

        let task = scheduler.dequeue().expect("task must exist");
        scheduler.fail(&task, now);

        assert_eq!(scheduler.stats().completed, 0);
        assert_eq!(scheduler.stats().failed, 1);
    }

    #[test]
    fn completed_tasks_record_statistics() {
        let now = Instant::now();
        let mut scheduler = TaskScheduler::new(10);

        scheduler.enqueue(
            request(
                TaskKind::BaselineComparison,
                TaskPriority::Normal,
                TaskTarget::System,
                now,
            ),
            budget(),
            now,
        );

        let task = scheduler.dequeue().unwrap();
        scheduler.complete(&task, now);

        assert_eq!(scheduler.stats().completed, 1);
        assert_eq!(scheduler.stats().in_flight, 0);
    }
}
