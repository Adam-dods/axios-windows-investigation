use crate::{
    analysis, network,
    runtime::scheduler::{ScheduledTask, TaskKind, TaskTarget},
    security,
    security::signature,
    storage,
    telemetry::{resources::ResourceSampler, windows_events, windows_metrics},
};
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize)]
pub struct WorkerResult {
    pub task_id: u64,
    pub task_kind: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u128,
    pub budget_exceeded: bool,
    pub success: bool,
    pub payload: Value,
}

pub trait TaskWorker: Send {
    fn kind(&self) -> TaskKind;

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value>;
}

pub struct WorkerRegistry {
    workers: HashMap<TaskKind, Box<dyn TaskWorker>>,
}

impl Default for WorkerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerRegistry {
    pub fn new() -> Self {
        Self {
            workers: HashMap::new(),
        }
    }

    pub fn with_default_workers() -> Self {
        let mut registry = Self::new();

        registry.register(ProcessInspectionWorker);
        registry.register(NetworkInspectionWorker);
        registry.register(ResourceWorker::new());
        registry.register(WindowsMetricsWorker);
        registry.register(WindowsEventLogWorker::new());
        registry.register(DefenderStatusWorker);
        registry.register(FileIntegrityWorker);
        registry.register(SignatureVerificationWorker);

        registry
    }

    pub fn register<W: TaskWorker + 'static>(&mut self, worker: W) {
        self.workers.insert(worker.kind(), Box::new(worker));
    }

    pub fn execute(&mut self, task: &ScheduledTask) -> WorkerResult {
        let started_instant = Instant::now();
        let started_at = Utc::now().to_rfc3339();

        let result: Result<Value> = match self.workers.get_mut(&task.request.kind) {
            Some(worker) => worker.execute(task),
            None => Err(anyhow::anyhow!(
                "no worker registered for {}",
                task.request.kind
            )),
        };

        let duration = started_instant.elapsed();
        let budget_exceeded = duration > task.budget.max_runtime;

        match result {
            Ok(payload) => WorkerResult {
                task_id: task.id,
                task_kind: task.request.kind.to_string(),
                started_at,
                finished_at: Utc::now().to_rfc3339(),
                duration_ms: duration.as_millis(),
                budget_exceeded,
                success: true,
                payload: if budget_exceeded {
                    serde_json::json!({
                        "result": payload,
                        "warning": "task completed after its time budget"
                    })
                } else {
                    payload
                },
            },

            Err(error) => WorkerResult {
                task_id: task.id,
                task_kind: task.request.kind.to_string(),
                started_at,
                finished_at: Utc::now().to_rfc3339(),
                duration_ms: duration.as_millis(),
                budget_exceeded,
                success: false,
                payload: serde_json::json!({
                    "error": error.to_string()
                }),
            },
        }
    }
}

pub struct ProcessInspectionWorker;

impl TaskWorker for ProcessInspectionWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::ProcessInspection
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        let TaskTarget::Process(process_id) = task.request.target else {
            anyhow::bail!("process inspection only accepts a process target");
        };

        let snapshot = storage::snapshot::collect();
        let processes = serde_json::to_value(&snapshot.processes)?;
        let process = processes.as_array().and_then(|items| {
            items.iter().find(|item| {
                item.get("pid")
                    .and_then(Value::as_u64)
                    .map(|pid| pid == u64::from(process_id))
                    .unwrap_or(false)
            })
        });

        let Some(process) = process else {
            return Ok(json!({
                "success": true,
                "process_id": process_id,
                "found": false,
                "reason": "process exited or was not found"
            }));
        };

        let executable_path = process
            .get("executable")
            .and_then(Value::as_str)
            .map(str::to_string);

        let facts = analysis::risk::ProcessFacts {
            executable_path,
            command_line: process_command_line(process),
            signed: None,
            ..Default::default()
        };

        let assessment = analysis::risk::assess_process(&facts);

        Ok(json!({
            "success": true,
            "process_id": process_id,
            "found": true,
            "process": process,
            "assessment": assessment
        }))
    }
}

fn process_command_line(process: &Value) -> String {
    if let Some(command_line) = process.get("command_line").and_then(Value::as_str) {
        return command_line.to_string();
    }

    process
        .get("command")
        .and_then(Value::as_array)
        .map(|arguments| {
            arguments
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

pub struct NetworkInspectionWorker;

impl TaskWorker for NetworkInspectionWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::NetworkInspection
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        if task.request.target != TaskTarget::System {
            anyhow::bail!("network inspection only accepts a system target");
        }

        Ok(network::collector::collect())
    }
}

pub struct ResourceWorker {
    sampler: ResourceSampler,
}

impl Default for ResourceWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceWorker {
    pub fn new() -> Self {
        Self {
            sampler: ResourceSampler::new(),
        }
    }
}

impl TaskWorker for ResourceWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::ResourceSample
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        if task.request.target != TaskTarget::System {
            anyhow::bail!("resource sampling only accepts a system target");
        }

        let sample = self.sampler.sample(10);

        Ok(serde_json::to_value(sample)?)
    }
}

pub struct WindowsMetricsWorker;

impl TaskWorker for WindowsMetricsWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::WindowsMetrics
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        if task.request.target != TaskTarget::System {
            anyhow::bail!("Windows metrics only accepts a system target");
        }

        Ok(windows_metrics::collect())
    }
}

pub struct WindowsEventLogWorker {
    last_collection: chrono::DateTime<Utc>,
}

impl Default for WindowsEventLogWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsEventLogWorker {
    pub fn new() -> Self {
        Self {
            last_collection: Utc::now() - chrono::Duration::minutes(5),
        }
    }
}

impl TaskWorker for WindowsEventLogWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::WindowsEventLog
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        if task.request.target != TaskTarget::System {
            anyhow::bail!("Windows Event Log only accepts a system target");
        }

        let result = windows_events::collect_since(self.last_collection);

        if windows_events::collection_succeeded(&result) {
            self.last_collection = Utc::now();
        }

        Ok(result)
    }
}

pub struct FileIntegrityWorker;

impl TaskWorker for FileIntegrityWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::FileIntegrity
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        let TaskTarget::File(path) = &task.request.target else {
            anyhow::bail!("file integrity only accepts a file target");
        };

        let path_ref = Path::new(path);

        if !path_ref.is_file() {
            return Ok(serde_json::json!({
                "success": true,
                "path": path,
                "exists": false,
                "status": "file_not_present"
            }));
        }

        Ok(serde_json::json!({
            "success": true,
            "exists": true,
            "fingerprint": security::integrity::fingerprint_file(
                path_ref
            )?
        }))
    }
}

pub struct SignatureVerificationWorker;

impl TaskWorker for SignatureVerificationWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::SignatureVerification
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        let TaskTarget::File(path) = &task.request.target else {
            anyhow::bail!("signature verification only accepts a file target");
        };

        Ok(signature::inspect(path))
    }
}

pub struct DefenderStatusWorker;

impl TaskWorker for DefenderStatusWorker {
    fn kind(&self) -> TaskKind {
        TaskKind::DefenderStatus
    }

    fn execute(&mut self, task: &ScheduledTask) -> Result<Value> {
        if task.request.target != TaskTarget::System {
            anyhow::bail!("Defender status only accepts a system target");
        }

        Ok(security::defender::collect())
    }
}

pub fn default_budget(kind: TaskKind) -> Duration {
    match kind {
        TaskKind::ProcessInspection => Duration::from_secs(25),
        TaskKind::SignatureVerification => Duration::from_secs(5),
        TaskKind::NetworkInspection => Duration::from_secs(10),
        TaskKind::ResourceSample => Duration::from_secs(2),
        TaskKind::WindowsEventLog => Duration::from_secs(10),
        TaskKind::WindowsMetrics => Duration::from_secs(15),
        TaskKind::DefenderStatus => Duration::from_secs(15),
        TaskKind::FileIntegrity => Duration::from_secs(60),
        TaskKind::BaselineComparison => Duration::from_secs(30),
        TaskKind::RepairPlan => Duration::from_secs(30),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::scheduler::{TaskBudget, TaskPriority, TaskRequest};

    struct TestWorker;

    impl TaskWorker for TestWorker {
        fn kind(&self) -> TaskKind {
            TaskKind::BaselineComparison
        }

        fn execute(&mut self, _task: &ScheduledTask) -> Result<Value> {
            Ok(serde_json::json!({
                "worker": "test",
                "status": "complete"
            }))
        }
    }

    fn task() -> ScheduledTask {
        ScheduledTask {
            id: 1,
            request: TaskRequest {
                kind: TaskKind::BaselineComparison,
                priority: TaskPriority::Normal,
                target: TaskTarget::System,
                requested_at: Instant::now(),
            },
            budget: TaskBudget {
                max_runtime: Duration::from_secs(1),
                min_interval: Duration::from_secs(1),
            },
        }
    }

    #[test]
    fn registry_routes_task_to_matching_worker() {
        let mut registry = WorkerRegistry::new();
        registry.register(TestWorker);

        let result = registry.execute(&task());

        assert!(result.success);
        assert_eq!(result.payload["worker"], serde_json::json!("test"));
    }

    #[test]
    fn registry_rejects_missing_worker() {
        let mut registry = WorkerRegistry::new();

        let result = registry.execute(&task());

        assert!(!result.success);
        assert!(result.payload["error"]
            .as_str()
            .unwrap()
            .contains("no worker registered"));
    }

    #[test]
    fn process_command_line_uses_argument_array_when_needed() {
        let process = serde_json::json!({
            "command": ["powershell.exe", "-NoProfile", "-Command", "Get-Date"]
        });

        assert_eq!(
            process_command_line(&process),
            "powershell.exe -NoProfile -Command Get-Date"
        );
    }

    #[test]
    fn worker_budgets_are_focused() {
        assert_eq!(
            default_budget(TaskKind::ResourceSample),
            Duration::from_secs(2)
        );

        assert_eq!(
            default_budget(TaskKind::FileIntegrity),
            Duration::from_secs(60)
        );
    }
}
