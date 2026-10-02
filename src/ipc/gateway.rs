use crate::{
    ipc::protocol::{
        error_response, success_response, IpcAuthorizationError, IpcCommand, IpcRequest,
        IpcResponse, RequestAuthorizer,
    },
    runtime::{
        scheduler::{
            ScheduleDecision, TaskBudget, TaskKind, TaskPriority, TaskRequest, TaskScheduler,
            TaskTarget,
        },
        workers::default_budget,
    },
};
use std::time::{Duration, Instant};

pub struct CommandGateway {
    authorizer: RequestAuthorizer,
    scheduler: TaskScheduler,
}

impl CommandGateway {
    pub fn new(token: impl Into<String>, queue_size: usize) -> Self {
        Self {
            authorizer: RequestAuthorizer::new(token),
            scheduler: TaskScheduler::new(queue_size),
        }
    }

    pub fn handle(&mut self, request: IpcRequest) -> IpcResponse {
        let request_id = request.request_id.clone();

        if let Err(error) = self.authorizer.authorize(&request) {
            return error_response(request_id, authorization_error_message(error));
        }

        match request.command {
            IpcCommand::QueueTask {
                kind,
                priority,
                target,
            } => {
                if !kind.is_implemented() {
                    return error_response(request_id, "requested task is not implemented");
                }

                let budget = budget_for(kind);

                let decision = self.scheduler.enqueue(
                    TaskRequest {
                        kind,
                        priority,
                        target,
                        requested_at: Instant::now(),
                    },
                    budget,
                    Instant::now(),
                );

                success_response(
                    request_id,
                    serde_json::json!({
                        "decision": schedule_decision_name(decision),
                        "scheduler": self.scheduler.stats()
                    }),
                )
            }

            IpcCommand::GetServiceStatus => success_response(
                request_id,
                serde_json::json!({
                    "service": "running",
                    "scheduler": self.scheduler.stats()
                }),
            ),

            IpcCommand::GetSchedulerStats => {
                success_response(request_id, serde_json::json!(self.scheduler.stats()))
            }

            IpcCommand::GetTimelineSummary { limit } => success_response(
                request_id,
                serde_json::json!({
                    "supported": false,
                    "requested_limit": limit,
                    "reason": "timeline reader is attached by the service layer"
                }),
            ),
        }
    }

    pub fn enqueue_trusted(&mut self, request: TaskRequest) -> ScheduleDecision {
        let kind = request.kind;

        self.scheduler
            .enqueue(request, budget_for(kind), Instant::now())
    }

    pub fn next_task(&mut self) -> Option<crate::runtime::scheduler::ScheduledTask> {
        self.scheduler.dequeue()
    }

    pub fn complete_task(&mut self, task: &crate::runtime::scheduler::ScheduledTask) {
        self.scheduler.complete(task, Instant::now());
    }

    pub fn fail_task(&mut self, task: &crate::runtime::scheduler::ScheduledTask) {
        self.scheduler.fail(task, Instant::now());
    }

    pub fn enqueue_background(&mut self, kind: TaskKind, interval: Duration) -> ScheduleDecision {
        self.scheduler.enqueue(
            TaskRequest {
                kind,
                priority: TaskPriority::Background,
                target: TaskTarget::System,
                requested_at: Instant::now(),
            },
            TaskBudget {
                max_runtime: default_budget(kind),
                min_interval: interval,
            },
            Instant::now(),
        )
    }

    pub fn stats(&self) -> crate::runtime::scheduler::SchedulerStats {
        self.scheduler.stats()
    }
}

fn budget_for(kind: TaskKind) -> TaskBudget {
    let min_interval = match kind {
        TaskKind::ResourceSample => Duration::from_secs(30),
        TaskKind::WindowsMetrics => Duration::from_secs(900),
        TaskKind::WindowsEventLog => Duration::from_secs(120),
        TaskKind::DefenderStatus => Duration::from_secs(900),
        TaskKind::FileIntegrity => Duration::from_secs(900),
        TaskKind::BaselineComparison => Duration::from_secs(900),
        TaskKind::ProcessInspection
        | TaskKind::SignatureVerification
        | TaskKind::NetworkInspection
        | TaskKind::RepairPlan => Duration::from_secs(10),
    };

    TaskBudget {
        max_runtime: default_budget(kind),
        min_interval,
    }
}

fn authorization_error_message(error: IpcAuthorizationError) -> &'static str {
    error.message()
}

fn schedule_decision_name(decision: ScheduleDecision) -> &'static str {
    match decision {
        ScheduleDecision::Enqueued => "enqueued",
        ScheduleDecision::Coalesced => "coalesced",
        ScheduleDecision::RejectedCooldown => "rejected_cooldown",
        ScheduleDecision::RejectedQueueFull => "rejected_queue_full",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::{IpcCommand, IpcRequest, IPC_PROTOCOL_VERSION};

    fn queue_request(id: &str, token: &str, kind: TaskKind) -> IpcRequest {
        IpcRequest {
            version: IPC_PROTOCOL_VERSION,
            request_id: id.to_string(),
            issued_at: "2026-08-01T00:00:00Z".to_string(),
            authorization_token: token.to_string(),
            command: IpcCommand::QueueTask {
                kind,
                priority: TaskPriority::High,
                target: TaskTarget::System,
            },
        }
    }

    #[test]
    fn authenticated_client_can_queue_task() {
        let mut gateway = CommandGateway::new("token", 10);

        let response = gateway.handle(queue_request(
            "request-1",
            "token",
            TaskKind::DefenderStatus,
        ));

        assert!(response.success);
        assert_eq!(response.payload["decision"], serde_json::json!("enqueued"));
    }

    #[test]
    fn invalid_token_cannot_queue_task() {
        let mut gateway = CommandGateway::new("token", 10);

        let response = gateway.handle(queue_request(
            "request-1",
            "wrong",
            TaskKind::DefenderStatus,
        ));

        assert!(!response.success);
        assert_eq!(gateway.stats().queued, 0);
    }

    #[test]
    fn unsupported_task_is_rejected_before_queueing() {
        let mut gateway = CommandGateway::new("token", 10);

        let response = gateway.handle(queue_request(
            "request-1",
            "token",
            TaskKind::BaselineComparison,
        ));

        assert!(!response.success);
        assert_eq!(gateway.stats().queued, 0);
    }

    #[test]
    fn trusted_file_observation_is_queued() {
        let mut gateway = CommandGateway::new("token", 10);

        let decision = gateway.enqueue_trusted(TaskRequest {
            kind: TaskKind::SignatureVerification,
            priority: TaskPriority::High,
            target: TaskTarget::File(r"C:\ProgramData\example.exe".to_string()),
            requested_at: Instant::now(),
        });

        assert_eq!(decision, ScheduleDecision::Enqueued);

        let task = gateway.next_task().expect("task must exist");

        assert_eq!(task.request.kind, TaskKind::SignatureVerification);
    }

    #[test]
    fn queued_task_can_be_taken_by_worker() {
        let mut gateway = CommandGateway::new("token", 10);

        gateway.handle(queue_request(
            "request-1",
            "token",
            TaskKind::ResourceSample,
        ));

        let task = gateway.next_task().unwrap();

        assert_eq!(task.request.kind, TaskKind::ResourceSample);

        gateway.complete_task(&task);

        assert_eq!(gateway.stats().completed, 1);
    }
}
