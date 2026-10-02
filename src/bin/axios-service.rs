#[cfg(windows)]
mod windows_service_host {
    use std::{
        ffi::OsString,
        fs::{create_dir_all, OpenOptions},
        io::Write,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    use axios_core::{
        ipc::{gateway::CommandGateway, named_pipe::NamedPipeServer, protocol::error_response},
        runtime::{
            scheduler::{ScheduledTask, TaskKind, TaskPriority, TaskRequest, TaskTarget},
            workers::{WorkerRegistry, WorkerResult},
        },
        telemetry::timeline::{append_event, AxiosEvent, EventCategory, EventSeverity},
        watchers::{file_policy::WatchImportance, file_watcher::FileWatcherService},
    };
    use chrono::Utc;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "AxiosCore";
    const SERVICE_DISPLAY_NAME: &str = "AXIOS Core Service";
    const TIMELINE_PATH: &str = r"C:\ProgramData\AXIOS\timeline.jsonl";
    const TOKEN_PATH: &str = r"C:\ProgramData\AXIOS\ipc.token";

    define_windows_service!(ffi_service_main, axios_service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn axios_service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run() {
            log_line(&format!("service startup failure: {error}"));
        }
    }

    fn run() -> windows_service::Result<()> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::clone(&stop_requested);

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |event| match event {
                ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                    stop_signal.store(true, Ordering::SeqCst);

                    ServiceControlHandlerResult::NoError
                }

                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })?;

        let token = match load_ipc_token() {
            Some(token) => token,
            None => {
                log_line("service refused to start: IPC token unavailable");

                return Ok(());
            }
        };

        let gateway = Arc::new(Mutex::new(CommandGateway::new(token, 64)));

        start_ipc_listener(Arc::clone(&gateway));

        record_lifecycle_event("service_starting", EventSeverity::Informational);

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PRESHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        record_lifecycle_event("service_running", EventSeverity::Informational);

        let mut workers = WorkerRegistry::with_default_workers();

        let mut file_watcher = match FileWatcherService::windows_default() {
            Ok(watcher) => {
                log_line("selective file watcher started");
                Some(watcher)
            }

            Err(error) => {
                log_line(&format!("file watcher unavailable: {error}"));
                None
            }
        };

        while !stop_requested.load(Ordering::SeqCst) {
            if let Some(watcher) = file_watcher.as_mut() {
                enqueue_file_watch_tasks(&gateway, watcher);
            }

            let task = match gateway.lock() {
                Ok(mut gateway) => gateway.next_task(),
                Err(_) => {
                    log_line("IPC gateway lock poisoned");
                    None
                }
            };

            if let Some(task) = task {
                let result = workers.execute(&task);

                record_worker_result(&task, &result);

                if let Ok(mut gateway) = gateway.lock() {
                    if result.success {
                        gateway.complete_task(&task);
                    } else {
                        gateway.fail_task(&task);
                    }
                }
            }

            thread::sleep(Duration::from_secs(1));
        }

        record_lifecycle_event("service_stopping", EventSeverity::Informational);

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }

    fn start_ipc_listener(gateway: Arc<Mutex<CommandGateway>>) {
        thread::spawn(move || {
            let server = match NamedPipeServer::bind() {
                Ok(server) => server,
                Err(error) => {
                    log_line(&format!("IPC listener startup failure: {error}"));

                    return;
                }
            };

            log_line("AXIOS IPC listener started");

            loop {
                let current_gateway = Arc::clone(&gateway);

                let result = server.accept_once(move |request| {
                    let request_id = request.request_id.clone();

                    match current_gateway.lock() {
                        Ok(mut gateway) => gateway.handle(request),
                        Err(_) => error_response(request_id, "service command gateway unavailable"),
                    }
                });

                if let Err(error) = result {
                    log_line(&format!("IPC listener failure: {error}"));

                    thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }

    fn enqueue_file_watch_tasks(
        gateway: &Arc<Mutex<CommandGateway>>,
        watcher: &mut FileWatcherService,
    ) {
        for watched_task in watcher.poll() {
            let priority = match watched_task.importance {
                WatchImportance::Critical => TaskPriority::Critical,
                WatchImportance::High => TaskPriority::High,
                WatchImportance::Normal => TaskPriority::Normal,
            };

            let kind = watched_task.kind;

            let decision = match gateway.lock() {
                Ok(mut gateway) => gateway.enqueue_trusted(TaskRequest {
                    kind,
                    priority,
                    target: TaskTarget::File(watched_task.path.to_string_lossy().to_string()),
                    requested_at: Instant::now(),
                }),

                Err(_) => {
                    log_line("file watcher gateway lock poisoned");
                    return;
                }
            };

            if decision == axios_core::runtime::scheduler::ScheduleDecision::Enqueued {
                log_line(&format!("file watcher queued {}", kind));
            }
        }
    }

    fn record_worker_result(task: &ScheduledTask, result: &WorkerResult) {
        let severity = if result.success {
            EventSeverity::Informational
        } else {
            EventSeverity::Low
        };

        let event = AxiosEvent {
            schema_version: 1,
            event_id: format!("axios-task-{}-{}", task.request.kind, task.id),
            timestamp: Utc::now().to_rfc3339(),
            category: category_for_task(task.request.kind),
            severity,
            source: "axios-task-engine".to_string(),
            action: task.request.kind.to_string(),
            process_id: Some(std::process::id()),
            parent_process_id: None,
            executable: std::env::current_exe()
                .ok()
                .map(|path| path.to_string_lossy().to_string()),
            target: Some(format!("{:?}", task.request.target)),
            success: Some(result.success),
            risk_score: 0,
            details: serde_json::json!({
                "task": result,
                "budget": {
                    "max_runtime_ms":
                        task.budget.max_runtime.as_millis(),
                    "min_interval_ms":
                        task.budget.min_interval.as_millis()
                }
            }),
        };

        if let Err(error) = append_event(TIMELINE_PATH, &event) {
            log_line(&format!("task result write failure: {error}"));
        }
    }

    fn category_for_task(kind: TaskKind) -> EventCategory {
        match kind {
            TaskKind::ResourceSample | TaskKind::WindowsMetrics => EventCategory::Hardware,

            TaskKind::WindowsEventLog => EventCategory::System,

            TaskKind::DefenderStatus => EventCategory::Defender,

            TaskKind::NetworkInspection => EventCategory::Network,

            TaskKind::FileIntegrity => EventCategory::File,

            TaskKind::ProcessInspection
            | TaskKind::SignatureVerification
            | TaskKind::BaselineComparison
            | TaskKind::RepairPlan => EventCategory::System,
        }
    }

    fn load_ipc_token() -> Option<String> {
        let token = std::fs::read_to_string(TOKEN_PATH).ok()?;
        let token = token.trim().to_string();

        if token.len() < 32 {
            return None;
        }

        Some(token)
    }

    fn record_lifecycle_event(action: &str, severity: EventSeverity) {
        let event = AxiosEvent {
            schema_version: 1,
            event_id: format!(
                "axios-service-{}-{}",
                action,
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ),
            timestamp: Utc::now().to_rfc3339(),
            category: EventCategory::System,
            severity,
            source: "axios-core-service".to_string(),
            action: action.to_string(),
            process_id: Some(std::process::id()),
            parent_process_id: None,
            executable: std::env::current_exe()
                .ok()
                .map(|path| path.to_string_lossy().to_string()),
            target: None,
            success: Some(true),
            risk_score: 0,
            details: serde_json::json!({
                "account": "LocalSystem",
                "service_name": SERVICE_NAME
            }),
        };

        if let Err(error) = append_event(TIMELINE_PATH, &event) {
            log_line(&format!("timeline write failure: {error}"));
        }
    }

    fn log_line(message: &str) {
        let directory = r"C:\ProgramData\AXIOS";
        let logfile = r"C:\ProgramData\AXIOS\axios-service.log";

        if create_dir_all(directory).is_err() {
            return;
        }

        let mut file = match OpenOptions::new().create(true).append(true).open(logfile) {
            Ok(file) => file,
            Err(_) => return,
        };

        let _ = writeln!(file, "{} {}", Utc::now().to_rfc3339(), message);
    }

    #[allow(dead_code)]
    pub const NAME: &str = SERVICE_DISPLAY_NAME;
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_service_host::start()
}

#[cfg(not(windows))]
fn main() {
    println!("AXIOS service is Windows-only. Cross-compile it for Windows.");
}
