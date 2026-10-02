use anyhow::{bail, Context, Result};
use axios_core::{
    ipc::{
        named_pipe::NamedPipeClient,
        protocol::{IpcCommand, IpcRequest, IPC_PROTOCOL_VERSION},
    },
    runtime::scheduler::{TaskKind, TaskPriority, TaskTarget},
};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};

const DEFAULT_TOKEN_PATH: &str = r"C:\ProgramData\AXIOS\ipc.token";

#[derive(Parser)]
#[command(
    name = "axios-client",
    version,
    about = "AXIOS local service task client"
)]
struct Cli {
    #[arg(long, default_value = DEFAULT_TOKEN_PATH)]
    token_path: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Stats,

    Queue {
        #[arg(value_enum)]
        task: TaskSelector,

        #[arg(long, value_enum, default_value_t = PrioritySelector::Normal)]
        priority: PrioritySelector,

        #[arg(long)]
        pid: Option<u32>,

        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
enum TaskSelector {
    Process,
    Network,
    Resources,
    Events,
    Metrics,
    Defender,
    Signature,
    Integrity,
}

#[derive(Clone, ValueEnum)]
enum PrioritySelector {
    Background,
    Normal,
    High,
    Critical,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let token = read_token(&cli.token_path)?;

    let command = match cli.command {
        Command::Status => IpcCommand::GetServiceStatus,
        Command::Stats => IpcCommand::GetSchedulerStats,
        Command::Queue {
            task,
            priority,
            pid,
            path,
        } => {
            let (kind, target) = queue_target(task, pid, path)?;

            IpcCommand::QueueTask {
                kind,
                priority: priority.into(),
                target,
            }
        }
    };

    let request = IpcRequest {
        version: IPC_PROTOCOL_VERSION,
        request_id: format!(
            "axios-client-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ),
        issued_at: Utc::now().to_rfc3339(),
        authorization_token: token,
        command,
    };

    let response = NamedPipeClient::send(&request)?;
    println!("{}", serde_json::to_string_pretty(&response)?);

    if !response.success {
        bail!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "AXIOS service rejected the request".to_string())
        );
    }

    Ok(())
}

fn read_token(path: &str) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read IPC token from {path}"))?
        .trim()
        .to_string();

    if token.is_empty() {
        bail!("IPC token is empty");
    }

    Ok(token)
}

fn queue_target(
    task: TaskSelector,
    pid: Option<u32>,
    path: Option<String>,
) -> Result<(TaskKind, TaskTarget)> {
    match task {
        TaskSelector::Process => Ok((
            TaskKind::ProcessInspection,
            TaskTarget::Process(pid.context("process task requires --pid")?),
        )),

        TaskSelector::Network => Ok((TaskKind::NetworkInspection, TaskTarget::System)),

        TaskSelector::Resources => Ok((TaskKind::ResourceSample, TaskTarget::System)),

        TaskSelector::Events => Ok((TaskKind::WindowsEventLog, TaskTarget::System)),

        TaskSelector::Metrics => Ok((TaskKind::WindowsMetrics, TaskTarget::System)),

        TaskSelector::Defender => Ok((TaskKind::DefenderStatus, TaskTarget::System)),

        TaskSelector::Signature => Ok((
            TaskKind::SignatureVerification,
            TaskTarget::File(path.context("signature task requires --path")?),
        )),

        TaskSelector::Integrity => Ok((
            TaskKind::FileIntegrity,
            TaskTarget::File(path.context("integrity task requires --path")?),
        )),
    }
}

impl From<PrioritySelector> for TaskPriority {
    fn from(value: PrioritySelector) -> Self {
        match value {
            PrioritySelector::Background => Self::Background,
            PrioritySelector::Normal => Self::Normal,
            PrioritySelector::High => Self::High,
            PrioritySelector::Critical => Self::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_task_requires_pid() {
        assert!(queue_target(TaskSelector::Process, None, None).is_err());
    }

    #[test]
    fn network_task_uses_system_target() {
        let (kind, target) = queue_target(TaskSelector::Network, None, None).unwrap();

        assert_eq!(kind, TaskKind::NetworkInspection);
        assert_eq!(target, TaskTarget::System);
    }

    #[test]
    fn signature_task_requires_file_path() {
        assert!(queue_target(TaskSelector::Signature, None, None).is_err());
    }
}
