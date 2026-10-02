use crate::system::windows_tools::ExecutionApproval;
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::{process::Command, time::Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTerminationState {
    BlockedApproval,
    InvalidTarget,
    Completed,
    FailedToStart,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTerminationResult {
    pub process_id: u32,
    pub state: ProcessTerminationState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub stdout: String,
    pub stderr: String,
}

pub fn terminate_process(process_id: u32, approval: ExecutionApproval) -> ProcessTerminationResult {
    if !approval.explicitly_approved {
        return ProcessTerminationResult {
            process_id,
            state: ProcessTerminationState::BlockedApproval,
            success: false,
            exit_code: None,
            duration_ms: None,
            stdout: String::new(),
            stderr: "explicit approval is required".to_string(),
        };
    }

    if matches!(process_id, 0 | 4) {
        return ProcessTerminationResult {
            process_id,
            state: ProcessTerminationState::InvalidTarget,
            success: false,
            exit_code: None,
            duration_ms: None,
            stdout: String::new(),
            stderr: "the Windows Idle and System processes cannot be terminated".to_string(),
        };
    }

    #[cfg(windows)]
    {
        let started = Instant::now();
        let process_id_text = process_id.to_string();

        match Command::new("taskkill.exe")
            .args(["/PID", &process_id_text, "/T", "/F"])
            .output()
        {
            Ok(output) => ProcessTerminationResult {
                process_id,
                state: ProcessTerminationState::Completed,
                success: output.status.success(),
                exit_code: output.status.code(),
                duration_ms: Some(started.elapsed().as_millis()),
                stdout: bounded_output(&output.stdout),
                stderr: bounded_output(&output.stderr),
            },

            Err(error) => ProcessTerminationResult {
                process_id,
                state: ProcessTerminationState::FailedToStart,
                success: false,
                exit_code: None,
                duration_ms: Some(started.elapsed().as_millis()),
                stdout: String::new(),
                stderr: error.to_string(),
            },
        }
    }

    #[cfg(not(windows))]
    {
        ProcessTerminationResult {
            process_id,
            state: ProcessTerminationState::UnsupportedPlatform,
            success: false,
            exit_code: None,
            duration_ms: None,
            stdout: String::new(),
            stderr: "Windows-only process termination".to_string(),
        }
    }
}

#[cfg(windows)]
fn bounded_output(bytes: &[u8]) -> String {
    const MAX_OUTPUT_BYTES: usize = 64 * 1024;

    let truncated = bytes.len() > MAX_OUTPUT_BYTES;
    let bytes = if truncated {
        &bytes[..MAX_OUTPUT_BYTES]
    } else {
        bytes
    };

    let mut text = String::from_utf8_lossy(bytes).to_string();

    if truncated {
        text.push_str("\n[output truncated]");
    }

    text
}

#[derive(Debug, Clone, Serialize, Deserialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ServiceControlAction {
    Start,
    Stop,
    Disable,
    EnableManual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlState {
    BlockedApproval,
    InvalidTarget,
    Completed,
    FailedToStart,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceControlResult {
    pub service_name: String,
    pub action: ServiceControlAction,
    pub state: ServiceControlState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub stdout: String,
    pub stderr: String,
}

pub fn control_service(
    service_name: String,
    action: ServiceControlAction,
    approval: ExecutionApproval,
) -> ServiceControlResult {
    if !approval.explicitly_approved {
        return service_result(
            service_name,
            action,
            ServiceControlOutcome {
                state: ServiceControlState::BlockedApproval,
                success: false,
                exit_code: None,
                duration_ms: None,
                stdout: String::new(),
                stderr: "explicit approval is required".to_string(),
            },
        );
    }

    if !valid_service_name(&service_name) {
        return service_result(
            service_name,
            action,
            ServiceControlOutcome {
                state: ServiceControlState::InvalidTarget,
                success: false,
                exit_code: None,
                duration_ms: None,
                stdout: String::new(),
                stderr: "service name contains unsupported characters".to_string(),
            },
        );
    }

    #[cfg(windows)]
    {
        let started = Instant::now();
        let mut command = Command::new("sc.exe");

        match action {
            ServiceControlAction::Start => {
                command.args(["start", &service_name]);
            }

            ServiceControlAction::Stop => {
                command.args(["stop", &service_name]);
            }

            ServiceControlAction::Disable => {
                command.args(["config", &service_name, "start=", "disabled"]);
            }

            ServiceControlAction::EnableManual => {
                command.args(["config", &service_name, "start=", "demand"]);
            }
        }

        match command.output() {
            Ok(output) => service_result(
                service_name,
                action,
                ServiceControlOutcome {
                    state: ServiceControlState::Completed,
                    success: output.status.success(),
                    exit_code: output.status.code(),
                    duration_ms: Some(started.elapsed().as_millis()),
                    stdout: bounded_output(&output.stdout),
                    stderr: bounded_output(&output.stderr),
                },
            ),

            Err(error) => service_result(
                service_name,
                action,
                ServiceControlOutcome {
                    state: ServiceControlState::FailedToStart,
                    success: false,
                    exit_code: None,
                    duration_ms: Some(started.elapsed().as_millis()),
                    stdout: String::new(),
                    stderr: error.to_string(),
                },
            ),
        }
    }

    #[cfg(not(windows))]
    {
        service_result(
            service_name,
            action,
            ServiceControlOutcome {
                state: ServiceControlState::UnsupportedPlatform,
                success: false,
                exit_code: None,
                duration_ms: None,
                stdout: String::new(),
                stderr: "Windows-only service control".to_string(),
            },
        )
    }
}

struct ServiceControlOutcome {
    state: ServiceControlState,
    success: bool,
    exit_code: Option<i32>,
    duration_ms: Option<u128>,
    stdout: String,
    stderr: String,
}

fn service_result(
    service_name: String,
    action: ServiceControlAction,
    outcome: ServiceControlOutcome,
) -> ServiceControlResult {
    ServiceControlResult {
        service_name,
        action,
        state: outcome.state,
        success: outcome.success,
        exit_code: outcome.exit_code,
        duration_ms: outcome.duration_ms,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
    }
}

fn valid_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum FirewallProgramAction {
    Block,
    Unblock,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum FirewallDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallCommandResult {
    pub direction: String,
    pub rule_name: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProgramRuleState {
    BlockedApproval,
    InvalidTarget,
    Completed,
    FailedToStart,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallProgramRuleResult {
    pub program_path: String,
    pub action: FirewallProgramAction,
    pub direction: FirewallDirection,
    pub state: FirewallProgramRuleState,
    pub success: bool,
    pub duration_ms: Option<u128>,
    pub commands: Vec<FirewallCommandResult>,
    pub error: Option<String>,
}

pub fn manage_firewall_program_rule(
    program_path: String,
    action: FirewallProgramAction,
    direction: FirewallDirection,
    approval: ExecutionApproval,
) -> FirewallProgramRuleResult {
    if !approval.explicitly_approved {
        return firewall_result(
            program_path,
            action,
            direction,
            FirewallRuleOutcome {
                state: FirewallProgramRuleState::BlockedApproval,
                success: false,
                duration_ms: None,
                commands: Vec::new(),
                error: Some("explicit approval is required".to_string()),
            },
        );
    }

    if !valid_windows_program_path(&program_path) {
        return firewall_result(
            program_path,
            action,
            direction,
            FirewallRuleOutcome {
                state: FirewallProgramRuleState::InvalidTarget,
                success: false,
                duration_ms: None,
                commands: Vec::new(),
                error: Some("program path must be an absolute Windows path".to_string()),
            },
        );
    }

    #[cfg(windows)]
    {
        let started = Instant::now();
        let directions: &[&str] = match direction {
            FirewallDirection::Inbound => &["in"],
            FirewallDirection::Outbound => &["out"],
            FirewallDirection::Both => &["in", "out"],
        };

        let mut commands = Vec::with_capacity(directions.len());

        for direction_value in directions {
            let rule_name = firewall_rule_name(&program_path, direction_value);
            let output = match action {
                FirewallProgramAction::Block => Command::new("netsh.exe")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={rule_name}"),
                        &format!("dir={direction_value}"),
                        "action=block",
                        &format!("program={program_path}"),
                        "enable=yes",
                        "profile=any",
                    ])
                    .output(),

                FirewallProgramAction::Unblock => Command::new("netsh.exe")
                    .args([
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={rule_name}"),
                    ])
                    .output(),
            };

            match output {
                Ok(output) => commands.push(FirewallCommandResult {
                    direction: (*direction_value).to_string(),
                    rule_name,
                    success: output.status.success(),
                    exit_code: output.status.code(),
                    stdout: bounded_output(&output.stdout),
                    stderr: bounded_output(&output.stderr),
                }),

                Err(error) => {
                    return firewall_result(
                        program_path,
                        action,
                        direction,
                        FirewallRuleOutcome {
                            state: FirewallProgramRuleState::FailedToStart,
                            success: false,
                            duration_ms: Some(started.elapsed().as_millis()),
                            commands,
                            error: Some(error.to_string()),
                        },
                    );
                }
            }
        }

        let success = commands.iter().all(|command| command.success);

        firewall_result(
            program_path,
            action,
            direction,
            FirewallRuleOutcome {
                state: FirewallProgramRuleState::Completed,
                success,
                duration_ms: Some(started.elapsed().as_millis()),
                commands,
                error: None,
            },
        )
    }

    #[cfg(not(windows))]
    {
        firewall_result(
            program_path,
            action,
            direction,
            FirewallRuleOutcome {
                state: FirewallProgramRuleState::UnsupportedPlatform,
                success: false,
                duration_ms: None,
                commands: Vec::new(),
                error: Some("Windows-only firewall control".to_string()),
            },
        )
    }
}

struct FirewallRuleOutcome {
    state: FirewallProgramRuleState,
    success: bool,
    duration_ms: Option<u128>,
    commands: Vec<FirewallCommandResult>,
    error: Option<String>,
}

fn firewall_result(
    program_path: String,
    action: FirewallProgramAction,
    direction: FirewallDirection,
    outcome: FirewallRuleOutcome,
) -> FirewallProgramRuleResult {
    let FirewallRuleOutcome {
        state,
        success,
        duration_ms,
        commands,
        error,
    } = outcome;

    FirewallProgramRuleResult {
        program_path,
        action,
        direction,
        state,
        success,
        duration_ms,
        commands,
        error,
    }
}

fn valid_windows_program_path(value: &str) -> bool {
    let bytes = value.as_bytes();

    value.len() > 3
        && value.len() <= 32_767
        && !value.contains('\0')
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'\\') | Some(b'/'))
}

#[cfg(windows)]
fn firewall_rule_name(program_path: &str, direction: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;

    for byte in program_path.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    format!("AXIOS-Program-Block-{hash:016x}-{direction}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_requires_explicit_approval() {
        let result = terminate_process(
            1234,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, ProcessTerminationState::BlockedApproval);
        assert!(!result.success);
    }

    #[test]
    fn firewall_rule_requires_explicit_approval() {
        let result = manage_firewall_program_rule(
            r"C:\Program Files\Example\example.exe".to_string(),
            FirewallProgramAction::Block,
            FirewallDirection::Outbound,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, FirewallProgramRuleState::BlockedApproval);
        assert!(!result.success);
    }

    #[test]
    fn firewall_rule_rejects_relative_paths() {
        let result = manage_firewall_program_rule(
            "example.exe".to_string(),
            FirewallProgramAction::Block,
            FirewallDirection::Both,
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.state, FirewallProgramRuleState::InvalidTarget);
        assert!(!result.success);
    }

    #[test]
    fn service_control_requires_explicit_approval() {
        let result = control_service(
            "ExampleService".to_string(),
            ServiceControlAction::Stop,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, ServiceControlState::BlockedApproval);
        assert!(!result.success);
    }

    #[test]
    fn invalid_service_name_is_rejected() {
        let result = control_service(
            "bad service name".to_string(),
            ServiceControlAction::Disable,
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.state, ServiceControlState::InvalidTarget);
        assert!(!result.success);
    }

    #[test]
    fn protected_system_pid_is_rejected() {
        let result = terminate_process(
            4,
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.state, ProcessTerminationState::InvalidTarget);
        assert!(!result.success);
    }
}
