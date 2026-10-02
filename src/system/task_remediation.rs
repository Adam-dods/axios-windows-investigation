use serde::Serialize;
use std::time::Instant;

use crate::system::windows_tools::ExecutionApproval;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ScheduledTaskAction {
    Disable,
    Enable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTaskControlState {
    Completed,
    Rejected,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct ScheduledTaskControlResult {
    pub task_name: String,
    pub action: ScheduledTaskAction,
    pub state: ScheduledTaskControlState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
}

pub fn control_scheduled_task(
    task_name: String,
    action: ScheduledTaskAction,
    approval: ExecutionApproval,
) -> ScheduledTaskControlResult {
    let started_at = Instant::now();

    if !approval.explicitly_approved {
        return result(
            task_name,
            action,
            ScheduledTaskControlOutcome {
                state: ScheduledTaskControlState::Rejected,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Explicit approval is required.".to_string(),
            },
        );
    }

    if !valid_task_name(&task_name) {
        return result(
            task_name,
            action,
            ScheduledTaskControlOutcome {
                state: ScheduledTaskControlState::Rejected,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Scheduled task name is invalid.".to_string(),
            },
        );
    }

    #[cfg(windows)]
    {
        let state_argument = match action {
            ScheduledTaskAction::Disable => "/Disable",
            ScheduledTaskAction::Enable => "/Enable",
        };

        let output = std::process::Command::new("schtasks.exe")
            .args(["/Change", "/TN", &task_name, state_argument])
            .output();

        match output {
            Ok(output) => {
                let success = output.status.success();

                result(
                    task_name,
                    action,
                    ScheduledTaskControlOutcome {
                        state: if success {
                            ScheduledTaskControlState::Completed
                        } else {
                            ScheduledTaskControlState::Failed
                        },
                        success,
                        exit_code: output.status.code(),
                        started_at,
                        stdout: decode_output(&output.stdout),
                        stderr: decode_output(&output.stderr),
                    },
                )
            }
            Err(error) => result(
                task_name,
                action,
                ScheduledTaskControlOutcome {
                    state: ScheduledTaskControlState::Failed,
                    success: false,
                    exit_code: None,
                    started_at,
                    stdout: String::new(),
                    stderr: error.to_string(),
                },
            ),
        }
    }

    #[cfg(not(windows))]
    {
        result(
            task_name,
            action,
            ScheduledTaskControlOutcome {
                state: ScheduledTaskControlState::Unsupported,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Scheduled task control is only available on Windows.".to_string(),
            },
        )
    }
}

struct ScheduledTaskControlOutcome {
    state: ScheduledTaskControlState,
    success: bool,
    exit_code: Option<i32>,
    started_at: Instant,
    stdout: String,
    stderr: String,
}

fn result(
    task_name: String,
    action: ScheduledTaskAction,
    outcome: ScheduledTaskControlOutcome,
) -> ScheduledTaskControlResult {
    let ScheduledTaskControlOutcome {
        state,
        success,
        exit_code,
        started_at,
        stdout,
        stderr,
    } = outcome;

    ScheduledTaskControlResult {
        task_name,
        action,
        state,
        success,
        exit_code,
        duration_ms: started_at.elapsed().as_millis(),
        stdout,
        stderr,
    }
}

fn valid_task_name(task_name: &str) -> bool {
    task_name.starts_with('\\')
        && task_name.len() > 1
        && task_name.len() <= 260
        && !task_name.contains('\0')
        && !task_name.contains('"')
        && !task_name.chars().any(char::is_control)
}

#[cfg(windows)]
fn decode_output(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_control_requires_explicit_approval() {
        let result = control_scheduled_task(
            r"\AXIOS-Test".to_string(),
            ScheduledTaskAction::Disable,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, ScheduledTaskControlState::Rejected);
        assert!(!result.success);
    }

    #[test]
    fn task_name_must_be_absolute() {
        let result = control_scheduled_task(
            "AXIOS-Test".to_string(),
            ScheduledTaskAction::Disable,
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.state, ScheduledTaskControlState::Rejected);
        assert!(!result.success);
    }
}
