use serde::Serialize;
use std::time::Instant;

use crate::system::windows_tools::ExecutionApproval;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum RegistryRunLocation {
    CurrentUserRun,
    CurrentUserRunOnce,
    LocalMachineRun,
    LocalMachineRunOnce,
    LocalMachineWow6432Run,
    LocalMachineWow6432RunOnce,
}

impl RegistryRunLocation {
    fn key_path(self) -> &'static str {
        match self {
            Self::CurrentUserRun => r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            Self::CurrentUserRunOnce => r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            Self::LocalMachineRun => r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            Self::LocalMachineRunOnce => r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            Self::LocalMachineWow6432Run => {
                r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            }
            Self::LocalMachineWow6432RunOnce => {
                r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryRunRemovalState {
    Completed,
    Rejected,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct RegistryRunRemovalResult {
    pub location: RegistryRunLocation,
    pub key_path: String,
    pub value_name: String,
    pub state: RegistryRunRemovalState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
}

pub fn remove_registry_run_value(
    location: RegistryRunLocation,
    value_name: String,
    approval: ExecutionApproval,
) -> RegistryRunRemovalResult {
    let started_at = Instant::now();
    let key_path = location.key_path().to_string();

    if !approval.explicitly_approved {
        return result(
            location,
            key_path,
            value_name,
            RegistryRunRemovalOutcome {
                state: RegistryRunRemovalState::Rejected,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Explicit approval is required.".to_string(),
            },
        );
    }

    if !valid_value_name(&value_name) {
        return result(
            location,
            key_path,
            value_name,
            RegistryRunRemovalOutcome {
                state: RegistryRunRemovalState::Rejected,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Registry value name is invalid.".to_string(),
            },
        );
    }

    #[cfg(windows)]
    {
        let output = std::process::Command::new("reg.exe")
            .args(["delete", &key_path, "/v", &value_name, "/f"])
            .output();

        match output {
            Ok(output) => {
                let success = output.status.success();
                result(
                    location,
                    key_path,
                    value_name,
                    RegistryRunRemovalOutcome {
                        state: if success {
                            RegistryRunRemovalState::Completed
                        } else {
                            RegistryRunRemovalState::Failed
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
                location,
                key_path,
                value_name,
                RegistryRunRemovalOutcome {
                    state: RegistryRunRemovalState::Failed,
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
            location,
            key_path,
            value_name,
            RegistryRunRemovalOutcome {
                state: RegistryRunRemovalState::Unsupported,
                success: false,
                exit_code: None,
                started_at,
                stdout: String::new(),
                stderr: "Registry remediation is only available on Windows.".to_string(),
            },
        )
    }
}

struct RegistryRunRemovalOutcome {
    state: RegistryRunRemovalState,
    success: bool,
    exit_code: Option<i32>,
    started_at: Instant,
    stdout: String,
    stderr: String,
}

fn result(
    location: RegistryRunLocation,
    key_path: String,
    value_name: String,
    outcome: RegistryRunRemovalOutcome,
) -> RegistryRunRemovalResult {
    let RegistryRunRemovalOutcome {
        state,
        success,
        exit_code,
        started_at,
        stdout,
        stderr,
    } = outcome;

    RegistryRunRemovalResult {
        location,
        key_path,
        value_name,
        state,
        success,
        exit_code,
        duration_ms: started_at.elapsed().as_millis(),
        stdout,
        stderr,
    }
}

fn valid_value_name(value_name: &str) -> bool {
    !value_name.trim().is_empty() && value_name.len() <= 16_383 && !value_name.contains('\0')
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
    fn removal_requires_explicit_approval() {
        let result = remove_registry_run_value(
            RegistryRunLocation::CurrentUserRun,
            "AXIOS-Test".to_string(),
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, RegistryRunRemovalState::Rejected);
        assert!(!result.success);
    }

    #[test]
    fn empty_value_name_is_rejected() {
        let result = remove_registry_run_value(
            RegistryRunLocation::CurrentUserRun,
            " ".to_string(),
            ExecutionApproval {
                explicitly_approved: true,
            },
        );

        assert_eq!(result.state, RegistryRunRemovalState::Rejected);
        assert!(!result.success);
    }

    #[test]
    fn registry_run_locations_use_fixed_paths() {
        assert_eq!(
            RegistryRunLocation::CurrentUserRun.key_path(),
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }
}
