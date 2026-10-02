use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[cfg(windows)]
use std::{process::Command, time::Instant};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolSafety {
    ReadOnly,
    ChangesSystem,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsTool {
    SfcVerifyOnly,
    SfcRepair,
    DismScanHealth,
    DismCheckHealth,
    DismRestoreHealth,
    DefenderQuickScan,
    DefenderFullScan,
    DefenderSignatureUpdate,
    FlushDnsCache,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedToolCommand {
    pub tool: WindowsTool,
    pub safety: ToolSafety,
    pub program: String,
    pub arguments: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionApproval {
    pub explicitly_approved: bool,
}

impl FromStr for WindowsTool {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sfc-verify" => Ok(Self::SfcVerifyOnly),
            "sfc-repair" => Ok(Self::SfcRepair),
            "dism-scan" => Ok(Self::DismScanHealth),
            "dism-check" => Ok(Self::DismCheckHealth),
            "dism-restore" => Ok(Self::DismRestoreHealth),
            "defender-quick" => Ok(Self::DefenderQuickScan),
            "defender-full" => Ok(Self::DefenderFullScan),
            "defender-update" => Ok(Self::DefenderSignatureUpdate),
            "flush-dns" => Ok(Self::FlushDnsCache),
            _ => Err(format!("unknown Windows tool: {value}")),
        }
    }
}

pub fn prepare(tool: WindowsTool) -> PreparedToolCommand {
    match tool {
        WindowsTool::SfcVerifyOnly => PreparedToolCommand {
            tool,
            safety: ToolSafety::ReadOnly,
            program: "sfc.exe".to_string(),
            arguments: vec!["/verifyonly".to_string()],
            description: "Verify protected Windows system files without repairing them."
                .to_string(),
        },

        WindowsTool::SfcRepair => PreparedToolCommand {
            tool,
            safety: ToolSafety::ChangesSystem,
            program: "sfc.exe".to_string(),
            arguments: vec!["/scannow".to_string()],
            description: "Repair protected Windows system files.".to_string(),
        },

        WindowsTool::DismScanHealth => PreparedToolCommand {
            tool,
            safety: ToolSafety::ReadOnly,
            program: "DISM.exe".to_string(),
            arguments: vec![
                "/Online".to_string(),
                "/Cleanup-Image".to_string(),
                "/ScanHealth".to_string(),
            ],
            description: "Scan the Windows component store for corruption.".to_string(),
        },

        WindowsTool::DismCheckHealth => PreparedToolCommand {
            tool,
            safety: ToolSafety::ReadOnly,
            program: "DISM.exe".to_string(),
            arguments: vec![
                "/Online".to_string(),
                "/Cleanup-Image".to_string(),
                "/CheckHealth".to_string(),
            ],
            description: "Check whether Windows already recorded component corruption.".to_string(),
        },

        WindowsTool::DismRestoreHealth => PreparedToolCommand {
            tool,
            safety: ToolSafety::ChangesSystem,
            program: "DISM.exe".to_string(),
            arguments: vec![
                "/Online".to_string(),
                "/Cleanup-Image".to_string(),
                "/RestoreHealth".to_string(),
            ],
            description: "Repair the Windows component store.".to_string(),
        },

        WindowsTool::DefenderQuickScan => PreparedToolCommand {
            tool,
            safety: ToolSafety::ReadOnly,
            program: "powershell.exe".to_string(),
            arguments: vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Start-MpScan -ScanType QuickScan".to_string(),
            ],
            description: "Run Microsoft Defender quick scan.".to_string(),
        },

        WindowsTool::DefenderFullScan => PreparedToolCommand {
            tool,
            safety: ToolSafety::ReadOnly,
            program: "powershell.exe".to_string(),
            arguments: vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Start-MpScan -ScanType FullScan".to_string(),
            ],
            description: "Run Microsoft Defender full scan.".to_string(),
        },

        WindowsTool::DefenderSignatureUpdate => PreparedToolCommand {
            tool,
            safety: ToolSafety::ChangesSystem,
            program: "powershell.exe".to_string(),
            arguments: vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Update-MpSignature".to_string(),
            ],
            description: "Update Microsoft Defender security intelligence.".to_string(),
        },

        WindowsTool::FlushDnsCache => PreparedToolCommand {
            tool,
            safety: ToolSafety::ChangesSystem,
            program: "ipconfig.exe".to_string(),
            arguments: vec!["/flushdns".to_string()],
            description: "Flush the local Windows DNS resolver cache.".to_string(),
        },
    }
}

pub fn may_execute(command: &PreparedToolCommand, approval: ExecutionApproval) -> bool {
    match command.safety {
        ToolSafety::ReadOnly => true,
        ToolSafety::ChangesSystem => approval.explicitly_approved,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolExecutionState {
    BlockedApproval,
    Completed,
    FailedToStart,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionResult {
    pub command: PreparedToolCommand,
    pub state: ToolExecutionState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub stdout: String,
    pub stderr: String,
}

pub fn execute(tool: WindowsTool, approval: ExecutionApproval) -> ToolExecutionResult {
    let command = prepare(tool);

    if !may_execute(&command, approval) {
        return ToolExecutionResult {
            command,
            state: ToolExecutionState::BlockedApproval,
            success: false,
            exit_code: None,
            duration_ms: None,
            stdout: String::new(),
            stderr: "explicit approval is required".to_string(),
        };
    }

    #[cfg(windows)]
    {
        let started = Instant::now();

        match Command::new(&command.program)
            .args(&command.arguments)
            .output()
        {
            Ok(output) => ToolExecutionResult {
                command,
                state: ToolExecutionState::Completed,
                success: output.status.success(),
                exit_code: output.status.code(),
                duration_ms: Some(started.elapsed().as_millis()),
                stdout: bounded_output(&output.stdout),
                stderr: bounded_output(&output.stderr),
            },

            Err(error) => ToolExecutionResult {
                command,
                state: ToolExecutionState::FailedToStart,
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
        ToolExecutionResult {
            command,
            state: ToolExecutionState::UnsupportedPlatform,
            success: false,
            exit_code: None,
            duration_ms: None,
            stdout: String::new(),
            stderr: "Windows-only tool execution".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_tool_is_blocked_without_approval() {
        let result = execute(
            WindowsTool::DismRestoreHealth,
            ExecutionApproval {
                explicitly_approved: false,
            },
        );

        assert_eq!(result.state, ToolExecutionState::BlockedApproval);
        assert!(!result.success);
    }

    #[test]
    fn tool_name_is_parsed_from_fixed_allowlist() {
        assert_eq!(
            "dism-scan".parse::<WindowsTool>().unwrap(),
            WindowsTool::DismScanHealth
        );

        assert!("arbitrary-command".parse::<WindowsTool>().is_err());
    }

    #[test]
    fn sfc_verify_only_does_not_repair() {
        let command = prepare(WindowsTool::SfcVerifyOnly);

        assert_eq!(command.program, "sfc.exe");
        assert_eq!(command.arguments, vec!["/verifyonly"]);
        assert_eq!(command.safety, ToolSafety::ReadOnly);
    }

    #[test]
    fn repair_requires_explicit_approval() {
        let command = prepare(WindowsTool::DismRestoreHealth);

        assert!(!may_execute(
            &command,
            ExecutionApproval {
                explicitly_approved: false
            }
        ));

        assert!(may_execute(
            &command,
            ExecutionApproval {
                explicitly_approved: true
            }
        ));
    }

    #[test]
    fn tool_registry_uses_fixed_arguments() {
        let command = prepare(WindowsTool::DismScanHealth);

        assert_eq!(command.program, "DISM.exe");
        assert!(command.arguments.contains(&"/ScanHealth".to_string()));
    }
}
