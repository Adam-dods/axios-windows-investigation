use serde::Serialize;
use std::time::Instant;

use crate::system::windows_tools::ExecutionApproval;

#[cfg(windows)]
use crate::command::powershell;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum DefenderScanKind {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenderScanState {
    Completed,
    Rejected,
    Failed,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct DefenderScanResult {
    pub scan_kind: DefenderScanKind,
    pub scan_path: Option<String>,
    pub state: DefenderScanState,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
}

pub fn start_scan(
    scan_kind: DefenderScanKind,
    scan_path: Option<String>,
    approval: ExecutionApproval,
) -> DefenderScanResult {
    let started_at = Instant::now();

    if !approval.explicitly_approved {
        return result(
            scan_kind,
            scan_path,
            DefenderScanState::Rejected,
            false,
            None,
            started_at,
            String::new(),
            "Explicit approval is required.".to_string(),
        );
    }

    let script = match scan_script(scan_kind, scan_path.as_deref()) {
        Ok(script) => script,
        Err(error) => {
            return result(
                scan_kind,
                scan_path,
                DefenderScanState::Rejected,
                false,
                None,
                started_at,
                String::new(),
                error,
            );
        }
    };

    #[cfg(windows)]
    {
        match powershell(&script) {
            Ok(command) => {
                let success = command.success;

                result(
                    scan_kind,
                    scan_path,
                    if success {
                        DefenderScanState::Completed
                    } else {
                        DefenderScanState::Failed
                    },
                    success,
                    command.exit_code,
                    started_at,
                    command.stdout,
                    command.stderr,
                )
            }
            Err(error) => result(
                scan_kind,
                scan_path,
                DefenderScanState::Failed,
                false,
                None,
                started_at,
                String::new(),
                error.to_string(),
            ),
        }
    }

    #[cfg(not(windows))]
    {
        let _ = script;

        result(
            scan_kind,
            scan_path,
            DefenderScanState::Unsupported,
            false,
            None,
            started_at,
            String::new(),
            "Defender scanning is only available on Windows.".to_string(),
        )
    }
}

fn scan_script(scan_kind: DefenderScanKind, scan_path: Option<&str>) -> Result<String, String> {
    match scan_kind {
        DefenderScanKind::Quick => {
            if scan_path.is_some() {
                return Err("Quick scans do not accept a path.".to_string());
            }

            Ok("Start-MpScan -ScanType QuickScan".to_string())
        }
        DefenderScanKind::Full => {
            if scan_path.is_some() {
                return Err("Full scans do not accept a path.".to_string());
            }

            Ok("Start-MpScan -ScanType FullScan".to_string())
        }
        DefenderScanKind::Custom => {
            let path = scan_path.ok_or_else(|| "Custom scans require --path.".to_string())?;

            if path.trim().is_empty()
                || path.contains('\0')
                || path.contains('\r')
                || path.contains('\n')
            {
                return Err("Custom scan path is invalid.".to_string());
            }

            let quoted_path = path.replace('\'', "''");

            Ok(format!(
                "Start-MpScan -ScanType CustomScan -ScanPath '{quoted_path}'"
            ))
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "This constructor maps the complete Defender execution result at one boundary."
)]
fn result(
    scan_kind: DefenderScanKind,
    scan_path: Option<String>,
    state: DefenderScanState,
    success: bool,
    exit_code: Option<i32>,
    started_at: Instant,
    stdout: String,
    stderr: String,
) -> DefenderScanResult {
    DefenderScanResult {
        scan_kind,
        scan_path,
        state,
        success,
        exit_code,
        duration_ms: started_at.elapsed().as_millis(),
        stdout,
        stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_scan_requires_a_path() {
        assert!(scan_script(DefenderScanKind::Custom, None).is_err());
    }

    #[test]
    fn quick_scan_rejects_a_path() {
        assert!(scan_script(DefenderScanKind::Quick, Some(r"C:\")).is_err());
    }

    #[test]
    fn custom_scan_quotes_single_quotes() {
        let script = scan_script(
            DefenderScanKind::Custom,
            Some(r"C:\Test Data\Analyst's Files"),
        )
        .unwrap();

        assert!(script.contains("Analyst''s Files"));
    }
}
