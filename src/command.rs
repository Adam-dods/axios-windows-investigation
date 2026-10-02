use crate::models::CommandResult;
use anyhow::{Context, Result};
use std::process::{Command, Stdio};

pub fn powershell(script: &str) -> Result<CommandResult> {
    let configured_script = format!(
        concat!(
            "$axiosUtf8 = [System.Text.UTF8Encoding]::new($false); ",
            "[Console]::InputEncoding = $axiosUtf8; ",
            "[Console]::OutputEncoding = $axiosUtf8; ",
            "$OutputEncoding = $axiosUtf8; ",
            "& chcp.com 65001 *> $null; ",
            "{}"
        ),
        script
    );

    execute(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &configured_script,
        ],
    )
}

fn execute(program: &str, arguments: &[&str]) -> Result<CommandResult> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to execute {program}"))?;

    Ok(CommandResult {
        command: format!("{} {}", program, arguments.join(" ")),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: decode_windows_output(&output.stdout),
        stderr: decode_windows_output(&output.stderr),
    })
}

fn decode_windows_output(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

pub fn parse_json_output(result: CommandResult) -> serde_json::Value {
    if result.success {
        return match serde_json::from_str::<serde_json::Value>(&result.stdout) {
            Ok(value) => value,
            Err(error) => serde_json::json!({
                "success": false,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "error": format!("collector returned invalid JSON: {error}")
            }),
        };
    }

    serde_json::json!({
        "success": false,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": "collector command exited unsuccessfully"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(success: bool, stdout: &str, stderr: &str, exit_code: Option<i32>) -> CommandResult {
        CommandResult {
            command: "test-command".to_string(),
            success,
            exit_code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn valid_json_from_successful_command_is_preserved() {
        let report = parse_json_output(result(
            true,
            r#"{"success":true,"collector":"test"}"#,
            "",
            Some(0),
        ));

        assert_eq!(report["success"], true);
        assert_eq!(report["collector"], "test");
    }

    #[test]
    fn invalid_json_from_successful_command_becomes_failure() {
        let report = parse_json_output(result(true, "not-json", "", Some(0)));

        assert_eq!(report["success"], false);
        assert_eq!(report["exit_code"], 0);
        assert!(report["error"]
            .as_str()
            .unwrap_or("")
            .contains("invalid JSON"));
    }

    #[test]
    fn nonzero_command_never_becomes_successful_report() {
        let report = parse_json_output(result(
            false,
            r#"{"success":true,"collector":"forged"}"#,
            "collector failed",
            Some(1),
        ));

        assert_eq!(report["success"], false);
        assert_eq!(report["exit_code"], 1);
        assert_eq!(report["stderr"], "collector failed");
    }
}
