use anyhow::{bail, Result};
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-privilege-surface-review")]
struct Options {
    #[arg(long, default_value_t = 512)]
    max_items: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_items == 0 || options.max_items > 2048 {
        bail!("max-items must be between 1 and 2048");
    }

    let snapshot = collect_snapshot(options.max_items)?;
    let report = build_report(&snapshot);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_snapshot(max_items: usize) -> Result<Value> {
    let script = format!(
        r#"
$ErrorActionPreference = "Stop"

$services = @(
    Get-CimInstance Win32_Service |
        Where-Object {{
            $_.StartName -match "LocalSystem|LocalService|NetworkService"
        }} |
        Select-Object -First {max_items} `
            Name, DisplayName, StartMode, State, StartName, PathName
)

$tasks = @(
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object {{
            $_.Principal.RunLevel -eq "Highest" -or
            $_.Principal.UserId -match "SYSTEM"
        }} |
        Select-Object -First {max_items} `
            TaskName, TaskPath, State,
            @{{Name="RunLevel"; Expression={{ $_.Principal.RunLevel }}}},
            @{{Name="UserId"; Expression={{ $_.Principal.UserId }}}},
            @{{Name="Actions"; Expression={{ @($_.Actions | ForEach-Object {{ $_.Execute }}) }}}}
)

$administrators = @(
    Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop |
        Select-Object -First {max_items} Name, ObjectClass, PrincipalSource
)

[PSCustomObject]@{{
    success = $true
    services = $services
    privileged_tasks = $tasks
    local_administrators = $administrators
    collection_limited = (
        $services.Count -ge {max_items} -or
        $tasks.Count -ge {max_items} -or
        $administrators.Count -ge {max_items}
    )
}} | ConvertTo-Json -Depth 8 -Compress
"#
    );

    let output = powershell(&script)?;
    if !output.success {
        bail!("privilege surface collector failed: {}", output.stderr);
    }

    Ok(parse_json_output(output))
}

#[cfg(not(windows))]
fn collect_snapshot(_max_items: usize) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collection_status": "windows_only"
    }))
}

fn build_report(snapshot: &Value) -> Value {
    let mut artifacts = Vec::new();

    for service in snapshot
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let command = service
            .get("PathName")
            .and_then(Value::as_str)
            .unwrap_or("");

        let path = executable_from_command(command);

        if is_user_writable(&path) {
            artifacts.push(json!({
                "priority": "high",
                "classification": "privileged_user_writable_service",
                "kind": "service",
                "name": service.get("Name").cloned().unwrap_or(Value::Null),
                "path": path,
                "run_as": service.get("StartName").cloned().unwrap_or(Value::Null),
                "reason": "service_runs_with_privileged_account_from_user_writable_path"
            }));
        }
    }

    for task in snapshot
        .get("privileged_tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        for action in task
            .get("Actions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let path = executable_from_command(action.as_str().unwrap_or(""));

            if is_user_writable(&path) {
                artifacts.push(json!({
                    "priority": "high",
                    "classification": "privileged_user_writable_scheduled_task",
                    "kind": "scheduled_task",
                    "name": task.get("TaskName").cloned().unwrap_or(Value::Null),
                    "task_path": task.get("TaskPath").cloned().unwrap_or(Value::Null),
                    "path": path,
                    "run_level": task.get("RunLevel").cloned().unwrap_or(Value::Null),
                    "user_id": task.get("UserId").cloned().unwrap_or(Value::Null),
                    "reason": "scheduled_task_runs_privileged_executable_from_user_writable_path"
                }));
            }
        }
    }

    let high = artifacts
        .iter()
        .filter(|item| item["priority"] == "high")
        .count();

    json!({
        "success": true,
        "collector": "axios_privilege_surface_review",
        "read_only": true,
        "database_used": false,
        "privilege_escalation_confirmed": false,
        "policy": {
            "system_service_alone": "normal_system_context",
            "highest_task_alone": "normal_system_context",
            "privileged_execution_from_user_writable_path": "high_priority_review"
        },
        "summary": {
            "services_examined": snapshot.get("services").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "privileged_tasks_examined": snapshot.get("privileged_tasks").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "local_administrators_observed": snapshot.get("local_administrators").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "high_priority_findings": high,
            "collection_limited": snapshot.get("collection_limited").and_then(Value::as_bool).unwrap_or(false)
        },
        "artifacts": artifacts
    })
}

fn executable_from_command(command: &str) -> String {
    let value = command.trim();

    if let Some(quoted) = value.strip_prefix('"') {
        return quoted.split('"').next().unwrap_or_default().to_string();
    }

    value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn is_user_writable(path: &str) -> bool {
    let value = path.replace('/', "\\").to_ascii_lowercase();

    // Defender platform binaries live under ProgramData for servicing, but
    // the platform directory is ACL-protected and is not a user-writable path.
    if value.contains(r"\programdata\microsoft\windows defender\platform\") {
        return false;
    }

    [
        r"\users\",
        r"\programdata\",
        r"\temp\",
        r"\downloads\",
        r"\appdata\",
    ]
    .iter()
    .any(|marker| value.contains(marker))
        && !value.contains(r"\windows\system32\")
        && !value.contains(r"\program files\windowsapps\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_service_command_extracts_executable() {
        assert_eq!(
            executable_from_command(r#""C:\Users\Test\AppData\Local\a.exe" --service"#),
            r"C:\Users\Test\AppData\Local\a.exe"
        );
    }

    #[test]
    fn defender_platform_path_is_not_treated_as_user_writable() {
        assert!(!is_user_writable(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe"
        ));
    }

    #[test]
    fn system_path_is_not_treated_as_user_writable() {
        assert!(!is_user_writable(r"C:\Windows\System32\svchost.exe"));
        assert!(is_user_writable(r"C:\Users\Test\AppData\Local\tool.exe"));
    }

    #[test]
    fn collector_does_not_hide_privileged_enumeration_failure() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bin/axios-privilege-surface-review.rs"
        ));

        assert!(source.contains("Get-ScheduledTask -ErrorAction Stop"));
        assert!(source.contains("Get-LocalGroupMember -SID \"S-1-5-32-544\" -ErrorAction Stop"));

        let task_suppressed = concat!("Get-ScheduledTask -ErrorAction ", "SilentlyContinue");

        let group_suppressed = concat!(
            "Get-LocalGroupMember -SID \"S-1-5-32-544\" -ErrorAction ",
            "SilentlyContinue"
        );

        assert!(!source.contains(task_suppressed));
        assert!(!source.contains(group_suppressed));
    }
}
