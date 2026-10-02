use crate::telemetry::timeline::{append_event, AxiosEvent, EventCategory, EventSeverity};
use anyhow::Result;
use chrono::Utc;
use std::{collections::HashMap, path::Path, thread, time::Duration};
use sysinfo::{ProcessesToUpdate, System};

#[derive(Debug, Clone)]
struct KnownProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    executable: Option<String>,
    command_line: String,
}

pub fn monitor_processes(output: impl AsRef<Path>, interval_seconds: u64) -> Result<()> {
    let output = output.as_ref();
    let mut system = System::new_all();
    system.refresh_all();

    let mut previous = collect_process_map(&system);
    let mut sequence: u64 = 0;

    println!("AXIOS process telemetry started: {}", output.display());

    loop {
        thread::sleep(Duration::from_secs(interval_seconds.max(1)));

        system.refresh_processes(ProcessesToUpdate::All, true);

        let current = collect_process_map(&system);

        for (pid, process) in &current {
            if !previous.contains_key(pid) {
                sequence += 1;

                let event = AxiosEvent {
                    schema_version: 1,
                    event_id: format!("process-start-{}-{}", pid, sequence),
                    timestamp: Utc::now().to_rfc3339(),
                    category: EventCategory::Process,
                    severity: initial_severity(process),
                    source: "axios-process-monitor".to_string(),
                    action: "process_started".to_string(),
                    process_id: Some(*pid),
                    parent_process_id: process.parent_pid,
                    executable: process.executable.clone(),
                    target: None,
                    success: Some(true),
                    risk_score: initial_risk_score(process),
                    details: serde_json::json!({
                        "name": process.name,
                        "command_line": process.command_line
                    }),
                };

                append_event(output, &event)?;

                println!("[START] PID={} NAME={}", pid, process.name);
            }
        }

        for (pid, process) in &previous {
            if !current.contains_key(pid) {
                sequence += 1;

                let event = AxiosEvent {
                    schema_version: 1,
                    event_id: format!("process-stop-{}-{}", pid, sequence),
                    timestamp: Utc::now().to_rfc3339(),
                    category: EventCategory::Process,
                    severity: EventSeverity::Informational,
                    source: "axios-process-monitor".to_string(),
                    action: "process_stopped".to_string(),
                    process_id: Some(*pid),
                    parent_process_id: process.parent_pid,
                    executable: process.executable.clone(),
                    target: None,
                    success: Some(true),
                    risk_score: 0,
                    details: serde_json::json!({
                        "name": process.name,
                        "command_line": process.command_line
                    }),
                };

                append_event(output, &event)?;

                println!("[STOP] PID={} NAME={}", pid, process.name);
            }
        }

        previous = current;
    }
}

fn collect_process_map(system: &System) -> HashMap<u32, KnownProcess> {
    system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let process = KnownProcess {
                pid: pid.as_u32(),
                parent_pid: process.parent().map(|parent| parent.as_u32()),
                name: process.name().to_string_lossy().to_string(),
                executable: process.exe().map(|path| path.to_string_lossy().to_string()),
                command_line: process
                    .cmd()
                    .iter()
                    .map(|value| value.to_string_lossy().to_string())
                    .collect::<Vec<String>>()
                    .join(" "),
            };

            (process.pid, process)
        })
        .collect()
}

fn initial_risk_score(process: &KnownProcess) -> u32 {
    let mut score = 0;
    let path = process
        .executable
        .as_deref()
        .unwrap_or_default()
        .to_lowercase()
        .replace('/', "\\");

    let command = process.command_line.to_lowercase();

    if path.contains("\\temp\\") {
        score += 15;
    }

    if path.contains("\\appdata\\roaming\\") {
        score += 10;
    }

    if (command.contains("powershell") || command.contains("pwsh"))
        && (command.contains("-encodedcommand") || command.contains("-enc "))
    {
        score += 30;
    }

    score.min(100)
}

fn initial_severity(process: &KnownProcess) -> EventSeverity {
    match initial_risk_score(process) {
        0..=9 => EventSeverity::Informational,
        10..=29 => EventSeverity::Low,
        30..=49 => EventSeverity::Medium,
        50..=74 => EventSeverity::High,
        _ => EventSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_process_receives_risk_score() {
        let process = KnownProcess {
            pid: 1,
            parent_pid: None,
            name: "unknown.exe".to_string(),
            executable: Some(r"C:\Users\TestUser\AppData\Local\Temp\unknown.exe".to_string()),
            command_line: "unknown.exe".to_string(),
        };

        assert_eq!(initial_risk_score(&process), 15);
        assert_eq!(initial_severity(&process), EventSeverity::Low);
    }

    #[test]
    fn encoded_powershell_is_medium_risk() {
        let process = KnownProcess {
            pid: 2,
            parent_pid: Some(1),
            name: "powershell.exe".to_string(),
            executable: Some(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            ),
            command_line: "powershell.exe -EncodedCommand SQBFAFgA".to_string(),
        };

        assert_eq!(initial_risk_score(&process), 30);
        assert_eq!(initial_severity(&process), EventSeverity::Medium);
    }
}
