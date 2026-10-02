use crate::analysis::risk::{assess_process, ProcessFacts};
use crate::models::ProcessRecord;
use sysinfo::System;

pub fn collect(system: &System) -> Vec<ProcessRecord> {
    let mut records: Vec<ProcessRecord> = system
        .processes()
        .iter()
        .map(|(pid, process)| ProcessRecord {
            pid: pid.as_u32(),
            parent_pid: process.parent().map(|parent| parent.as_u32()),
            name: process.name().to_string_lossy().to_string(),
            executable: process.exe().map(|path| path.to_string_lossy().to_string()),
            command: process
                .cmd()
                .iter()
                .map(|value| value.to_string_lossy().to_string())
                .collect(),
            cpu_percent: process.cpu_usage(),
            memory_bytes: process.memory(),
            virtual_memory_bytes: process.virtual_memory(),
            runtime_seconds: process.run_time(),
            status: format!("{:?}", process.status()),
            risk: assess_process(&ProcessFacts {
                executable_path: process.exe().map(|path| path.to_string_lossy().to_string()),
                command_line: process
                    .cmd()
                    .iter()
                    .map(|value| value.to_string_lossy().to_string())
                    .collect::<Vec<String>>()
                    .join(" "),
                signed: None,
                creates_persistence: false,
                opens_listening_port: false,
                creates_system_service: false,
                adds_defender_exclusion: false,
                launches_encoded_powershell: false,
                drops_driver: false,
            }),
        })
        .collect();

    records.sort_by(|left, right| {
        right
            .cpu_percent
            .partial_cmp(&left.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    records
}
