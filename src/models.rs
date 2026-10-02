use crate::analysis::risk::RiskAssessment;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CommandResult {
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Serialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable: Option<String>,
    pub command: Vec<String>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub runtime_seconds: u64,
    pub status: String,
    pub risk: RiskAssessment,
}

#[derive(Debug, Serialize)]
pub struct AxiosSnapshot {
    pub schema_version: u32,
    pub axios_version: String,
    pub timestamp: String,
    pub system: serde_json::Value,
    pub processes: Vec<ProcessRecord>,
    pub network: serde_json::Value,
    pub services: serde_json::Value,
    pub drivers: serde_json::Value,
    pub security: serde_json::Value,
    pub persistence: serde_json::Value,
}
