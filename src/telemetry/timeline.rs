use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Boot,
    System,
    Process,
    File,
    Registry,
    Network,
    Service,
    Driver,
    Defender,
    Firewall,
    Update,
    Hardware,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxiosEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub timestamp: String,
    pub category: EventCategory,
    pub severity: EventSeverity,
    pub source: String,
    pub action: String,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub executable: Option<String>,
    pub target: Option<String>,
    pub success: Option<bool>,
    pub risk_score: u32,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineSummary {
    pub valid_events: usize,
    pub invalid_events: usize,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub categories: BTreeMap<String, usize>,
    pub severities: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct TimelineRetention {
    pub max_file_bytes: u64,
    pub max_archives: u8,
}

impl Default for TimelineRetention {
    fn default() -> Self {
        Self {
            max_file_bytes: 32 * 1024 * 1024,
            max_archives: 7,
        }
    }
}

pub fn append_event(path: impl AsRef<Path>, event: &AxiosEvent) -> Result<()> {
    append_event_with_retention(path, event, TimelineRetention::default())
}

pub fn append_event_with_retention(
    path: impl AsRef<Path>,
    event: &AxiosEvent,
    retention: TimelineRetention,
) -> Result<()> {
    validate_event(event)?;

    let path = path.as_ref();
    let serialized = serde_json::to_vec(event)?;

    rotate_if_needed(path, serialized.len() as u64 + 1, retention)?;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open timeline {}", path.display()))?;

    let mut writer = BufWriter::new(file);
    writer.write_all(&serialized)?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    Ok(())
}

fn rotate_if_needed(
    path: &Path,
    next_entry_bytes: u64,
    retention: TimelineRetention,
) -> Result<()> {
    let current_bytes = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,

        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect timeline {}", path.display()));
        }
    };

    if current_bytes.saturating_add(next_entry_bytes) <= retention.max_file_bytes.max(1) {
        return Ok(());
    }

    let archive_count = retention.max_archives.max(1);

    remove_if_exists(&archive_path(path, archive_count))?;

    for index in (1..archive_count).rev() {
        let source = archive_path(path, index);
        let destination = archive_path(path, index + 1);

        if source.exists() {
            remove_if_exists(&destination)?;

            fs::rename(&source, &destination)
                .with_context(|| format!("failed to rotate {}", source.display()))?;
        }
    }

    if path.exists() {
        let destination = archive_path(path, 1);

        remove_if_exists(&destination)?;

        fs::rename(path, &destination)
            .with_context(|| format!("failed to rotate active timeline {}", path.display()))?;
    }

    Ok(())
}

fn archive_path(path: &Path, index: u8) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));

    PathBuf::from(value)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),

        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),

        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

pub fn read_events(path: impl AsRef<Path>) -> Result<Vec<AxiosEvent>> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("failed to open timeline {}", path.as_ref().display()))?;

    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed to read timeline line {}", index + 1))?;

        if line.trim().is_empty() {
            continue;
        }

        let event: AxiosEvent = serde_json::from_str(&line)
            .with_context(|| format!("invalid event at line {}", index + 1))?;

        validate_event(&event)
            .with_context(|| format!("invalid event fields at line {}", index + 1))?;

        events.push(event);
    }

    Ok(events)
}

pub fn summarize_file(path: impl AsRef<Path>) -> Result<TimelineSummary> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("failed to open timeline {}", path.as_ref().display()))?;

    let reader = BufReader::new(file);

    let mut valid_events = 0;
    let mut invalid_events = 0;
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut categories = BTreeMap::new();
    let mut severities = BTreeMap::new();

    for line in reader.lines() {
        let line = match line {
            Ok(value) => value,
            Err(_) => {
                invalid_events += 1;
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let event = match serde_json::from_str::<AxiosEvent>(&line) {
            Ok(value) if validate_event(&value).is_ok() => value,
            _ => {
                invalid_events += 1;
                continue;
            }
        };

        valid_events += 1;

        if first_timestamp.is_none() {
            first_timestamp = Some(event.timestamp.clone());
        }

        last_timestamp = Some(event.timestamp.clone());

        *categories
            .entry(category_name(&event.category).to_string())
            .or_insert(0) += 1;

        *severities
            .entry(severity_name(&event.severity).to_string())
            .or_insert(0) += 1;
    }

    Ok(TimelineSummary {
        valid_events,
        invalid_events,
        first_timestamp,
        last_timestamp,
        categories,
        severities,
    })
}

pub fn validate_event(event: &AxiosEvent) -> Result<()> {
    if event.schema_version == 0 {
        anyhow::bail!("schema_version must be greater than zero");
    }

    if event.event_id.trim().is_empty() {
        anyhow::bail!("event_id cannot be empty");
    }

    if event.timestamp.trim().is_empty() {
        anyhow::bail!("timestamp cannot be empty");
    }

    if event.source.trim().is_empty() {
        anyhow::bail!("source cannot be empty");
    }

    if event.action.trim().is_empty() {
        anyhow::bail!("action cannot be empty");
    }

    if event.risk_score > 100 {
        anyhow::bail!("risk_score cannot exceed 100");
    }

    Ok(())
}

fn category_name(category: &EventCategory) -> &'static str {
    match category {
        EventCategory::Boot => "boot",
        EventCategory::System => "system",
        EventCategory::Process => "process",
        EventCategory::File => "file",
        EventCategory::Registry => "registry",
        EventCategory::Network => "network",
        EventCategory::Service => "service",
        EventCategory::Driver => "driver",
        EventCategory::Defender => "defender",
        EventCategory::Firewall => "firewall",
        EventCategory::Update => "update",
        EventCategory::Hardware => "hardware",
        EventCategory::Shutdown => "shutdown",
    }
}

fn severity_name(severity: &EventSeverity) -> &'static str {
    match severity {
        EventSeverity::Informational => "informational",
        EventSeverity::Low => "low",
        EventSeverity::Medium => "medium",
        EventSeverity::High => "high",
        EventSeverity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_event() -> AxiosEvent {
        AxiosEvent {
            schema_version: 1,
            event_id: "event-1".to_string(),
            timestamp: "2026-08-01T10:00:00Z".to_string(),
            category: EventCategory::Process,
            severity: EventSeverity::Medium,
            source: "unit-test".to_string(),
            action: "process_started".to_string(),
            process_id: Some(4000),
            parent_process_id: Some(1000),
            executable: Some(r"C:\Temp\example.exe".to_string()),
            target: None,
            success: Some(true),
            risk_score: 30,
            details: serde_json::json!({
                "command_line": "example.exe"
            }),
        }
    }

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!("axios-{name}-{unique}.jsonl"))
    }

    #[test]
    fn valid_event_passes_validation() {
        assert!(validate_event(&test_event()).is_ok());
    }

    #[test]
    fn excessive_risk_score_is_rejected() {
        let mut event = test_event();
        event.risk_score = 101;

        assert!(validate_event(&event).is_err());
    }

    #[test]
    fn event_can_be_written_and_read() {
        let path = temporary_path("timeline");

        append_event(&path, &test_event()).unwrap();
        let events = read_events(&path).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "event-1");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn timeline_rotates_when_size_limit_is_reached() {
        let path = temporary_path("rotation");

        let retention = TimelineRetention {
            max_file_bytes: 1,
            max_archives: 2,
        };

        append_event_with_retention(&path, &test_event(), retention).unwrap();

        append_event_with_retention(&path, &test_event(), retention).unwrap();

        let archive = archive_path(&path, 1);

        assert!(archive.exists());
        assert_eq!(read_events(&archive).unwrap().len(), 1);
        assert_eq!(read_events(&path).unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
        let _ = std::fs::remove_file(archive_path(&path, 2));
    }

    #[test]
    fn summary_counts_categories_and_severities() {
        let path = temporary_path("summary");

        append_event(&path, &test_event()).unwrap();
        append_event(&path, &test_event()).unwrap();

        let summary = summarize_file(&path).unwrap();

        assert_eq!(summary.valid_events, 2);
        assert_eq!(summary.invalid_events, 0);
        assert_eq!(summary.categories.get("process"), Some(&2));
        assert_eq!(summary.severities.get("medium"), Some(&2));

        let _ = std::fs::remove_file(path);
    }
}
