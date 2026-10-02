use crate::telemetry::{
    etw::providers::KernelProvider,
    timeline::{AxiosEvent, EventCategory, EventSeverity},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEtwEvent {
    pub timestamp: String,
    pub provider: KernelProvider,
    pub event_id: u16,
    pub process_id: u32,
    pub thread_id: u32,
    pub parent_process_id: Option<u32>,
    pub executable: Option<String>,
    pub target: Option<String>,
    pub details: serde_json::Value,
}

pub fn normalize(raw: RawEtwEvent) -> AxiosEvent {
    let risk_score = event_risk_score(&raw);
    let severity = severity_from_score(risk_score);

    AxiosEvent {
        schema_version: 1,
        event_id: format!(
            "etw-{}-{}-{}",
            raw.provider.category(),
            raw.process_id,
            raw.event_id
        ),
        timestamp: raw.timestamp,
        category: category_from_provider(raw.provider),
        severity,
        source: raw.provider.provider_name().to_string(),
        action: format!("{}_event_{}", raw.provider.category(), raw.event_id),
        process_id: Some(raw.process_id),
        parent_process_id: raw.parent_process_id,
        executable: raw.executable,
        target: raw.target,
        success: Some(true),
        risk_score,
        details: serde_json::json!({
            "thread_id": raw.thread_id,
            "provider": raw.provider,
            "raw": raw.details
        }),
    }
}

pub fn event_risk_score(raw: &RawEtwEvent) -> u32 {
    let mut score = 0;

    match raw.provider {
        KernelProvider::Process => {
            if raw
                .executable
                .as_deref()
                .unwrap_or_default()
                .to_lowercase()
                .replace('/', "\\")
                .contains("\\temp\\")
            {
                score += 15;
            }
        }

        KernelProvider::ImageLoad => {
            if raw
                .target
                .as_deref()
                .unwrap_or_default()
                .to_lowercase()
                .ends_with(".sys")
            {
                score += 25;
            }
        }

        KernelProvider::NetworkTcpIp => {
            score += 5;
        }

        KernelProvider::Registry => {
            score += 10;
        }

        KernelProvider::Thread | KernelProvider::DiskIo => {}
    }

    score.min(100)
}

pub fn severity_from_score(score: u32) -> EventSeverity {
    match score {
        0..=9 => EventSeverity::Informational,
        10..=29 => EventSeverity::Low,
        30..=49 => EventSeverity::Medium,
        50..=74 => EventSeverity::High,
        _ => EventSeverity::Critical,
    }
}

fn category_from_provider(provider: KernelProvider) -> EventCategory {
    match provider {
        KernelProvider::Process => EventCategory::Process,
        KernelProvider::Thread => EventCategory::Process,
        KernelProvider::ImageLoad => EventCategory::Driver,
        KernelProvider::DiskIo => EventCategory::Hardware,
        KernelProvider::NetworkTcpIp => EventCategory::Network,
        KernelProvider::Registry => EventCategory::Registry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(provider: KernelProvider) -> RawEtwEvent {
        RawEtwEvent {
            timestamp: "2026-08-01T00:00:00Z".to_string(),
            provider,
            event_id: 1,
            process_id: 1234,
            thread_id: 4321,
            parent_process_id: Some(100),
            executable: None,
            target: None,
            details: serde_json::json!({}),
        }
    }

    #[test]
    fn temp_process_event_is_low_risk() {
        let mut event = raw(KernelProvider::Process);
        event.executable = Some(r"C:\Users\TestUser\AppData\Local\Temp\dropper.exe".to_string());

        let normalized = normalize(event);

        assert_eq!(normalized.risk_score, 15);
        assert_eq!(normalized.severity, EventSeverity::Low);
    }

    #[test]
    fn loaded_driver_has_risk_score() {
        let mut event = raw(KernelProvider::ImageLoad);
        event.target = Some(r"C:\Temp\unknown-driver.sys".to_string());

        let normalized = normalize(event);

        assert_eq!(normalized.risk_score, 25);
        assert_eq!(normalized.severity, EventSeverity::Low);
    }

    #[test]
    fn network_event_is_normalized() {
        let event = raw(KernelProvider::NetworkTcpIp);
        let normalized = normalize(event);

        assert_eq!(normalized.category, EventCategory::Network);
        assert_eq!(normalized.risk_score, 5);
    }
}
