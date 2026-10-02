use crate::telemetry::{
    etw::{
        normalize::{normalize, RawEtwEvent},
        providers::{default_providers, EtwProviderConfig, KernelProvider},
    },
    timeline::AxiosEvent,
};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EtwSessionState {
    Stopped,
    Running,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwSessionStatus {
    pub name: String,
    pub state: EtwSessionState,
    pub started_at: Option<String>,
    pub events_received: u64,
    pub events_dropped: u64,
    pub providers: Vec<EtwProviderConfig>,
}

pub struct EtwSession {
    name: String,
    state: EtwSessionState,
    started_at: Option<String>,
    events_received: u64,
    events_dropped: u64,
    providers: Vec<EtwProviderConfig>,
}

impl EtwSession {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: EtwSessionState::Stopped,
            started_at: None,
            events_received: 0,
            events_dropped: 0,
            providers: default_providers(),
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if self.state == EtwSessionState::Running {
            anyhow::bail!("ETW session is already running");
        }

        self.state = EtwSessionState::Running;
        self.started_at = Some(Utc::now().to_rfc3339());

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.state == EtwSessionState::Stopped {
            anyhow::bail!("ETW session is already stopped");
        }

        self.state = EtwSessionState::Stopped;

        Ok(())
    }

    pub fn ingest(&mut self, raw_event: RawEtwEvent) -> Result<AxiosEvent> {
        if self.state != EtwSessionState::Running {
            self.events_dropped += 1;
            anyhow::bail!("ETW session is not running");
        }

        if !self.provider_enabled(raw_event.provider) {
            self.events_dropped += 1;
            anyhow::bail!(
                "ETW provider {} is disabled",
                raw_event.provider.provider_name()
            );
        }

        self.events_received += 1;

        Ok(normalize(raw_event))
    }

    pub fn set_provider(&mut self, provider: KernelProvider, enabled: bool) {
        if let Some(config) = self
            .providers
            .iter_mut()
            .find(|item| item.provider == provider)
        {
            config.enabled = enabled;
            return;
        }

        self.providers.push(EtwProviderConfig {
            provider,
            enabled,
            capture_stack_traces: false,
        });
    }

    pub fn status(&self) -> EtwSessionStatus {
        EtwSessionStatus {
            name: self.name.clone(),
            state: self.state.clone(),
            started_at: self.started_at.clone(),
            events_received: self.events_received,
            events_dropped: self.events_dropped,
            providers: self.providers.clone(),
        }
    }

    fn provider_enabled(&self, provider: KernelProvider) -> bool {
        self.providers
            .iter()
            .any(|config| config.provider == provider && config.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::etw::providers::KernelProvider;

    fn event(provider: KernelProvider) -> RawEtwEvent {
        RawEtwEvent {
            timestamp: "2026-08-01T00:00:00Z".to_string(),
            provider,
            event_id: 1,
            process_id: 123,
            thread_id: 456,
            parent_process_id: Some(1),
            executable: None,
            target: None,
            details: serde_json::json!({}),
        }
    }

    #[test]
    fn session_starts_and_stops() {
        let mut session = EtwSession::new("AXIOS-Kernel");

        session.start().unwrap();

        assert_eq!(session.status().state, EtwSessionState::Running);

        session.stop().unwrap();

        assert_eq!(session.status().state, EtwSessionState::Stopped);
    }

    #[test]
    fn running_session_normalizes_event() {
        let mut session = EtwSession::new("AXIOS-Kernel");
        session.start().unwrap();

        let normalized = session.ingest(event(KernelProvider::Process)).unwrap();

        assert_eq!(normalized.process_id, Some(123));
        assert_eq!(session.status().events_received, 1);
    }

    #[test]
    fn stopped_session_drops_event() {
        let mut session = EtwSession::new("AXIOS-Kernel");

        assert!(session.ingest(event(KernelProvider::Process)).is_err());

        assert_eq!(session.status().events_dropped, 1);
    }

    #[test]
    fn disabled_provider_drops_event() {
        let mut session = EtwSession::new("AXIOS-Kernel");
        session.start().unwrap();

        session.set_provider(KernelProvider::Registry, false);

        assert!(session.ingest(event(KernelProvider::Registry)).is_err());

        assert_eq!(session.status().events_dropped, 1);
    }
}
