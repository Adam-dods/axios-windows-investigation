use crate::runtime::scheduler::{TaskKind, TaskPriority, TaskTarget};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use subtle::ConstantTimeEq;

pub const IPC_PROTOCOL_VERSION: u32 = 1;
const MAX_REPLAY_CACHE: usize = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcCommand {
    QueueTask {
        kind: TaskKind,
        priority: TaskPriority,
        target: TaskTarget,
    },

    GetServiceStatus,

    GetSchedulerStats,

    GetTimelineSummary {
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub version: u32,
    pub request_id: String,
    pub issued_at: String,
    pub authorization_token: String,
    pub command: IpcCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub version: u32,
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
    pub payload: serde_json::Value,
}

pub struct RequestAuthorizer {
    token: String,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl RequestAuthorizer {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn authorize(&mut self, request: &IpcRequest) -> Result<(), IpcAuthorizationError> {
        if request.version != IPC_PROTOCOL_VERSION {
            return Err(IpcAuthorizationError::UnsupportedVersion);
        }

        if request.request_id.trim().is_empty() {
            return Err(IpcAuthorizationError::MissingRequestId);
        }

        if !constant_time_equals(&self.token, &request.authorization_token) {
            return Err(IpcAuthorizationError::InvalidToken);
        }

        if self.seen.contains(&request.request_id) {
            return Err(IpcAuthorizationError::ReplayDetected);
        }

        self.remember_request_id(request.request_id.clone());

        Ok(())
    }

    fn remember_request_id(&mut self, request_id: String) {
        self.seen.insert(request_id.clone());
        self.order.push_back(request_id);

        while self.order.len() > MAX_REPLAY_CACHE {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcAuthorizationError {
    UnsupportedVersion,
    MissingRequestId,
    InvalidToken,
    ReplayDetected,
}

impl IpcAuthorizationError {
    pub fn message(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported IPC protocol version",
            Self::MissingRequestId => "request_id is required",
            Self::InvalidToken => "authorization failed",
            Self::ReplayDetected => "replayed request rejected",
        }
    }
}

pub fn success_response(request_id: impl Into<String>, payload: serde_json::Value) -> IpcResponse {
    IpcResponse {
        version: IPC_PROTOCOL_VERSION,
        request_id: request_id.into(),
        success: true,
        error: None,
        payload,
    }
}

pub fn error_response(request_id: impl Into<String>, error: impl Into<String>) -> IpcResponse {
    IpcResponse {
        version: IPC_PROTOCOL_VERSION,
        request_id: request_id.into(),
        success: false,
        error: Some(error.into()),
        payload: serde_json::json!({}),
    }
}

fn constant_time_equals(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(token: &str) -> IpcRequest {
        IpcRequest {
            version: IPC_PROTOCOL_VERSION,
            request_id: "request-001".to_string(),
            issued_at: "2026-08-01T00:00:00Z".to_string(),
            authorization_token: token.to_string(),
            command: IpcCommand::QueueTask {
                kind: TaskKind::ProcessInspection,
                priority: TaskPriority::High,
                target: TaskTarget::Process(1234),
            },
        }
    }

    #[test]
    fn valid_request_is_authorized() {
        let mut authorizer = RequestAuthorizer::new("secret-token");

        assert!(authorizer.authorize(&request("secret-token")).is_ok());
    }

    #[test]
    fn invalid_token_is_rejected() {
        let mut authorizer = RequestAuthorizer::new("secret-token");

        assert_eq!(
            authorizer.authorize(&request("wrong-token")),
            Err(IpcAuthorizationError::InvalidToken)
        );
    }

    #[test]
    fn replayed_request_is_rejected() {
        let mut authorizer = RequestAuthorizer::new("secret-token");
        let request = request("secret-token");

        assert!(authorizer.authorize(&request).is_ok());

        assert_eq!(
            authorizer.authorize(&request),
            Err(IpcAuthorizationError::ReplayDetected)
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut authorizer = RequestAuthorizer::new("secret-token");
        let mut request = request("secret-token");
        request.version = 999;

        assert_eq!(
            authorizer.authorize(&request),
            Err(IpcAuthorizationError::UnsupportedVersion)
        );
    }

    #[test]
    fn error_response_has_safe_shape() {
        let response = error_response("id-1", "blocked");

        assert!(!response.success);
        assert_eq!(response.error.as_deref(), Some("blocked"));
    }
}
