use crate::ipc::{
    framing::{read_frame, write_frame},
    protocol::{error_response, IpcRequest, IpcResponse},
};
use anyhow::{Context, Result};
use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};
use std::io::{Read, Write};

pub const AXIOS_PIPE_NAME: &str = "axios-core-v1";

pub struct NamedPipeServer {
    listener: LocalSocketListener,
}

impl NamedPipeServer {
    pub fn bind() -> Result<Self> {
        let listener = LocalSocketListener::bind(AXIOS_PIPE_NAME)
            .context("failed to bind AXIOS local IPC pipe")?;

        Ok(Self { listener })
    }

    pub fn accept_once<F>(&self, handler: F) -> Result<()>
    where
        F: FnOnce(IpcRequest) -> IpcResponse,
    {
        let mut stream = self
            .listener
            .accept()
            .context("failed to accept AXIOS IPC connection")?;

        let response = match receive_request(&mut stream) {
            Ok(request) => handler(request),

            Err(error) => error_response("unknown", format!("invalid IPC request: {error}")),
        };

        send_response(&mut stream, &response)
    }
}

pub struct NamedPipeClient;

impl NamedPipeClient {
    pub fn send(request: &IpcRequest) -> Result<IpcResponse> {
        let mut stream = LocalSocketStream::connect(AXIOS_PIPE_NAME)
            .context("failed to connect to AXIOS local IPC pipe")?;

        send_request(&mut stream, request)?;

        receive_response(&mut stream)
    }
}

pub fn receive_request(stream: &mut (impl Read + Write)) -> Result<IpcRequest> {
    let payload = read_frame(stream)?;

    serde_json::from_slice(&payload).context("failed to decode IPC request JSON")
}

pub fn send_request(stream: &mut (impl Read + Write), request: &IpcRequest) -> Result<()> {
    let payload = serde_json::to_vec(request).context("failed to encode IPC request JSON")?;

    write_frame(stream, &payload)
}

pub fn receive_response(stream: &mut (impl Read + Write)) -> Result<IpcResponse> {
    let payload = read_frame(stream)?;

    serde_json::from_slice(&payload).context("failed to decode IPC response JSON")
}

pub fn send_response(stream: &mut (impl Read + Write), response: &IpcResponse) -> Result<()> {
    let payload = serde_json::to_vec(response).context("failed to encode IPC response JSON")?;

    write_frame(stream, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::{IpcCommand, IPC_PROTOCOL_VERSION};
    use crate::runtime::scheduler::{TaskKind, TaskPriority, TaskTarget};
    use std::io::Cursor;

    fn request() -> IpcRequest {
        IpcRequest {
            version: IPC_PROTOCOL_VERSION,
            request_id: "test-request".to_string(),
            issued_at: "2026-08-01T00:00:00Z".to_string(),
            authorization_token: "token".to_string(),
            command: IpcCommand::QueueTask {
                kind: TaskKind::ProcessInspection,
                priority: TaskPriority::High,
                target: TaskTarget::Process(1),
            },
        }
    }

    #[test]
    fn request_serializes_into_framed_stream() {
        let request = request();
        let mut stream = Cursor::new(Vec::new());

        send_request(&mut stream, &request).unwrap();

        stream.set_position(0);

        let decoded = receive_request(&mut stream).unwrap();

        assert_eq!(decoded.request_id, "test-request");
    }
}
