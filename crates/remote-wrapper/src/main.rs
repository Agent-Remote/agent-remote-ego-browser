use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ego_browser_bridge_protocol::{
    aad_for_outer, canonical_json, decode_b64url, encode_b64url, parse_strict_json, read_frame,
    write_frame, BridgeCapability, ConcurrencyMode, Direction, InnerExecuteRequest,
    InnerExecuteResponse, InnerMessageType, OuterEnvelope, OuterMessageType, RequestPermit,
    RequestScope, SessionCipher, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_PIXELS, MAX_EXECUTE_TIMEOUT_MS,
    MAX_SCRIPT_BYTES, MAX_STDERR_BYTES, MAX_STDOUT_BYTES,
};
use serde::{Deserialize, Serialize};
use tokio::io::{stdin, stdout, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_COUNT: usize = 32;
const DEFAULT_ARTIFACT_RETENTION_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_ARTIFACT_REQUEST_DIRECTORIES: usize = 64;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PermitRequest<'a> {
    protocol: &'static str,
    #[serde(rename = "type")]
    message_type: &'static str,
    startup_nonce: &'a str,
    script_bytes: usize,
    timeout_ms: u64,
    cwd_label: &'a str,
    concurrency_mode: ConcurrencyMode,
    task_space_scope: Option<&'a str>,
    tab_scope: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitResponse {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    status: String,
    permit: Option<RequestPermit>,
    session_key: Option<String>,
    capability: Option<BridgeCapability>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BrokerCommand<'a, T: Serialize> {
    protocol: &'static str,
    #[serde(rename = "type")]
    message_type: String,
    startup_nonce: &'a str,
    payload: &'a T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerResponse {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    status: String,
    response: Option<serde_json::Value>,
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    let result = run().await;
    if let Err(error) = result {
        eprintln!("ego-browser: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), WrapperError> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "--help".to_owned());
    match command.as_str() {
        "nodejs" => execute(args).await,
        "--doctor" => control_command("doctor").await,
        "--reload" => control_command("reload").await,
        "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => Err(WrapperError::Usage),
    }
}

async fn execute(mut args: impl Iterator<Item = String>) -> Result<(), WrapperError> {
    if args.next().is_some() {
        return Err(WrapperError::Usage);
    }
    let script = read_bounded_script().await?;
    let startup_nonce =
        env::var("EGO_BROWSER_BROKER_NONCE").map_err(|_| WrapperError::Unavailable)?;
    if startup_nonce.is_empty() || startup_nonce.len() > 256 {
        return Err(WrapperError::Protocol("invalid broker nonce".into()));
    }
    let timeout_ms = match env::var("EGO_BROWSER_TIMEOUT_MS") {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_EXECUTE_TIMEOUT_MS)
            .ok_or_else(|| WrapperError::Protocol("invalid timeout".into()))?,
        Err(_) => MAX_EXECUTE_TIMEOUT_MS,
    };
    let cwd_label =
        env::var("EGO_BROWSER_CWD_LABEL").unwrap_or_else(|_| "workspace-default".into());
    let mode = parse_mode(env::var("EGO_BROWSER_CONCURRENCY_MODE").ok().as_deref());
    let task_space = env::var("EGO_BROWSER_TASK_SPACE_SCOPE").ok();
    let tab_scope = env::var("EGO_BROWSER_TAB_SCOPE").ok();
    let requested_scope =
        RequestScope::normalized(Some(mode), task_space.as_deref(), tab_scope.as_deref());
    let request = PermitRequest {
        protocol: "ego-browser-bridge-v1",
        message_type: "permit_request",
        startup_nonce: &startup_nonce,
        script_bytes: script.len(),
        timeout_ms,
        cwd_label: &cwd_label,
        concurrency_mode: requested_scope.mode,
        task_space_scope: requested_scope.task_space.as_deref(),
        tab_scope: requested_scope.tab.as_deref(),
    };
    let mut stream = connect_broker().await?;
    send_json(&mut stream, &request).await?;
    let permit_frame = read_frame(&mut stream, MAX_FRAME_BYTES)
        .await
        .map_err(WrapperError::Frame)?
        .ok_or(WrapperError::Disconnected)?;
    let permit_response: PermitResponse = parse_strict_json(&permit_frame)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    validate_permit_response(&permit_response)?;
    let permit = permit_response.permit.ok_or(WrapperError::Unavailable)?;
    let capability = permit_response
        .capability
        .ok_or(WrapperError::Unavailable)?;
    let key_text = permit_response
        .session_key
        .ok_or(WrapperError::Unavailable)?;
    let key_bytes = decode_b64url(&key_text)
        .map_err(|_| WrapperError::Protocol("invalid session key".into()))?;
    if encode_b64url(&key_bytes) != key_text {
        return Err(WrapperError::Protocol(
            "session key is not canonical".into(),
        ));
    }
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| WrapperError::Protocol("invalid session key length".into()))?;
    capability
        .validate()
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    permit
        .validate(&capability, now_millis(), script.len())
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    if permit.concurrency_mode != requested_scope.mode
        || permit.task_space_scope != requested_scope.task_space
        || permit.tab_scope != requested_scope.tab
    {
        return Err(WrapperError::Protocol(
            "permit scope does not match request".into(),
        ));
    }
    let inner = inner_request_from_permit(script, timeout_ms, cwd_label, &permit)?;
    inner
        .validate(&capability)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let plaintext =
        canonical_json(&inner).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let cipher = SessionCipher::new(&key);
    let mut envelope = OuterEnvelope {
        protocol: "ego-browser-bridge-v1".to_owned(),
        channel: "ego_browser_bridge".to_owned(),
        relay_binding_kind: "ego_browser".to_owned(),
        message_type: OuterMessageType::Execute,
        request_id: permit.request_id.clone(),
        binding_id: permit.binding_id.clone(),
        generation: permit.generation,
        sequence: permit.sequence,
        direction: Direction::Request,
        payload_bytes: plaintext.len(),
        nonce: String::new(),
        ciphertext: String::new(),
        auth_tag: String::new(),
        key_wrap: String::new(),
    };
    let aad =
        aad_for_outer(&envelope).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let (nonce, ciphertext, tag) = cipher
        .seal(&plaintext, &aad)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    envelope.payload_bytes = ciphertext.len();
    envelope.nonce = encode_b64url(&nonce);
    envelope.ciphertext = encode_b64url(&ciphertext);
    envelope.auth_tag = encode_b64url(&tag);
    envelope
        .validate(MAX_FRAME_BYTES)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    send_json(&mut stream, &envelope).await?;
    let response_frame = read_frame(&mut stream, MAX_FRAME_BYTES)
        .await
        .map_err(WrapperError::Frame)?
        .ok_or(WrapperError::Disconnected)?;
    let response = decode_response(&response_frame, &cipher, &permit)?;
    emit_response(response).await
}

fn inner_request_from_permit(
    script: Vec<u8>,
    timeout_ms: u64,
    cwd_label: String,
    permit: &RequestPermit,
) -> Result<InnerExecuteRequest, WrapperError> {
    Ok(InnerExecuteRequest {
        protocol: "ego-browser-bridge-v1-inner".to_owned(),
        message_type: InnerMessageType::Execute,
        script: String::from_utf8(script)
            .map_err(|_| WrapperError::Protocol("script must be UTF-8".into()))?,
        timeout_ms,
        cwd_label,
        default_task_space: permit.default_task_space.clone(),
        concurrency_mode: permit.concurrency_mode,
        task_space_scope: permit.task_space_scope.clone(),
        tab_scope: permit.tab_scope.clone(),
        allowlist_revision: permit.allowlist_revision,
        learning_bundle_digest: permit.learning_bundle_digest.clone(),
    })
}

async fn control_command(command: &str) -> Result<(), WrapperError> {
    let mut stream = connect_broker().await?;
    let startup_nonce =
        env::var("EGO_BROWSER_BROKER_NONCE").map_err(|_| WrapperError::Unavailable)?;
    if startup_nonce.is_empty() || startup_nonce.len() > 256 {
        return Err(WrapperError::Protocol("invalid broker nonce".into()));
    }
    let payload = serde_json::json!({"command": command});
    let request = BrokerCommand {
        protocol: "ego-browser-bridge-v1",
        message_type: command.to_owned(),
        startup_nonce: &startup_nonce,
        payload: &payload,
    };
    send_json(&mut stream, &request).await?;
    let frame = read_frame(&mut stream, MAX_FRAME_BYTES)
        .await
        .map_err(WrapperError::Frame)?
        .ok_or(WrapperError::Disconnected)?;
    let response: BrokerResponse =
        parse_strict_json(&frame).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    if response.protocol != "ego-browser-bridge-v1" || response.status != "ok" {
        if let Some(error) = response.error {
            return Err(WrapperError::Status(error));
        }
        return Err(WrapperError::Unavailable);
    }
    if let Some(value) = response.response {
        println!(
            "{}",
            serde_json::to_string(&value)
                .map_err(|error| WrapperError::Protocol(error.to_string()))?
        );
    } else {
        println!("{}", response.message_type);
    }
    Ok(())
}

async fn connect_broker() -> Result<UnixStream, WrapperError> {
    let path = env::var_os("EGO_BROWSER_BROKER_SOCKET").ok_or(WrapperError::Unavailable)?;
    if PathBuf::from(&path).as_os_str().is_empty() {
        return Err(WrapperError::Unavailable);
    }
    UnixStream::connect(path)
        .await
        .map_err(|_| WrapperError::Unavailable)
}

async fn send_json<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), WrapperError> {
    let frame = canonical_json(value).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    write_frame(stream, &frame, MAX_FRAME_BYTES)
        .await
        .map_err(WrapperError::Frame)
}

async fn read_bounded_script() -> Result<Vec<u8>, WrapperError> {
    let mut input = stdin();
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = tokio::io::AsyncReadExt::read(&mut input, &mut buffer)
            .await
            .map_err(|error| WrapperError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > MAX_SCRIPT_BYTES {
            return Err(WrapperError::Protocol(
                "protocol_error: script exceeds 1 MiB".into(),
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn validate_permit_response(response: &PermitResponse) -> Result<(), WrapperError> {
    if response.protocol != "ego-browser-bridge-v1"
        || response.message_type != "permit_response"
        || response.status != "ok"
    {
        if response.error.as_deref() == Some("lease_renewal_required") {
            return Err(WrapperError::LeaseRenewalRequired);
        }
        return Err(WrapperError::Unavailable);
    }
    Ok(())
}

fn parse_mode(value: Option<&str>) -> ConcurrencyMode {
    match value {
        Some("task_space_tab") => ConcurrencyMode::TaskSpaceTab,
        Some("task_space") => ConcurrencyMode::TaskSpace,
        _ => ConcurrencyMode::Binding,
    }
}

fn decode_response(
    frame: &[u8],
    cipher: &SessionCipher,
    permit: &RequestPermit,
) -> Result<InnerExecuteResponse, WrapperError> {
    let envelope: OuterEnvelope =
        parse_strict_json(frame).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    envelope
        .validate(MAX_FRAME_BYTES)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    if envelope.message_type != OuterMessageType::ExecuteResult
        || envelope.direction != Direction::Response
    {
        return Err(WrapperError::Protocol("invalid response envelope".into()));
    }
    if envelope.binding_id != permit.binding_id
        || envelope.generation != permit.generation
        || envelope.request_id != permit.request_id
        || envelope.sequence != permit.sequence
        || envelope.payload_bytes > permit.max_payload_bytes
    {
        return Err(WrapperError::Protocol(
            "response envelope identity mismatch".into(),
        ));
    }
    let (ciphertext, nonce, tag) = envelope
        .decoded_payload()
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let aad =
        aad_for_outer(&envelope).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let plaintext = cipher
        .open(&nonce, &ciphertext, &tag, &aad)
        .map_err(|error| WrapperError::Protocol(error.to_string()))?;
    let response: InnerExecuteResponse =
        parse_strict_json(&plaintext).map_err(|error| WrapperError::Protocol(error.to_string()))?;
    if response.protocol != "ego-browser-bridge-v1-inner"
        || response.message_type != InnerMessageType::ExecuteResult
    {
        return Err(WrapperError::Protocol("invalid inner response".into()));
    }
    if response.request_id != envelope.request_id || response.sequence != envelope.sequence {
        return Err(WrapperError::Protocol("response identity mismatch".into()));
    }
    if response.stdout.len() > MAX_STDOUT_BYTES || response.stderr.len() > MAX_STDERR_BYTES {
        return Err(WrapperError::Protocol(
            "response output exceeds limit".into(),
        ));
    }
    Ok(response)
}

mod artifacts;

use artifacts::*;

fn print_help() {
    println!("ego-browser remote wrapper (official Skill compatible)");
    println!("Usage: ego-browser nodejs <<'EOF' ... EOF");
    println!("       ego-browser --doctor | --reload | --help");
    println!("The wrapper forwards full-trust heredoc execution to an explicitly authorized local Bridge.");
}

#[derive(Debug)]
enum WrapperError {
    Usage,
    Unavailable,
    Disconnected,
    LeaseRenewalRequired,
    Protocol(String),
    Frame(ego_browser_bridge_protocol::FrameError),
    Io(String),
    Status(String),
    Exit(i32),
}

impl std::fmt::Display for WrapperError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "unsupported ego-browser arguments; use nodejs, --doctor, --reload, or --help",
            ),
            Self::Unavailable => formatter.write_str("bridge_unavailable"),
            Self::Disconnected => formatter.write_str("unknown_result: bridge disconnected"),
            Self::LeaseRenewalRequired => formatter.write_str("lease_renewal_required"),
            Self::Protocol(message) => formatter.write_str(message),
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Io(message) => formatter.write_str(message),
            Self::Status(status) => formatter.write_str(status),
            Self::Exit(code) => write!(formatter, "ego-browser exited with code {code}"),
        }
    }
}

impl std::error::Error for WrapperError {}

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
