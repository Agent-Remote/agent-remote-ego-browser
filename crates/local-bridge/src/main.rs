use std::env;
use std::fs;
use std::future::Future;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ego_browser_bridge::{
    decode_permit_request, parse_permit_request, serialize_permit_response, BridgeConfig,
    BridgeError, BridgeSupervisor,
};
use ego_browser_bridge_protocol::{
    canonical_json, is_dedicated_task_space, parse_runtime_probe_output, parse_strict_json,
    read_frame, write_frame, ConcurrencyMode, CredentialProfile, OuterEnvelope, ReleaseProfile,
    RuntimeProbe, LOCAL_PLATFORM, REMOTE_PLATFORM, SUPPORTED_LOCAL_RUNTIME_VERSION,
    SUPPORTED_SKILL_VERSION,
};
use ego_browser_device::{CredentialError, CredentialStore, DeviceApiClient, DeviceIdentity};
use futures_util::{stream::FuturesUnordered, SinkExt, StreamExt};
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::process::Child;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::header::{HeaderValue, AUTHORIZATION},
        protocol::{Message, WebSocketConfig},
    },
    MaybeTlsStream, WebSocketStream,
};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_RECONNECT_MIN_DELAY: Duration = Duration::from_millis(250);
const RELAY_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const DEVICE_PEER_HEARTBEAT: &[u8] = b"EGB1\n";
const DEVICE_PEER_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);
const DEVICE_PEER_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const TASK_SPACE_MONITOR_POLL_INTERVAL_MS: u64 = 250;
const TASK_SPACE_MONITOR_TAKEOVER_EXIT_CODE: i32 = 73;
const TASK_SPACE_MONITOR_PAUSE_TIMEOUT: Duration = Duration::from_secs(10);
const TASK_SPACE_EXECUTION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportMode {
    UnixSocket,
    Outbound,
}

struct BridgeArgs {
    socket: PathBuf,
    credential_dir: PathBuf,
    config: BridgeConfig,
    transport: TransportMode,
    once: bool,
}

#[tokio::main]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--execution-supervisor") {
        match ego_browser_bridge::run_execution_supervisor().await {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!(
                    "ego-browser execution supervisor error={}",
                    error.log_code()
                );
                std::process::exit(125);
            }
        }
    }
    if let Err(error) = run().await {
        eprintln!("ego-browser-bridge error={}", error.log_code());
        std::process::exit(2);
    }
}

async fn run() -> Result<(), BridgeError> {
    let args = parse_args()?;
    if args.transport == TransportMode::Outbound {
        return run_outbound(args).await;
    }
    run_unix_socket(args).await
}

#[derive(Clone, Copy, Debug)]
struct LeaseSnapshot {
    generation: u64,
    lease_until: u64,
    absolute_ttl_until: u64,
    renew_interval_seconds: u64,
    renew_failure_grace_seconds: u64,
}

struct LeaseObserverContext {
    api: DeviceApiClient,
    supervisor: Arc<BridgeSupervisor>,
    config: BridgeConfig,
    store: CredentialStore,
    identity: DeviceIdentity,
}

#[derive(Debug)]
struct RelayTicket {
    path: String,
    token: String,
    expires_at: u64,
}

#[derive(Debug)]
enum RelaySessionOutcome {
    Disconnected,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceServiceSocketIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
enum DevicePeerObserverOutcome {
    Stopped,
    Lost(BridgeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskSpaceMonitorOutcome {
    Stopped,
    TakenOver,
    Unavailable,
}

mod arguments;
mod control_response;
mod device_peer;
mod local_socket;
mod outbound;
mod outbound_validation;
mod relay_session;
mod task_space_monitor;

use arguments::*;
use control_response::*;
use device_peer::*;
use local_socket::*;
use outbound::*;
use outbound_validation::*;
use relay_session::*;
use task_space_monitor::*;

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
