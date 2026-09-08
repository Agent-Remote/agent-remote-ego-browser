//! Local bridge local socket internals.

use super::*;

pub(super) async fn run_unix_socket(args: BridgeArgs) -> Result<(), BridgeError> {
    let socket = args.socket;
    let config = args.config;
    if socket.as_os_str().is_empty() {
        return Err(BridgeError::ProtocolMessage("--socket is required".into()));
    }
    if config.release_profile == ego_browser_bridge_protocol::ReleaseProfile::CommunityLocalTrust
        && !cfg!(target_os = "macos")
    {
        return Err(BridgeError::ProtocolMessage(
            "community-local-trust bridge must run on macOS".into(),
        ));
    }
    prepare_socket(&socket)?;
    let listener = UnixListener::bind(&socket).map_err(BridgeError::Io)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(BridgeError::Io)?;
    let supervisor = BridgeSupervisor::new(config)?;
    eprintln!("ego-browser-bridge listening on owner-only Unix socket");
    loop {
        let (stream, _) = listener.accept().await.map_err(BridgeError::Io)?;
        let supervisor = Arc::clone(&supervisor);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, supervisor).await {
                eprintln!("ego-browser-bridge connection error={}", error.log_code());
            }
        });
    }
}

fn prepare_socket(path: &PathBuf) -> Result<(), BridgeError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(BridgeError::ProtocolMessage(
                "refusing to replace non-socket path".into(),
            ));
        }
        fs::remove_file(path).map_err(BridgeError::Io)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(BridgeError::Io)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(BridgeError::Io)?;
    }
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    supervisor: Arc<BridgeSupervisor>,
) -> Result<(), BridgeError> {
    verify_peer_uid(&stream)?;
    let first = read_frame(&mut stream, MAX_FRAME_BYTES)
        .await
        .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?
        .ok_or_else(|| BridgeError::ProtocolMessage("connection closed".into()))?;
    let value = decode_permit_request(&first)?;
    validate_development_broker_identity(&value, &supervisor)?;
    let message_type = value
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    match message_type {
        "permit_request" => {
            let (_, request) = parse_permit_request(value)?;
            let (key, permit) = match request.issue(&supervisor) {
                Ok(value) => value,
                Err(error) => {
                    let response = serde_json::json!({
                        "protocol": "ego-browser-bridge-v1",
                        "type": "permit_response",
                        "status": "error",
                        "error": error.to_string(),
                    });
                    send_value(&mut stream, &response).await?;
                    return Ok(());
                }
            };
            let capability = supervisor.capability();
            let response = serialize_permit_response(&permit, &key, &capability)?;
            write_frame(&mut stream, &response, MAX_FRAME_BYTES)
                .await
                .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
            let frame = read_frame(&mut stream, MAX_FRAME_BYTES)
                .await
                .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?
                .ok_or_else(|| {
                    BridgeError::ProtocolMessage("request ended before execution".into())
                })?;
            let envelope: OuterEnvelope = parse_strict_json(&frame)
                .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
            if envelope.request_id != permit.request_id
                || envelope.sequence != permit.sequence
                || envelope.generation != permit.generation
                || envelope.binding_id != permit.binding_id
            {
                return Err(BridgeError::ProtocolMessage(
                    "permit and request identity mismatch".into(),
                ));
            }
            let response = supervisor.execute(envelope, key).await?;
            let bytes = canonical_json(&response)
                .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
            write_frame(&mut stream, &bytes, MAX_FRAME_BYTES)
                .await
                .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
        }
        "doctor" => {
            let response = serde_json::json!({
                "protocol": "ego-browser-bridge-v1",
                "type": "doctor_response",
                "status": "ok",
                "response": {
                    "bridge": "ready",
                    "ego_browser": supervisor.capability().local_ego_browser_runtime_version,
                    "release_profile": supervisor.capability().release_profile,
                    "allowlist_revision": supervisor.capability().allowlist_revision,
                    "learning_bundle_digest": supervisor.capability().learning_bundle_digest,
                }
            });
            send_value(&mut stream, &response).await?;
        }
        "reload" => {
            supervisor.cancel();
            let response = serde_json::json!({
                "protocol": "ego-browser-bridge-v1",
                "type": "reload_response",
                "status": "ok",
                "response": {"cancelled": true}
            });
            send_value(&mut stream, &response).await?;
        }
        _ => {
            return Err(BridgeError::ProtocolMessage(
                "unsupported bridge command".into(),
            ))
        }
    }
    Ok(())
}

fn validate_development_broker_identity(
    value: &serde_json::Value,
    supervisor: &BridgeSupervisor,
) -> Result<(), BridgeError> {
    let object = value
        .as_object()
        .ok_or_else(|| BridgeError::ProtocolMessage("broker request must be an object".into()))?;
    if supervisor.capability().release_profile != ReleaseProfile::DevelopmentLocal
        && supervisor.capability().release_profile != ReleaseProfile::LogicTest
    {
        return Err(BridgeError::ProtocolMessage(
            "local broker adapter is restricted to development profiles".into(),
        ));
    }
    if !supervisor.development_broker_nonce_matches(
        object.get("startup_nonce").and_then(|item| item.as_str()),
    ) {
        return Err(BridgeError::ProtocolMessage(
            "broker startup nonce is invalid".into(),
        ));
    }
    Ok(())
}

async fn send_value(stream: &mut UnixStream, value: &impl Serialize) -> Result<(), BridgeError> {
    let bytes =
        canonical_json(value).map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
    write_frame(stream, &bytes, MAX_FRAME_BYTES)
        .await
        .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))
}

pub(super) fn verify_peer_uid(stream: &UnixStream) -> Result<(), BridgeError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let peer_uid = peer_uid(fd);
        if peer_uid != Some(unsafe { libc::geteuid() }) {
            return Err(BridgeError::ProtocolMessage(
                "peer UID is not authorized".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_uid(fd: std::os::fd::RawFd) -> Option<libc::uid_t> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    (result == 0).then_some(credentials.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(fd: std::os::fd::RawFd) -> Option<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    (result == 0).then_some(uid)
}

#[cfg(not(unix))]
fn peer_uid(_fd: std::os::fd::RawFd) -> Option<u32> {
    None
}
