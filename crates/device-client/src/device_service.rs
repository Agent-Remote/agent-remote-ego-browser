//! Local owner-only Device Client service socket.

use super::*;

pub(super) async fn service(store: &CredentialStore) -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = store.device_service_socket_path();
    let listener = prepare_device_service_listener(&socket_path)?;
    let _socket_guard = DeviceServiceSocketGuard(socket_path);
    let mut peers = JoinSet::new();
    let mut metadata_interval = tokio::time::interval(Duration::from_secs(20));
    metadata_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    eprintln!("ego-browser-device service started; waiting for an independent device registration");
    emit_metric("ego_browser_device_service_up", 1, "services", "ready");
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                peers.abort_all();
                emit_metric("ego_browser_device_service_up", 0, "services", "stopped");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if same_user_peer(&stream) {
                    peers.spawn(serve_device_peer_with_store(stream, store.clone()));
                    emit_metric(
                        "ego_browser_device_bridge_peers",
                        peers.len() as u64,
                        "connections",
                        "connected",
                    );
                } else {
                    emit_metric("ego_browser_device_peer_total", 1, "connections", "rejected");
                }
            }
            _ = metadata_interval.tick() => {
                let status = refresh_candidate_metadata(store).await;
                emit_metric("ego_browser_device_refresh_total", 1, "requests", status);
            }
            Some(_) = peers.join_next(), if !peers.is_empty() => {
                emit_metric(
                    "ego_browser_device_bridge_peers",
                    peers.len() as u64,
                    "connections",
                    "disconnected",
                );
            }
        }
    }
}

async fn refresh_candidate_metadata(store: &CredentialStore) -> &'static str {
    let Ok(credential) = store.load(now()) else {
        return "unregistered";
    };
    let Ok(identity) = store.load_identity(
        credential.device_id.clone(),
        credential.release_profile.clone(),
        credential.credential_profile.clone(),
    ) else {
        return "identity_unavailable";
    };
    let Ok(client) = DeviceApiClient::with_identity(&credential, identity) else {
        return "client_unavailable";
    };
    if client.candidates().await.is_ok() {
        "completed"
    } else {
        "control_plane_error"
    }
}

fn emit_metric(name: &'static str, value: u64, unit: &'static str, status: &'static str) {
    eprintln!("{}", metric_event(name, value, unit, status));
}

pub(super) fn metric_event(
    name: &'static str,
    value: u64,
    unit: &'static str,
    status: &'static str,
) -> String {
    serde_json::json!({
        "event": "metric",
        "metric": name,
        "status": status,
        "unit": unit,
        "value": value,
    })
    .to_string()
}

#[cfg(test)]
pub(super) async fn serve_device_peer(stream: UnixStream) {
    serve_device_peer_inner(stream, None).await;
}

pub(super) async fn serve_device_peer_with_store(stream: UnixStream, store: CredentialStore) {
    serve_device_peer_inner(stream, Some(store)).await;
}

async fn serve_device_peer_inner(mut stream: UnixStream, store: Option<CredentialStore>) {
    let mut interval = tokio::time::interval(DEVICE_PEER_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match store
            .as_ref()
            .map(local_peer_admission)
            .unwrap_or(LocalPeerAdmission::Open)
        {
            LocalPeerAdmission::Open => {
                if stream.write_all(DEVICE_PEER_HEARTBEAT).await.is_err() {
                    return;
                }
            }
            LocalPeerAdmission::Closed => {
                // Only an explicit claim may reopen admission.
                if stream
                    .write_all(DEVICE_PEER_ADMISSION_CLOSED)
                    .await
                    .is_err()
                {
                    return;
                }
                return;
            }
            LocalPeerAdmission::Invalid => {
                // Invalid authorization returns EOF rather than a pause signal.
                return;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalPeerAdmission {
    Open,
    Closed,
    Invalid,
}

fn local_peer_admission(store: &CredentialStore) -> LocalPeerAdmission {
    let credential = match store.load(now()) {
        Ok(credential) => credential,
        Err(CredentialError::Missing) => return LocalPeerAdmission::Closed,
        Err(_) => return LocalPeerAdmission::Invalid,
    };
    let binding = match store.load_active_binding(&credential.device_id) {
        Ok(binding) => binding,
        Err(CredentialError::Missing) => return LocalPeerAdmission::Closed,
        Err(_) => return LocalPeerAdmission::Invalid,
    };
    match store.local_admission_is_open(&credential.device_id, &binding) {
        Ok(true) => LocalPeerAdmission::Open,
        Ok(false) => LocalPeerAdmission::Closed,
        Err(_) => LocalPeerAdmission::Invalid,
    }
}

pub(super) fn prepare_device_service_listener(
    path: &std::path::Path,
) -> std::io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "device service socket path is unsafe",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub(super) fn same_user_peer(stream: &UnixStream) -> bool {
    peer_uid(stream.as_raw_fd()) == Some(unsafe { libc::geteuid() })
}

#[cfg(target_os = "linux")]
fn peer_uid(fd: std::os::fd::RawFd) -> Option<libc::uid_t> {
    let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    (result == 0).then_some(credential.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(fd: std::os::fd::RawFd) -> Option<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    (result == 0).then_some(uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_fd: std::os::fd::RawFd) -> Option<u32> {
    None
}

struct DeviceServiceSocketGuard(PathBuf);

impl Drop for DeviceServiceSocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            let _ = fs::remove_file(&self.0);
        }
    }
}
