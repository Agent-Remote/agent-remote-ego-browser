//! Local bridge device peer internals.

use super::*;

pub(super) fn inspect_device_service_socket(
    path: &std::path::Path,
) -> Result<DeviceServiceSocketIdentity, BridgeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        BridgeError::ProtocolMessage("device client service socket is unavailable".into())
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(BridgeError::ProtocolMessage(
            "device client service socket metadata is unsafe".into(),
        ));
    }
    Ok(DeviceServiceSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(super) async fn connect_device_service_peer(
    store: &CredentialStore,
) -> Result<UnixStream, BridgeError> {
    let path = store.device_service_socket_path();
    let before = inspect_device_service_socket(&path)?;
    let mut stream =
        tokio::time::timeout(DEVICE_PEER_HEARTBEAT_TIMEOUT, UnixStream::connect(&path))
            .await
            .map_err(|_| {
                BridgeError::ProtocolMessage("device client service connection timed out".into())
            })?
            .map_err(|_| {
                BridgeError::ProtocolMessage("device client service socket is unavailable".into())
            })?;
    verify_peer_uid(&stream)?;
    let after = inspect_device_service_socket(&path)?;
    if before != after {
        return Err(BridgeError::ProtocolMessage(
            "device client service socket changed during connection".into(),
        ));
    }
    read_device_peer_heartbeat(&mut stream, DEVICE_PEER_HEARTBEAT_TIMEOUT).await?;
    Ok(stream)
}

pub(super) async fn read_device_peer_heartbeat<R: AsyncRead + Unpin>(
    stream: &mut R,
    heartbeat_timeout: Duration,
) -> Result<(), BridgeError> {
    let mut heartbeat = [0_u8; DEVICE_PEER_HEARTBEAT.len()];
    tokio::time::timeout(heartbeat_timeout, stream.read_exact(&mut heartbeat))
        .await
        .map_err(|_| BridgeError::ProtocolMessage("device client heartbeat timed out".into()))?
        .map_err(|_| BridgeError::ProtocolMessage("device client heartbeat was lost".into()))?;
    if heartbeat != DEVICE_PEER_HEARTBEAT {
        return Err(BridgeError::ProtocolMessage(
            "device client heartbeat is malformed".into(),
        ));
    }
    Ok(())
}

pub(super) async fn run_device_peer_observer_loop<R, Stop, StopFuture>(
    mut stream: R,
    supervisor: Arc<BridgeSupervisor>,
    store: CredentialStore,
    stop_binding: Stop,
    mut stop: tokio::sync::watch::Receiver<bool>,
    heartbeat_timeout: Duration,
) -> DevicePeerObserverOutcome
where
    R: AsyncRead + Unpin + Send + 'static,
    Stop: FnOnce() -> StopFuture + Send + 'static,
    StopFuture: Future<Output = ()> + Send + 'static,
{
    loop {
        let heartbeat = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return DevicePeerObserverOutcome::Stopped;
                }
                continue;
            }
            result = read_device_peer_heartbeat(&mut stream, heartbeat_timeout) => result,
        };
        if let Err(error) = heartbeat {
            let error =
                fail_closed_device_peer_loss(&supervisor, &store, error, stop_binding).await;
            return DevicePeerObserverOutcome::Lost(error);
        }
    }
}

pub(super) async fn fail_closed_device_peer_loss<Stop, StopFuture>(
    supervisor: &BridgeSupervisor,
    store: &CredentialStore,
    error: BridgeError,
    stop_binding: Stop,
) -> BridgeError
where
    Stop: FnOnce() -> StopFuture,
    StopFuture: Future<Output = ()>,
{
    supervisor.revoke();
    if store.clear_active_binding().is_err() {
        eprintln!("ego-browser-bridge could not clear the active binding after device peer loss");
    }
    stop_binding().await;
    error
}

pub(super) async fn stop_binding_after_peer_loss(
    api: DeviceApiClient,
    binding_id: String,
    generation: u64,
) {
    match tokio::time::timeout(DEVICE_PEER_STOP_TIMEOUT, api.stop(&binding_id, generation)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            eprintln!("ego-browser-bridge could not confirm binding stop after device peer loss");
        }
        Err(_) => {
            eprintln!("ego-browser-bridge binding stop timed out after device peer loss");
        }
    }
}

pub(super) async fn device_peer_task_failure(
    outcome: Result<DevicePeerObserverOutcome, tokio::task::JoinError>,
    supervisor: &BridgeSupervisor,
    store: &CredentialStore,
    api: &DeviceApiClient,
    binding_id: &str,
    generation: u64,
) -> BridgeError {
    if let Ok(DevicePeerObserverOutcome::Lost(error)) = outcome {
        return error;
    }
    let error = BridgeError::ProtocolMessage("device client peer observer stopped".into());
    let stop_api = api.clone();
    let binding_id = binding_id.to_owned();
    fail_closed_device_peer_loss(supervisor, store, error, move || async move {
        stop_binding_after_peer_loss(stop_api, binding_id, generation).await;
    })
    .await
}

pub(super) async fn stop_device_peer_observer(
    stop: tokio::sync::watch::Sender<bool>,
    mut task: tokio::task::JoinHandle<DevicePeerObserverOutcome>,
) {
    stop.send_replace(true);
    if tokio::time::timeout(Duration::from_secs(2), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}
