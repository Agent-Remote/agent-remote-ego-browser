//! Local bridge relay session internals.

use super::*;

pub(super) async fn open_relay(
    api: &DeviceApiClient,
    ticket: &RelayTicket,
    binding_id: &str,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, BridgeError> {
    if ticket.path != relay_path(binding_id) {
        return Err(BridgeError::ProtocolMessage(
            "relay path does not match binding".into(),
        ));
    }
    // Ticket TTL is deliberately checked again immediately before dialing: a
    // ticket can expire during control-plane parsing or a reconnect backoff.
    if ticket.expires_at <= now_seconds() {
        return Err(BridgeError::LeaseExpired);
    }
    let mut url = reqwest::Url::parse(api.server_url())
        .map_err(|_| BridgeError::ProtocolMessage("server URL is invalid".into()))?;
    let scheme = match url.scheme() {
        "https" => "wss",
        _ => {
            return Err(BridgeError::ProtocolMessage(
                "outbound relay requires HTTPS/WSS".into(),
            ))
        }
    };
    url.set_scheme(scheme)
        .map_err(|_| BridgeError::ProtocolMessage("server URL scheme is invalid".into()))?;
    url.set_path(&ticket.path);
    url.set_query(None);
    url.set_fragment(None);
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| BridgeError::ProtocolMessage("relay request is invalid".into()))?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", ticket.token))
        .map_err(|_| BridgeError::ProtocolMessage("relay authorization is invalid".into()))?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    let connected = tokio::time::timeout(
        RELAY_CONNECT_TIMEOUT,
        connect_async_with_config(request, Some(websocket_config), true),
    )
    .await
    .map_err(|_| BridgeError::ProtocolMessage("relay connection timed out".into()))?
    .map_err(|_| BridgeError::ProtocolMessage("relay connection failed".into()))?;
    Ok(connected.0)
}

pub(super) async fn run_relay_session<S>(
    socket: WebSocketStream<S>,
    supervisor: Arc<BridgeSupervisor>,
    encryption_secret: [u8; 32],
) -> Result<RelaySessionOutcome, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut cancellation = supervisor.cancellation_receiver();
    let maximum_tasks = supervisor.max_parallel_requests().saturating_add(1);
    let (mut sink, mut stream) = socket.split();
    let mut pending = FuturesUnordered::new();
    loop {
        if *cancellation.borrow() {
            cancel_and_reap(&supervisor, &mut pending).await;
            let _ = sink.close().await;
            return Ok(RelaySessionOutcome::Disconnected);
        }
        tokio::select! {
            result = pending.next(), if !pending.is_empty() => {
                let response = match result.expect("guarded non-empty relay task set") {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => {
                        cancel_and_reap(&supervisor, &mut pending).await;
                        let _ = sink.close().await;
                        return Err(error);
                    }
                    Err(_) => {
                        cancel_and_reap(&supervisor, &mut pending).await;
                        let _ = sink.close().await;
                        return Err(BridgeError::ProtocolMessage(
                            "relay execution task failed".into(),
                        ));
                    }
                };
                if *cancellation.borrow() {
                    cancel_and_reap(&supervisor, &mut pending).await;
                    let _ = sink.close().await;
                    return Ok(RelaySessionOutcome::Disconnected);
                }
                let bytes = match canonical_json(&response) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        cancel_and_reap(&supervisor, &mut pending).await;
                        let _ = sink.close().await;
                        return Err(BridgeError::ProtocolMessage(error.to_string()));
                    }
                };
                if sink.send(Message::binary(bytes)).await.is_err() {
                    cancel_and_reap(&supervisor, &mut pending).await;
                    return Err(BridgeError::ProtocolMessage(
                        "relay response send failed".into(),
                    ));
                }
                supervisor.finish_remote_request(&response);
            }
            changed = cancellation.changed() => {
                if changed.is_ok() && *cancellation.borrow() {
                    cancel_and_reap(&supervisor, &mut pending).await;
                    let _ = sink.close().await;
                    return Ok(RelaySessionOutcome::Disconnected);
                }
            }
            message = stream.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        if bytes.len() > MAX_FRAME_BYTES {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            let _ = sink.close().await;
                            return Err(BridgeError::ProtocolMessage("relay frame is too large".into()));
                        }
                        let envelope: OuterEnvelope = match parse_strict_json(&bytes) {
                            Ok(envelope) => envelope,
                            Err(error) => {
                                cancel_and_reap(&supervisor, &mut pending).await;
                                let _ = sink.close().await;
                                return Err(BridgeError::ProtocolMessage(error.to_string()));
                            }
                        };
                        if let Err(error) = envelope.validate(MAX_FRAME_BYTES) {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            let _ = sink.close().await;
                            return Err(BridgeError::Protocol(error));
                        }
                        if envelope.direction != ego_browser_bridge_protocol::Direction::Request {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            let _ = sink.close().await;
                            return Err(BridgeError::ProtocolMessage("invalid relay request envelope".into()));
                        }
                        if envelope.message_type == ego_browser_bridge_protocol::OuterMessageType::Cancel {
                            if let Err(error) = supervisor.cancel_remote_request(&envelope) {
                                cancel_and_reap(&supervisor, &mut pending).await;
                                let _ = sink.close().await;
                                return Err(error);
                            }
                            continue;
                        }
                        if envelope.message_type != ego_browser_bridge_protocol::OuterMessageType::Execute {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            let _ = sink.close().await;
                            return Err(BridgeError::ProtocolMessage("invalid relay request envelope".into()));
                        }
                        if pending.len() >= maximum_tasks {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            let _ = sink.close().await;
                            return Err(BridgeError::ProtocolMessage(
                                "relay exceeded its bounded request window".into(),
                            ));
                        }
                        let request_supervisor = Arc::clone(&supervisor);
                        let execution = match request_supervisor
                            .prepare_remote_execution(envelope, encryption_secret)
                        {
                            Ok(execution) => execution,
                            Err(error) => {
                                cancel_and_reap(&supervisor, &mut pending).await;
                                let _ = sink.close().await;
                                return Err(error);
                            }
                        };
                        pending.push(tokio::spawn(execution));
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            cancel_and_reap(&supervisor, &mut pending).await;
                            return Err(BridgeError::ProtocolMessage("relay pong failed".into()));
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        cancel_and_reap(&supervisor, &mut pending).await;
                        return Ok(RelaySessionOutcome::Disconnected);
                    }
                    Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {
                        cancel_and_reap(&supervisor, &mut pending).await;
                        let _ = sink.close().await;
                        return Err(BridgeError::ProtocolMessage("relay message must be binary".into()));
                    }
                }
            }
        }
    }
}

async fn cancel_and_reap(
    supervisor: &BridgeSupervisor,
    pending: &mut FuturesUnordered<tokio::task::JoinHandle<Result<OuterEnvelope, BridgeError>>>,
) {
    supervisor.cancel();
    while pending.next().await.is_some() {}
    supervisor.clear_remote_requests();
}

pub(super) async fn run_lease_observer_loop(
    context: LeaseObserverContext,
    interval_seconds: u64,
    failure_grace_seconds: u64,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let LeaseObserverContext {
        api,
        supervisor,
        config,
        store,
        identity,
    } = context;
    let mut interval_seconds = interval_seconds.max(1);
    let mut failure_grace_seconds = failure_grace_seconds.max(1);
    let mut delay = Duration::from_secs(interval_seconds);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return; }
            }
            _ = tokio::time::sleep(delay) => {}
        }
        if *stop.borrow() {
            return;
        }
        if verify_policy_snapshot(&store, &config).is_err() {
            supervisor.revoke();
            return;
        }
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            api.renew_binding(
                &config.binding_id,
                config.generation,
                config.allowlist_revision,
                config.learning_bundle_digest.clone(),
            ),
        )
        .await;
        match result {
            Ok(Ok(value)) => match parse_connected_response(&value, &config, &identity) {
                Ok(lease) => {
                    if supervisor
                        .update_lease(
                            lease.generation,
                            lease.lease_until,
                            lease.absolute_ttl_until,
                            true,
                        )
                        .is_err()
                    {
                        supervisor.revoke();
                        return;
                    }
                    interval_seconds = lease.renew_interval_seconds.max(1);
                    failure_grace_seconds = lease.renew_failure_grace_seconds.max(1);
                    delay = Duration::from_secs(interval_seconds);
                }
                Err(_) => {
                    if supervisor
                        .mark_renewal_failed(failure_grace_seconds)
                        .is_err()
                    {
                        return;
                    }
                    delay = Duration::from_secs(1);
                }
            },
            Ok(Err(error)) => {
                if !is_retryable_control_error(&error) {
                    supervisor.revoke();
                    return;
                }
                if supervisor
                    .mark_renewal_failed(failure_grace_seconds)
                    .is_err()
                {
                    return;
                }
                // Retry frequently enough to recover inside the bounded grace
                // window, while keeping the request path fail-closed.
                delay = Duration::from_secs(1);
            }
            Err(_) => {
                if supervisor
                    .mark_renewal_failed(failure_grace_seconds)
                    .is_err()
                {
                    return;
                }
                delay = Duration::from_secs(1);
            }
        }
    }
}
