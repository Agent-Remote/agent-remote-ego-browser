//! Local bridge outbound internals.

use super::*;

pub(super) async fn run_outbound(args: BridgeArgs) -> Result<(), BridgeError> {
    let mut config = args.config;
    if config.credential_profile != CredentialProfile::CommunityFile {
        return Err(BridgeError::ProtocolMessage(
            "the configured credential profile is not available to this build".into(),
        ));
    }
    if config.release_profile == ReleaseProfile::CommunityLocalTrust && !cfg!(target_os = "macos") {
        return Err(BridgeError::ProtocolMessage(
            "community-local-trust bridge must run on macOS".into(),
        ));
    }
    let runtime = probe_local_runtime(&config.executable).await?;
    if runtime.ego_browser_version != SUPPORTED_LOCAL_RUNTIME_VERSION {
        return Err(BridgeError::ProtocolMessage(
            "EGO_BROWSER_VERSION_MISMATCH: unsupported local ego-browser runtime".into(),
        ));
    }
    config.runtime_version = runtime.ego_browser_version.clone();
    config.ego_lite_version = runtime.ego_browser_version;
    config.skill_version = SUPPORTED_SKILL_VERSION.into();
    let store = CredentialStore::new(args.credential_dir.clone()).map_err(map_credential_error)?;
    let mut announced_wait = false;
    let (credential, active_binding) = loop {
        let credential = match store.load(now_seconds()) {
            Ok(value) => value,
            Err(CredentialError::Missing) if !args.once => {
                if !announced_wait {
                    eprintln!(
                        "ego-browser-bridge waiting for explicit device registration and binding"
                    );
                    announced_wait = true;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
                    signal = tokio::signal::ctrl_c() => {
                        return signal.map_err(|_| BridgeError::ProtocolMessage(
                            "shutdown signal handler failed".into()
                        ));
                    }
                }
            }
            Err(error) => return Err(map_credential_error(error)),
        };
        match store.load_active_binding(&credential.device_id) {
            Ok(binding) => break (credential, binding),
            Err(CredentialError::Missing) if !args.once => {
                if !announced_wait {
                    eprintln!(
                        "ego-browser-bridge waiting for explicit device registration and binding"
                    );
                    announced_wait = true;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
                    signal = tokio::signal::ctrl_c() => {
                        return signal.map_err(|_| BridgeError::ProtocolMessage(
                            "shutdown signal handler failed".into()
                        ));
                    }
                }
            }
            Err(error) => return Err(map_credential_error(error)),
        }
    };
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    if !config.binding_id.is_empty() && config.binding_id != active_binding.binding_id {
        return Err(BridgeError::ProtocolMessage(
            "configured binding does not match the explicit local claim".into(),
        ));
    }
    if config.generation != 1 && config.generation != active_binding.generation {
        return Err(BridgeError::ProtocolMessage(
            "configured generation does not match the explicit local claim".into(),
        ));
    }
    config.binding_id = active_binding.binding_id;
    config.generation = active_binding.generation;
    config.default_task_space = active_binding.task_space_label;
    let (_, policy) = store
        .load_policy(Some(SUPPORTED_SKILL_VERSION), Some(&config.runtime_version))
        .map_err(map_credential_error)?;
    config.apply_verified_policy(&policy);
    let supervisor = BridgeSupervisor::new(config.clone())?;
    let identity = store
        .load_identity(
            credential.device_id.clone(),
            release_profile_name(config.release_profile).into(),
            credential.credential_profile.clone(),
        )
        .map_err(map_credential_error)?;
    if identity.needs_encryption_key_rotation()
        || identity.device_id != credential.device_id
        || identity.credential_profile != credential.credential_profile
        || identity.release_profile != release_profile_name(config.release_profile)
    {
        return Err(BridgeError::ProtocolMessage(
            "device identity requires explicit rotation or profile alignment".into(),
        ));
    }

    let api = DeviceApiClient::with_identity(&credential, identity.clone())
        .map_err(map_credential_error)?;
    let connected_payload = connected_payload(&config, &identity)?;
    let device_peer = match connect_device_service_peer(&store).await {
        Ok(peer) => peer,
        Err(error) => {
            let stop_api = api.clone();
            let binding_id = config.binding_id.clone();
            let generation = config.generation;
            let error =
                fail_closed_device_peer_loss(&supervisor, &store, error, move || async move {
                    stop_binding_after_peer_loss(stop_api, binding_id, generation).await;
                })
                .await;
            return Err(error);
        }
    };
    let (device_stop, device_stop_rx) = tokio::sync::watch::channel(false);
    let peer_supervisor = Arc::clone(&supervisor);
    let peer_store = store.clone();
    let peer_api = api.clone();
    let peer_binding_id = config.binding_id.clone();
    let peer_generation = config.generation;
    let mut device_peer_task = tokio::spawn(async move {
        run_device_peer_observer_loop(
            device_peer,
            peer_supervisor,
            peer_store,
            move || async move {
                stop_binding_after_peer_loss(peer_api, peer_binding_id, peer_generation).await;
            },
            device_stop_rx,
            DEVICE_PEER_HEARTBEAT_TIMEOUT,
        )
        .await
    });

    let activation: Result<Option<LeaseSnapshot>, BridgeError> = tokio::select! {
        biased;
        outcome = &mut device_peer_task => {
            let error = device_peer_task_failure(
                outcome,
                &supervisor,
                &store,
                &api,
                &config.binding_id,
                config.generation,
            ).await;
            return Err(error);
        }
        result = async {
            let connected = api
                .connected(&config.binding_id, config.generation, connected_payload)
                .await
                .map_err(map_credential_error)?;
            let lease = parse_connected_response(&connected, &config, &identity)?;
            supervisor.update_lease(
                lease.generation,
                lease.lease_until,
                lease.absolute_ttl_until,
                true,
            )?;
            Ok(Some(lease))
        } => result,
        signal = &mut shutdown => {
            supervisor.cancel();
            signal
                .map(|()| None)
                .map_err(|_| BridgeError::ProtocolMessage("shutdown signal handler failed".into()))
        }
    };
    let lease = match activation {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            stop_device_peer_observer(device_stop, device_peer_task).await;
            return Ok(());
        }
        Err(error) => {
            supervisor.cancel();
            stop_device_peer_observer(device_stop, device_peer_task).await;
            return Err(error);
        }
    };

    let encryption_secret = identity.encryption_key.to_bytes();
    let (task_space_stop, task_space_stop_rx) = tokio::sync::watch::channel(false);
    let mut task_space_task = tokio::spawn(run_task_space_monitor(
        config.executable.clone(),
        config.work_root.clone(),
        config.default_task_space.clone(),
        task_space_stop_rx,
    ));
    let (renew_stop, renew_rx) = tokio::sync::watch::channel(false);
    let renewal_api = api.clone();
    let renewal_supervisor = Arc::clone(&supervisor);
    let renewal_config = config.clone();
    let renewal_store = store.clone();
    let renewal_task = tokio::spawn(async move {
        run_lease_observer_loop(
            LeaseObserverContext {
                api: renewal_api,
                supervisor: renewal_supervisor,
                config: renewal_config,
                store: renewal_store,
                identity,
            },
            lease.renew_interval_seconds,
            lease.renew_failure_grace_seconds,
            renew_rx,
        )
        .await;
    });

    let (result, device_peer_finished, task_space_finished): (Result<(), BridgeError>, bool, bool) = tokio::select! {
        biased;
        outcome = &mut device_peer_task => {
            let error = device_peer_task_failure(
                outcome,
                &supervisor,
                &store,
                &api,
                &config.binding_id,
                config.generation,
            ).await;
            (Err(error), true, false)
        }
        outcome = &mut task_space_task => {
            let outcome = outcome.unwrap_or(TaskSpaceMonitorOutcome::Unavailable);
            let pause_api = api.clone();
            let pause_binding_id = config.binding_id.clone();
            let pause_generation = config.generation;
            let error = fail_closed_task_space_monitor(
                outcome,
                &supervisor,
                move |reason| async move {
                    pause_binding_after_task_space_event(
                        pause_api,
                        pause_binding_id,
                        pause_generation,
                        reason,
                    )
                    .await;
                },
            )
            .await;
            (Err(error), false, true)
        }
        result = async {
            let mut first_connection = true;
            let mut reconnect_delay = RELAY_RECONNECT_MIN_DELAY;
            loop {
                verify_policy_snapshot(&store, &config)?;
                let ticket_result = tokio::select! {
                    result = api.bridge_relay_ticket(&config.binding_id, config.generation) => result,
                    signal = &mut shutdown => return finish_shutdown(&supervisor, signal),
                };
                let ticket_value = match ticket_result {
                    Ok(value) => value,
                    Err(error) => {
                        if args.once || !is_retryable_control_error(&error) {
                            return Err(map_credential_error(error));
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(reconnect_delay) => {}
                            signal = &mut shutdown => return finish_shutdown(&supervisor, signal),
                        }
                        reconnect_delay = (reconnect_delay * 2).min(RELAY_RECONNECT_MAX_DELAY);
                        continue;
                    }
                };
                let ticket =
                    parse_relay_ticket(&ticket_value, &config.binding_id, config.generation)?;
                let relay_result = tokio::select! {
                    result = open_relay(&api, &ticket, &config.binding_id) => result,
                    signal = &mut shutdown => return finish_shutdown(&supervisor, signal),
                };
                let socket = match relay_result {
                    Ok(socket) => socket,
                    Err(error) => {
                        if args.once {
                            return Err(error);
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(reconnect_delay) => {}
                            signal = &mut shutdown => return finish_shutdown(&supervisor, signal),
                        }
                        reconnect_delay = (reconnect_delay * 2).min(RELAY_RECONNECT_MAX_DELAY);
                        continue;
                    }
                };
                // A transient disconnect cancels the old supervised request. Only a
                // fresh ticket and a still-healthy lease may clear that cancellation.
                if !first_connection {
                    supervisor.resume_after_reconnect()?;
                }
                first_connection = false;
                reconnect_delay = RELAY_RECONNECT_MIN_DELAY;

                let session_result = tokio::select! {
                    result = run_relay_session(
                        socket,
                        Arc::clone(&supervisor),
                        encryption_secret,
                    ) => result,
                    signal = &mut shutdown => {
                        supervisor.cancel();
                        signal
                            .map(|()| RelaySessionOutcome::Shutdown)
                            .map_err(|_| BridgeError::ProtocolMessage("shutdown signal handler failed".into()))
                    }
                };

                match session_result {
                    Ok(RelaySessionOutcome::Disconnected) => {
                        if args.once {
                            return Ok(());
                        }
                        // run_relay_session marks the generation cancelled before it
                        // returns. The next iteration must obtain a new one-time ticket.
                        tokio::select! {
                            _ = tokio::time::sleep(reconnect_delay) => {}
                            signal = &mut shutdown => return finish_shutdown(&supervisor, signal),
                        }
                        reconnect_delay = (reconnect_delay * 2).min(RELAY_RECONNECT_MAX_DELAY);
                    }
                    Ok(RelaySessionOutcome::Shutdown) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        } => (result, false, false),
    };
    renew_stop.send_replace(true);
    let _ = renewal_task.await;
    if !device_peer_finished {
        stop_device_peer_observer(device_stop, device_peer_task).await;
    }
    if !task_space_finished {
        stop_task_space_monitor(task_space_stop, task_space_task).await;
    }
    result
}

fn finish_shutdown(
    supervisor: &BridgeSupervisor,
    signal: std::io::Result<()>,
) -> Result<(), BridgeError> {
    supervisor.cancel();
    signal.map_err(|_| BridgeError::ProtocolMessage("shutdown signal handler failed".into()))
}
