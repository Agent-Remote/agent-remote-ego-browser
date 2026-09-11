use super::*;
use ego_browser_bridge_protocol::{
    aad_for_outer, encode_b64url, unwrap_session_key, wrap_session_key, Direction, ExecutionStatus,
    InnerExecuteRequest, InnerExecuteResponse, InnerMessageType, OuterMessageType, SessionCipher,
};
use tokio_tungstenite::tungstenite::protocol::Role;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn test_config() -> BridgeConfig {
    BridgeConfig {
        executable: "ego-browser".into(),
        work_root: std::env::temp_dir(),
        binding_id: "binding-test".into(),
        generation: 7,
        allowlist_revision: 3,
        allowlist_roots_digest: Some(format!("sha256:{}", "b".repeat(64))),
        allowlist: None,
        learning_bundle_digest: Some(format!("sha256:{}", "a".repeat(64))),
        learning_bundle_root: None,
        local_policy_revision: 5,
        capabilities: vec![
            "ego_browser_script_execute_v1".into(),
            "ego_browser_snapshot_v1".into(),
            "ego_browser_screenshot_artifact_v1".into(),
            "ego_browser_task_space_v1".into(),
            "ego_browser_concurrency_v1".into(),
            "ego_browser_file_allowlist_v1".into(),
            "ego_browser_site_learning_v1".into(),
        ],
        release_profile: ReleaseProfile::LogicTest,
        credential_profile: CredentialProfile::CommunityFile,
        signer_certificate_sha256: "development".into(),
        runtime_version: "runtime-test".into(),
        ego_lite_version: "ego-lite-test".into(),
        skill_version: "skill-test".into(),
        max_parallel_requests: 4,
        default_task_space: "agent-remote:session-test".into(),
        broker_startup_nonce: None,
    }
}

fn connected_response(config: &BridgeConfig, identity: &DeviceIdentity) -> serde_json::Value {
    let capability = config.capability();
    serde_json::json!({
        "data": {
            "id": config.binding_id,
            "ego_browser_device_id": identity.device_id,
            "encryption_public_key": identity.encryption_public_key_b64(),
            "status": "active",
            "control_channel": "ego_browser_bridge",
            "relay_binding_kind": "ego_browser",
            "authorization_mode": "ego_browser_script_full_trust",
            "authorization_policy_version": 1,
            "release_profile": "logic-test",
            "signer_certificate_sha256": config.signer_certificate_sha256,
            "credential_profile": "community_file",
            "remote_platform": "linux",
            "local_platform": "macos",
            "local_runtime_version": config.runtime_version,
            "ego_lite_runtime_version": config.ego_lite_version,
            "skill_version": config.skill_version,
            "bridge_protocol_version": capability.bridge_protocol_version,
            "task_space_label": config.default_task_space,
            "allowlist_revision": config.allowlist_revision,
            "allowlist_roots_digest": config.allowlist_roots_digest,
            "learning_bundle_digest": config.learning_bundle_digest,
            "concurrency_mode": "binding",
            "max_parallel_requests": config.max_parallel_requests,
            "capabilities": capability.capabilities,
            "lease_until": "2099-01-01T00:01:00Z",
            "lease_health": "healthy",
            "lease_renew_interval_seconds": 17,
            "lease_renew_failure_grace_seconds": 9,
            "absolute_ttl_until": "2099-01-01T01:00:00Z",
            "generation": config.generation,
        }
    })
}

fn test_store() -> (tempfile::TempDir, CredentialStore) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let store = CredentialStore::new(
        temporary
            .path()
            .canonicalize()
            .expect("canonical temporary directory"),
    )
    .expect("credential store");
    (temporary, store)
}

#[tokio::test]
async fn bridge_verifies_device_socket_and_initial_heartbeat() {
    let (_temporary, store) = test_store();
    let path = store.device_service_socket_path();
    let listener = UnixListener::bind(&path).expect("bind device service socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("private device service socket");
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.expect("accept bridge");
        tokio::io::AsyncWriteExt::write_all(&mut peer, DEVICE_PEER_HEARTBEAT)
            .await
            .expect("write heartbeat");
    });

    let peer = connect_device_service_peer(&store)
        .await
        .expect("verified device peer");
    drop(peer);
    server.await.expect("join device service");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("make socket unsafe");
    assert!(inspect_device_service_socket(&path).is_err());
}

#[tokio::test]
async fn device_peer_eof_revokes_admission_and_clears_handoff() {
    let (_temporary, store) = test_store();
    store
        .save_active_binding(&ego_browser_device::ActiveBinding {
            version: 1,
            binding_id: "binding-test".into(),
            generation: 7,
            device_id: "device-test".into(),
            task_space_label: "agent-remote:session-test".into(),
            authorization_mode: "ego_browser_script_full_trust".into(),
            user_confirmation: true,
        })
        .expect("save active binding");
    let mut config = test_config();
    config.work_root = store
        .device_service_socket_path()
        .parent()
        .expect("credential directory")
        .join("bridge-work");
    let supervisor = BridgeSupervisor::new(config).expect("bridge supervisor");
    let (peer_writer, peer_reader) = tokio::io::duplex(64);
    drop(peer_writer);
    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stop_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback_flag = Arc::clone(&stop_called);

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        run_device_peer_observer_loop(
            peer_reader,
            Arc::clone(&supervisor),
            store.clone(),
            move || async move {
                callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            stop_rx,
            Duration::from_millis(50),
        ),
    )
    .await
    .expect("bounded peer observer");

    assert!(matches!(outcome, DevicePeerObserverOutcome::Lost(_)));
    assert!(stop_called.load(std::sync::atomic::Ordering::SeqCst));
    assert!(matches!(
        store.load_active_binding("device-test"),
        Err(CredentialError::Missing)
    ));
    assert!(matches!(
        supervisor.resume_after_reconnect(),
        Err(BridgeError::Revoked)
    ));
}

#[tokio::test]
async fn device_heartbeat_rejects_malformed_frames_and_times_out() {
    let (mut malformed_writer, mut malformed_reader) = tokio::io::duplex(64);
    tokio::io::AsyncWriteExt::write_all(&mut malformed_writer, b"NOPE\n")
        .await
        .expect("write malformed heartbeat");
    assert!(
        read_device_peer_heartbeat(&mut malformed_reader, Duration::from_secs(1))
            .await
            .is_err()
    );

    let (_waiting_writer, mut waiting_reader) = tokio::io::duplex(64);
    assert!(
        read_device_peer_heartbeat(&mut waiting_reader, Duration::from_millis(20))
            .await
            .is_err()
    );
}

#[test]
fn task_space_monitor_uses_only_native_read_only_ownership_state() {
    let script = String::from_utf8(
        task_space_monitor_script("agent-remote:session-test").expect("build Task Space monitor"),
    )
    .expect("monitor script is UTF-8");
    assert!(script.contains("await listTaskSpaces()"));
    assert!(script.contains("ownership === 'agent'"));
    assert!(script.contains("ownership === 'agentDelegatedToUser'"));
    assert!(script.contains("ownership === 'user'"));
    assert!(script.contains(&format!(
        "process.exit({TASK_SPACE_MONITOR_TAKEOVER_EXIT_CODE})"
    )));
    for forbidden in [
        "claimTaskSpace",
        "takeOverTaskSpace",
        "useOrCreateTaskSpace",
        "markTaskSpaceError",
        "process.stderr",
    ] {
        assert!(!script.contains(forbidden));
    }
    assert!(task_space_monitor_script("user-owned-space").is_err());
}

#[tokio::test]
async fn task_space_takeover_revokes_before_requesting_a_pause() {
    let directory = tempfile::tempdir().expect("create test directory");
    let mut config = test_config();
    config.work_root = directory
        .path()
        .canonicalize()
        .expect("canonical test directory")
        .join("bridge-work");
    let supervisor = BridgeSupervisor::new(config).expect("create bridge supervisor");
    let callback_supervisor = Arc::clone(&supervisor);
    let pause_reason = Arc::new(std::sync::Mutex::new(None));
    let callback_reason = Arc::clone(&pause_reason);

    let error = fail_closed_task_space_monitor(
        TaskSpaceMonitorOutcome::TakenOver,
        &supervisor,
        move |reason| async move {
            assert!(matches!(
                callback_supervisor.resume_after_reconnect(),
                Err(BridgeError::Revoked)
            ));
            *callback_reason.lock().expect("pause reason lock") = Some(reason);
        },
    )
    .await;

    assert!(error.to_string().contains("taken over"));
    assert_eq!(
        *pause_reason.lock().expect("pause reason lock"),
        Some("task_space_takeover")
    );
}

#[tokio::test]
async fn task_space_monitor_failure_revokes_before_requesting_a_pause() {
    let directory = tempfile::tempdir().expect("create test directory");
    let mut config = test_config();
    config.work_root = directory
        .path()
        .canonicalize()
        .expect("canonical test directory")
        .join("bridge-work");
    let supervisor = BridgeSupervisor::new(config).expect("create bridge supervisor");
    let callback_supervisor = Arc::clone(&supervisor);
    let pause_reason = Arc::new(std::sync::Mutex::new(None));
    let callback_reason = Arc::clone(&pause_reason);

    let error = fail_closed_task_space_monitor(
        TaskSpaceMonitorOutcome::Unavailable,
        &supervisor,
        move |reason| async move {
            assert!(matches!(
                callback_supervisor.resume_after_reconnect(),
                Err(BridgeError::Revoked)
            ));
            *callback_reason.lock().expect("pause reason lock") = Some(reason);
        },
    )
    .await;

    assert!(error.to_string().contains("monitor is unavailable"));
    assert_eq!(
        *pause_reason.lock().expect("pause reason lock"),
        Some("task_space_monitor_unavailable")
    );
}

fn remote_request(
    config: &BridgeConfig,
    recipient: &[u8; 32],
    sequence: u64,
    script: &str,
    tab_scope: &str,
) -> (OuterEnvelope, [u8; 32]) {
    let inner = InnerExecuteRequest {
        protocol: "ego-browser-bridge-v1-inner".into(),
        message_type: InnerMessageType::Execute,
        script: script.into(),
        timeout_ms: 5_000,
        cwd_label: "workspace".into(),
        default_task_space: config.default_task_space.clone(),
        concurrency_mode: ConcurrencyMode::TaskSpaceTab,
        task_space_scope: Some(config.default_task_space.clone()),
        tab_scope: Some(tab_scope.into()),
        allowlist_revision: config.allowlist_revision,
        learning_bundle_digest: config.learning_bundle_digest.clone(),
    };
    let plaintext = canonical_json(&inner).expect("serialize inner request");
    let (key, cipher) = SessionCipher::random();
    let request_id = format!("request-{sequence}");
    let mut envelope = OuterEnvelope {
        protocol: "ego-browser-bridge-v1".into(),
        channel: "ego_browser_bridge".into(),
        relay_binding_kind: "ego_browser".into(),
        message_type: OuterMessageType::Execute,
        request_id: request_id.clone(),
        binding_id: config.binding_id.clone(),
        generation: config.generation,
        sequence,
        direction: Direction::Request,
        payload_bytes: plaintext.len(),
        nonce: String::new(),
        ciphertext: String::new(),
        auth_tag: String::new(),
        key_wrap: wrap_session_key(
            &key,
            recipient,
            &config.binding_id,
            config.generation,
            &request_id,
            sequence,
        )
        .expect("wrap request key"),
    };
    let aad = aad_for_outer(&envelope).expect("build request AAD");
    let (nonce, ciphertext, tag) = cipher.seal(&plaintext, &aad).expect("seal request");
    envelope.nonce = encode_b64url(&nonce);
    envelope.ciphertext = encode_b64url(&ciphertext);
    envelope.auth_tag = encode_b64url(&tag);
    (envelope, key)
}

fn open_response(envelope: &OuterEnvelope, key: &[u8; 32]) -> InnerExecuteResponse {
    let (ciphertext, nonce, tag) = envelope.decoded_payload().expect("decode response payload");
    let aad = aad_for_outer(envelope).expect("build response AAD");
    let plaintext = SessionCipher::new(key)
        .open(&nonce, &ciphertext, &tag, &aad)
        .expect("open response payload");
    parse_strict_json(&plaintext).expect("parse inner response")
}

#[test]
fn connected_response_requires_complete_matching_capability() {
    let config = test_config();
    let identity = DeviceIdentity::generate("logic-test", "community_file");
    let response = connected_response(&config, &identity);
    let lease =
        parse_connected_response(&response, &config, &identity).expect("accept matching response");
    assert_eq!(lease.renew_interval_seconds, 17);
    assert_eq!(lease.renew_failure_grace_seconds, 9);

    for (field, invalid) in [
        ("control_channel", serde_json::json!("other")),
        ("relay_binding_kind", serde_json::json!("other")),
        ("remote_platform", serde_json::json!("macos")),
        ("release_profile", serde_json::json!("development-local")),
        (
            "credential_profile",
            serde_json::json!("keychain_access_group"),
        ),
        ("bridge_protocol_version", serde_json::json!("downgraded")),
        ("task_space_label", serde_json::json!("agent-remote:other")),
        ("max_parallel_requests", serde_json::json!(3)),
    ] {
        let mut invalid_response = response.clone();
        invalid_response["data"][field] = invalid;
        assert!(parse_connected_response(&invalid_response, &config, &identity).is_err());
    }
}

#[test]
fn startup_renews_an_already_active_generation() {
    let config = test_config();
    let identity = DeviceIdentity::generate("logic-test", "community_file");
    let mut response = connected_response(&config, &identity);
    assert_eq!(
        startup_activation(&response, &config, &identity).expect("active binding should renew"),
        StartupActivation::Renew
    );

    for status in ["pending_device", "connecting", "probing_local_browser"] {
        response["data"]["status"] = serde_json::json!(status);
        assert_eq!(
            startup_activation(&response, &config, &identity)
                .expect("pending binding should connect"),
            StartupActivation::Connect
        );
    }
}

#[test]
fn startup_rejects_stale_or_terminal_binding_state() {
    let config = test_config();
    let identity = DeviceIdentity::generate("logic-test", "community_file");
    let response = connected_response(&config, &identity);
    for (status, expected) in [
        ("paused", "explicit resume"),
        ("failed", "explicit resume"),
        ("expired", "lease"),
        ("revoked", "revoked"),
    ] {
        let mut candidate = response.clone();
        candidate["data"]["status"] = serde_json::json!(status);
        let error = startup_activation(&candidate, &config, &identity)
            .expect_err("stale state must not be auto-resumed");
        assert!(error.to_string().contains(expected));
    }
}

#[test]
fn connected_response_rejects_changed_or_duplicate_capabilities() {
    let config = test_config();
    let identity = DeviceIdentity::generate("logic-test", "community_file");
    let mut changed = connected_response(&config, &identity);
    changed["data"]["capabilities"] = serde_json::json!(["ego_browser_script_execute_v1"]);
    assert!(parse_connected_response(&changed, &config, &identity).is_err());

    let mut duplicate = connected_response(&config, &identity);
    let capabilities = duplicate["data"]["capabilities"]
        .as_array_mut()
        .expect("capability array");
    capabilities.push(capabilities[0].clone());
    assert!(parse_connected_response(&duplicate, &config, &identity).is_err());
}

#[test]
fn relay_ticket_rejects_expired_or_wrong_path() {
    let expired = serde_json::json!({
        "data": {
            "role": "bridge",
            "generation": 7,
            "relay_binding_kind": "ego_browser",
            "relay_path": "/api/v1/ego-browser/bindings/binding-test/relay",
            "relay_ticket": "ticket-value",
            "expires_at": "2000-01-01T00:00:00Z",
        }
    });
    assert!(matches!(
        parse_relay_ticket(&expired, "binding-test", 7),
        Err(BridgeError::LeaseExpired)
    ));

    let mut wrong_path = expired;
    wrong_path["data"]["expires_at"] = serde_json::json!("2099-01-01T00:00:00Z");
    wrong_path["data"]["relay_path"] = serde_json::json!("/unexpected");
    assert!(parse_relay_ticket(&wrong_path, "binding-test", 7).is_err());
}

#[tokio::test]
async fn relay_multiplexes_encrypted_conflicts_ahead_of_a_slow_request() {
    let directory = tempfile::tempdir().expect("create test directory");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonicalize test directory");
    let executable = root.join("fake-ego-browser");
    fs::write(
            &executable,
            "#!/bin/sh\nscript=$(/bin/cat)\ncase \"$script\" in\n  *slow-request*) /bin/sleep 0.25 ;;\nesac\nprintf '%s' \"$script\"\n",
        )
        .expect("write fake ego-browser");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make fake ego-browser executable");
    let mut config = test_config();
    config.executable = executable;
    config.work_root = root.join("bridge-work");
    config.learning_bundle_digest = None;
    let supervisor = BridgeSupervisor::new(config.clone()).expect("create bridge supervisor");

    let encryption_secret = StaticSecret::random();
    let encryption_public = X25519PublicKey::from(&encryption_secret);
    let secret_bytes = encryption_secret.to_bytes();
    let (slow, slow_key) = remote_request(
        &config,
        encryption_public.as_bytes(),
        1,
        "slow-request",
        "tab-a",
    );
    let (fast, fast_key) = remote_request(
        &config,
        encryption_public.as_bytes(),
        2,
        "fast-request",
        "tab-b",
    );
    let (conflict, conflict_key) = remote_request(
        &config,
        encryption_public.as_bytes(),
        3,
        "conflicting-request",
        "tab-a",
    );
    assert_eq!(
        unwrap_session_key(
            &slow.key_wrap,
            &secret_bytes,
            &slow.binding_id,
            slow.generation,
            &slow.request_id,
            slow.sequence,
        )
        .expect("unwrap test request key"),
        slow_key
    );

    let (bridge_io, client_io) = tokio::io::duplex(64 * 1024);
    let (bridge_socket, mut client_socket) = tokio::join!(
        WebSocketStream::from_raw_socket(bridge_io, Role::Server, None),
        WebSocketStream::from_raw_socket(client_io, Role::Client, None),
    );
    let relay_supervisor = Arc::clone(&supervisor);
    let mut relay = tokio::spawn(async move {
        run_relay_session(bridge_socket, relay_supervisor, secret_bytes).await
    });
    for envelope in [&slow, &fast, &conflict] {
        let bytes = canonical_json(envelope).expect("serialize relay request");
        client_socket
            .send(Message::binary(bytes))
            .await
            .expect("send relay request");
    }

    let mut response_order = Vec::new();
    let mut statuses = std::collections::HashMap::new();
    for _ in 0..3 {
        let message = tokio::select! {
            outcome = &mut relay => panic!("relay ended before its responses: {outcome:?}"),
            message = tokio::time::timeout(Duration::from_secs(2), client_socket.next()) => {
                message
                    .expect("relay response timeout")
                    .expect("relay closed before response")
                    .expect("read relay response")
            }
        };
        let Message::Binary(bytes) = message else {
            panic!("expected a binary relay response, got {message:?}");
        };
        let envelope: OuterEnvelope = parse_strict_json(&bytes).expect("parse response envelope");
        let key = match envelope.sequence {
            1 => &slow_key,
            2 => &fast_key,
            3 => &conflict_key,
            sequence => panic!("unexpected response sequence {sequence}"),
        };
        let inner = open_response(&envelope, key);
        response_order.push(envelope.sequence);
        statuses.insert(envelope.sequence, inner.status);
    }
    let fast_position = response_order
        .iter()
        .position(|sequence| *sequence == 2)
        .expect("fast response");
    let slow_position = response_order
        .iter()
        .position(|sequence| *sequence == 1)
        .expect("slow response");
    assert!(
        fast_position < slow_position,
        "responses were serialized: {response_order:?}"
    );
    assert_eq!(statuses.get(&1), Some(&ExecutionStatus::Completed));
    assert_eq!(
        statuses.get(&2),
        Some(&ExecutionStatus::ConcurrencyConflict)
    );
    assert_eq!(
        statuses.get(&3),
        Some(&ExecutionStatus::ConcurrencyConflict)
    );

    client_socket.close(None).await.expect("close relay client");
    let outcome = relay
        .await
        .expect("join relay session")
        .expect("relay outcome");
    assert!(matches!(outcome, RelaySessionOutcome::Disconnected));
}
