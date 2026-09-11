use super::*;
use tokio::io::AsyncReadExt;

#[test]
fn device_metric_event_is_content_free() {
    let encoded = metric_event(
        "ego_browser_device_refresh_total",
        1,
        "requests",
        "completed",
    );
    let value: serde_json::Value =
        serde_json::from_str(&encoded).expect("parse device metric event");
    let object = value.as_object().expect("metric object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        ["event", "metric", "status", "unit", "value"]
    );
    assert_eq!(value["event"], "metric");
    assert_eq!(value["metric"], "ego_browser_device_refresh_total");
    assert_eq!(value["status"], "completed");
    for forbidden in [
        "device_id",
        "binding_id",
        "session_id",
        "server_url",
        "token",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn top_level_error_line_omits_wrapped_error_content() {
    let secret = "browser-content-secret";
    let error = CredentialError::Io(std::io::Error::other(secret));
    let line = top_level_error_line(&error);
    assert_eq!(line, "ego-browser-device error=io_error");
    assert!(!line.contains(secret));
}

#[test]
fn token_stdin_normalization_strips_only_line_endings() {
    assert_eq!(
        crate::registration::normalize_stdin_token("art_test\r\n").expect("token"),
        "art_test"
    );
    assert!(crate::registration::normalize_stdin_token("\n").is_err());
    assert!(crate::registration::normalize_stdin_token(&"x".repeat(4097)).is_err());
}

#[test]
fn runtime_probe_discovers_the_standard_user_install_without_path() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let executable = temporary.path().join(".local/bin/ego-browser");
    fs::create_dir_all(executable.parent().expect("runtime parent"))
        .expect("create runtime directory");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' 'ego-browser {}' '  chromium 150.0.7871.101' '  node v24.18.0'\n",
            SUPPORTED_LOCAL_RUNTIME_VERSION
        ),
    )
    .expect("write fake runtime");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make fake runtime executable");

    let candidates = runtime_executable_candidates(None, None, Some(temporary.path().as_os_str()))
        .expect("discover runtime candidates");
    assert_eq!(
        candidates.first(),
        Some(&executable.canonicalize().expect("canonical fake runtime"))
    );
    let probe = probe_runtime_candidates(&candidates).expect("probe standard runtime");
    assert_eq!(probe.ego_browser_version, SUPPORTED_LOCAL_RUNTIME_VERSION);
}

#[test]
fn explicit_runtime_must_be_an_absolute_executable() {
    assert!(runtime_executable_candidates(Some(OsStr::new("ego-browser")), None, None).is_err());
    assert!(
        runtime_executable_candidates(Some(OsStr::new("/missing/ego-browser")), None, None)
            .is_err()
    );
}

#[test]
fn registration_response_must_match_rotated_identity_and_revision() {
    let mut identity = DeviceIdentity::generate("community-local-trust", "community_file");
    identity.device_id = "rotation-response-device".into();
    identity.generation = 4;
    let certificate = "a".repeat(64);
    let submitted = serde_json::json!({
        "platform": "macos",
        "bridge_protocol_version": PROTOCOL_VERSION,
        "bridge_version": env!("CARGO_PKG_VERSION"),
        "local_ego_browser_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
        "ego_lite_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
        "skill_version": SUPPORTED_SKILL_VERSION,
        "allowlist_revision": 7,
        "allowlist_roots_digest": "sha256:allowlist",
        "learning_bundle_digest": "sha256:learning",
        "capabilities": [
            "ego_browser_site_learning_v1",
            "ego_browser_script_execute_v1",
            "ego_browser_file_allowlist_v1"
        ]
    });
    let response = serde_json::json!({
        "data": {
            "id": identity.device_id,
            "generation": identity.generation,
            "status": "active",
            "public_key": identity.public_key_b64(),
            "encryption_public_key": identity.encryption_public_key_b64(),
            "release_profile": identity.release_profile,
            "credential_profile": identity.credential_profile,
            "signer_certificate_sha256": certificate,
            "platform": "macos",
            "bridge_protocol_version": PROTOCOL_VERSION,
            "bridge_version": env!("CARGO_PKG_VERSION"),
            "local_ego_browser_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
            "ego_lite_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
            "skill_version": SUPPORTED_SKILL_VERSION,
            "allowlist_revision": 7,
            "allowlist_roots_digest": "sha256:allowlist",
            "learning_bundle_digest": "sha256:learning",
            "capabilities": [
                "ego_browser_file_allowlist_v1",
                "ego_browser_script_execute_v1",
                "ego_browser_site_learning_v1"
            ],
            "credential": {
                "id": "credential-rotated",
                "ego_browser_device_id": identity.device_id,
                "credential_profile": identity.credential_profile,
                "generation": identity.generation,
                "revision": 9,
                "access_token": "egbc_rotated-response-token",
                "token_type": "bearer",
                "expires_in": 3600
            }
        }
    });
    let credential = credential_from_registration_response(
        &response,
        "https://control.example.test",
        &identity,
        &certificate,
        &submitted,
        Some(8),
    )
    .expect("validate rotated response");
    assert_eq!(credential.device_id, identity.device_id);
    assert_eq!(credential.revision, 9);
    assert_eq!(credential.token, "egbc_rotated-response-token");

    let mut stale = response.clone();
    stale["data"]["credential"]["revision"] = serde_json::json!(8);
    assert!(credential_from_registration_response(
        &stale,
        "https://control.example.test",
        &identity,
        &certificate,
        &submitted,
        Some(8),
    )
    .is_err());
    let mut wrong_key = response.clone();
    wrong_key["data"]["public_key"] = serde_json::json!("wrong-key");
    assert!(credential_from_registration_response(
        &wrong_key,
        "https://control.example.test",
        &identity,
        &certificate,
        &submitted,
        Some(8),
    )
    .is_err());

    for (field, wrong_value) in [
        ("learning_bundle_digest", serde_json::json!("sha256:wrong")),
        ("allowlist_roots_digest", serde_json::json!("sha256:wrong")),
        ("allowlist_revision", serde_json::json!(6)),
        (
            "capabilities",
            serde_json::json!(["ego_browser_script_execute_v1"]),
        ),
    ] {
        let mut mismatched = response.clone();
        mismatched["data"][field] = wrong_value;
        assert!(credential_from_registration_response(
            &mismatched,
            "https://control.example.test",
            &identity,
            &certificate,
            &submitted,
            Some(8),
        )
        .is_err());
    }
}

#[test]
fn allowlist_confirmation_must_pause_and_advance_the_exact_binding() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let canonical = temporary.path().canonicalize().expect("canonical root");
    let allowlist = ego_browser_bridge_protocol::Allowlist::new(
        vec![canonical],
        7,
        ego_browser_bridge_protocol::AllowlistLimits::default(),
    )
    .expect("allowlist");
    let digest = allowlist.roots_digest().expect("allowlist digest");
    let policy = VerifiedLocalPolicy {
        policy_revision: 7,
        allowlist_revision: 7,
        allowlist_roots_digest: Some(digest.clone()),
        allowlist: Some(allowlist),
        learning_bundle: None,
    };
    let response = serde_json::json!({
        "data": {
            "id": "binding-1",
            "ego_browser_device_id": "device-1",
            "generation": 5,
            "status": "paused",
            "stop_reason": "allowlist_changed",
            "authorization_mode": "ego_browser_script_full_trust",
            "task_space_label": "agent-remote:session-1",
            "allowlist_revision": 7,
            "allowlist_roots_digest": digest,
            "learning_bundle_digest": null,
            "capabilities": policy.capabilities(),
        }
    });
    assert_eq!(
        confirmed_allowlist_generation(
            &response,
            "binding-1",
            "device-1",
            4,
            &policy,
            Some("agent-remote:session-1"),
        )
        .expect("exact confirmation"),
        5
    );

    for (field, wrong_value) in [
        ("generation", serde_json::json!(4)),
        ("status", serde_json::json!("active")),
        ("allowlist_revision", serde_json::json!(6)),
        ("allowlist_roots_digest", serde_json::json!("sha256:wrong")),
    ] {
        let mut mismatched = response.clone();
        mismatched["data"][field] = wrong_value;
        assert!(confirmed_allowlist_generation(
            &mismatched,
            "binding-1",
            "device-1",
            4,
            &policy,
            Some("agent-remote:session-1"),
        )
        .is_err());
    }
}

#[test]
fn policy_auth_option_values_are_not_treated_as_paths() {
    let args = [
        "/allowed/root",
        "--token",
        "secret-token",
        "--signer-certificate-sha256",
        "certificate-digest",
        "--confirm",
    ]
    .map(str::to_owned);
    assert_eq!(
        positional_paths(&args, &["--token", "--signer-certificate-sha256"]).expect("parse paths"),
        [PathBuf::from("/allowed/root")]
    );
    assert!(option(
        &["--token", "one", "--token", "two"].map(str::to_owned),
        "--token"
    )
    .is_err());
    assert!(option(&["--token", "--confirm"].map(str::to_owned), "--token").is_err());
}

#[tokio::test]
async fn device_service_socket_is_owner_only_and_heartbeats_same_uid_peers() {
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
    let socket_path = store.device_service_socket_path();
    let listener = prepare_device_service_listener(&socket_path).expect("device listener");
    let metadata = fs::symlink_metadata(&socket_path).expect("socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let mut server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept bridge peer");
        assert!(same_user_peer(&stream));
        serve_device_peer(stream).await;
    });
    let mut client = UnixStream::connect(&socket_path)
        .await
        .expect("connect device service");
    let mut heartbeat = [0_u8; DEVICE_PEER_HEARTBEAT.len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut heartbeat))
        .await
        .expect("heartbeat timeout")
        .expect("heartbeat read");
    assert_eq!(heartbeat, DEVICE_PEER_HEARTBEAT);

    drop(client);
    if tokio::time::timeout(Duration::from_secs(1), &mut server)
        .await
        .is_err()
    {
        server.abort();
        let _ = server.await;
    }
}
