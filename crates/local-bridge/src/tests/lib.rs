use super::{
    execution_metric_events, helper_guard_script, now_seconds, ActiveRemoteRequest, BridgeConfig,
    BridgeError, BridgeSupervisor, FileGuardHandle, PermitRequest, RemoteRequestKey,
};
use ego_browser_bridge_protocol::{
    aad_for_outer, canonical_json, encode_b64url, Allowlist, AllowlistLimits, ArtifactDescriptor,
    ConcurrencyMode, CredentialProfile, Direction, ExecutionStatus, InnerCancelRequest,
    InnerExecuteRequest, InnerMessageType, LeasePolicy, OuterEnvelope, OuterMessageType,
    ProtocolError, ReleaseProfile, SessionCipher, PROTOCOL_VERSION,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[test]
fn execution_metrics_are_content_free() {
    let artifacts = vec![ArtifactDescriptor {
        artifact_id: "sensitive-artifact-id".into(),
        media_type: "image/png".into(),
        size_bytes: 42,
        width: 1,
        height: 1,
        content_b64: "sensitive-image-content".into(),
    }];
    let events = execution_metric_events(ExecutionStatus::Completed, 1_250, 123, 456, &artifacts);
    assert_eq!(events.len(), 5);
    let mut metric_names = Vec::new();
    for encoded in &events {
        let value: serde_json::Value =
            serde_json::from_str(encoded).expect("parse execution metric");
        let object = value.as_object().expect("metric object");
        assert_eq!(value["event"], "metric");
        assert_eq!(value["status"], "completed");
        assert!(object.keys().all(|key| matches!(
            key.as_str(),
            "direction" | "event" | "media_type" | "metric" | "status" | "unit" | "value"
        )));
        metric_names.push(value["metric"].as_str().expect("metric name").to_owned());
    }
    assert_eq!(
        metric_names,
        [
            "ego_browser_execute_total",
            "ego_browser_execute_duration_seconds",
            "ego_browser_bytes_total",
            "ego_browser_bytes_total",
            "ego_browser_artifacts_total",
        ]
    );
    let rendered = events.join("\n");
    for forbidden in [
        "sensitive-artifact-id",
        "sensitive-image-content",
        "binding_id",
        "request_id",
        "local_path",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn operational_error_codes_are_content_free() {
    let errors = [
        BridgeError::ProtocolMessage("sensitive-page-content".into()),
        BridgeError::Protocol(ProtocolError::DuplicateJsonKey(
            "sensitive-local-path".into(),
        )),
        BridgeError::Io(std::io::Error::other("sensitive-browser-output")),
    ];
    for error in errors {
        assert!(matches!(error.log_code(), "protocol_error" | "io_error"));
        assert!(!error.log_code().contains("sensitive"));
    }
}

#[test]
fn reconnect_during_renewal_window_restores_transport_but_not_request_admission() {
    let directory = tempfile::tempdir().expect("create test directory");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let supervisor = BridgeSupervisor::new(test_config(root.join("bridge-work")))
        .expect("create bridge supervisor");
    let policy = LeasePolicy::default();
    {
        let mut lease = supervisor.lease.lock().expect("lease lock");
        lease.lease_until =
            now_seconds().saturating_add(policy.admission_min_remaining_seconds.saturating_sub(1));
    }

    supervisor.cancel();
    assert!(supervisor.is_cancelled());
    supervisor
        .resume_after_reconnect()
        .expect("renewal window permits transport reconnect");
    assert!(!supervisor.is_cancelled());

    let request = PermitRequest {
        protocol: PROTOCOL_VERSION.into(),
        message_type: "permit_request".into(),
        script_bytes: 1,
        timeout_ms: 1_000,
        cwd_label: "workspace".into(),
        concurrency_mode: ConcurrencyMode::Binding,
        task_space_scope: None,
        tab_scope: None,
        startup_nonce: None,
    };
    assert!(matches!(
        supervisor.issue_permit(&request),
        Err(BridgeError::LeaseRenewalRequired)
    ));
}

fn test_config(work_root: std::path::PathBuf) -> BridgeConfig {
    BridgeConfig {
        executable: "ego-browser".into(),
        work_root,
        binding_id: "binding-test".into(),
        generation: 1,
        allowlist_revision: 1,
        allowlist_roots_digest: None,
        allowlist: None,
        learning_bundle_digest: None,
        learning_bundle_root: None,
        local_policy_revision: 1,
        capabilities: vec![
            "ego_browser_script_execute_v1".into(),
            "ego_browser_snapshot_v1".into(),
            "ego_browser_screenshot_artifact_v1".into(),
            "ego_browser_task_space_v1".into(),
            "ego_browser_concurrency_v1".into(),
        ],
        release_profile: ReleaseProfile::LogicTest,
        credential_profile: CredentialProfile::CommunityFile,
        signer_certificate_sha256: "development".into(),
        runtime_version: "test-runtime".into(),
        ego_lite_version: "test-ego-lite".into(),
        skill_version: "test-skill".into(),
        max_parallel_requests: 4,
        default_task_space: "agent-remote:session-test".into(),
        broker_startup_nonce: None,
    }
}

fn process_request(config: &BridgeConfig, script: &str) -> InnerExecuteRequest {
    InnerExecuteRequest {
        protocol: "ego-browser-bridge-v1-inner".into(),
        message_type: InnerMessageType::Execute,
        script: script.into(),
        timeout_ms: 5_000,
        cwd_label: "workspace".into(),
        default_task_space: config.default_task_space.clone(),
        concurrency_mode: ConcurrencyMode::TaskSpaceTab,
        task_space_scope: Some(config.default_task_space.clone()),
        tab_scope: Some(script.into()),
        allowlist_revision: config.allowlist_revision,
        learning_bundle_digest: config.learning_bundle_digest.clone(),
    }
}

fn cancel_envelope(
    config: &BridgeConfig,
    key: &[u8; 32],
    request_id: &str,
    sequence: u64,
    inner_request_id: &str,
) -> OuterEnvelope {
    let inner = InnerCancelRequest {
        protocol: "ego-browser-bridge-v1-inner".into(),
        message_type: InnerMessageType::Cancel,
        request_id: inner_request_id.into(),
        sequence,
    };
    let plaintext = canonical_json(&inner).expect("serialize cancel request");
    let mut envelope = OuterEnvelope {
        protocol: "ego-browser-bridge-v1".into(),
        channel: "ego_browser_bridge".into(),
        relay_binding_kind: "ego_browser".into(),
        message_type: OuterMessageType::Cancel,
        request_id: request_id.into(),
        binding_id: config.binding_id.clone(),
        generation: config.generation,
        sequence,
        direction: Direction::Request,
        payload_bytes: plaintext.len(),
        nonce: String::new(),
        ciphertext: String::new(),
        auth_tag: String::new(),
        key_wrap: String::new(),
    };
    let aad = aad_for_outer(&envelope).expect("build cancel AAD");
    let (nonce, ciphertext, tag) = SessionCipher::new(key)
        .seal(&plaintext, &aad)
        .expect("seal cancel request");
    envelope.nonce = encode_b64url(&nonce);
    envelope.ciphertext = encode_b64url(&ciphertext);
    envelope.auth_tag = encode_b64url(&tag);
    envelope
}

#[test]
fn remote_sequence_must_increase_strictly() {
    let directory = tempfile::tempdir().expect("create test directory");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical test root");
    let supervisor =
        BridgeSupervisor::new(test_config(root.join("work"))).expect("create supervisor");

    supervisor
        .reserve_remote_sequence(10)
        .expect("accept initial sequence");
    assert!(matches!(
        supervisor.reserve_remote_sequence(9),
        Err(BridgeError::Replay)
    ));
    assert!(matches!(
        supervisor.reserve_remote_sequence(10),
        Err(BridgeError::Replay)
    ));
    supervisor
        .reserve_remote_sequence(11)
        .expect("accept next sequence");

    drop(supervisor);
    let restored = BridgeSupervisor::new(test_config(root.join("work")))
        .expect("restore supervisor from ledger");
    assert!(matches!(
        restored.reserve_remote_sequence(11),
        Err(BridgeError::Replay)
    ));
    restored
        .reserve_remote_sequence(12)
        .expect("accept sequence after restart");
}

#[tokio::test]
async fn exact_remote_cancellation_kills_only_its_process_group() {
    let directory = tempfile::tempdir().expect("create test directory");
    let root = directory
        .path()
        .canonicalize()
        .expect("canonical test root");
    let executable = root.join("fake-ego-browser");
    std::fs::write(
        &executable,
        r#"#!/bin/sh
script=$(/bin/cat)
case "$script" in
  *target-request*)
    /bin/sleep 30 &
    child=$!
    printf '%s' "$child" > "${0%/*}/target-child.pid"
    wait "$child"
    ;;
  *unrelated-request*)
    /bin/sleep 0.35
    printf 'unrelated-ok'
    ;;
  *after-request*)
    printf 'after-ok'
    ;;
esac
"#,
    )
    .expect("write fake ego-browser");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("make fake ego-browser executable");
    let mut config = test_config(root.join("work"));
    config.executable = executable;
    config.learning_bundle_digest = None;
    let supervisor = BridgeSupervisor::new(config.clone()).expect("create supervisor");
    let target_key = [7_u8; 32];
    let unrelated_key = [9_u8; 32];
    let (target_cancel_tx, target_cancel_rx) = tokio::sync::watch::channel(false);
    let (unrelated_cancel_tx, unrelated_cancel_rx) = tokio::sync::watch::channel(false);
    {
        let mut active = supervisor
            .active_remote_requests
            .lock()
            .expect("active request registry");
        active.insert(
            RemoteRequestKey {
                binding_id: config.binding_id.clone(),
                generation: config.generation,
                request_id: "request-target".into(),
                sequence: 1,
            },
            ActiveRemoteRequest {
                cancel_tx: target_cancel_tx,
                session_key: target_key,
            },
        );
        active.insert(
            RemoteRequestKey {
                binding_id: config.binding_id.clone(),
                generation: config.generation,
                request_id: "request-unrelated".into(),
                sequence: 2,
            },
            ActiveRemoteRequest {
                cancel_tx: unrelated_cancel_tx,
                session_key: unrelated_key,
            },
        );
    }

    let target_supervisor = Arc::clone(&supervisor);
    let target_request = process_request(&config, "target-request");
    let target = tokio::spawn(async move {
        target_supervisor
            .run_process(&target_request, "request-target", 1, target_cancel_rx)
            .await
    });
    let unrelated_supervisor = Arc::clone(&supervisor);
    let unrelated_request = process_request(&config, "unrelated-request");
    let unrelated = tokio::spawn(async move {
        unrelated_supervisor
            .run_process(
                &unrelated_request,
                "request-unrelated",
                2,
                unrelated_cancel_rx,
            )
            .await
    });

    let child_path = root.join("target-child.pid");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !child_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("target descendant did not start");

    let mut tampered = cancel_envelope(&config, &target_key, "request-target", 1, "request-target");
    tampered.auth_tag.replace_range(
        ..1,
        if tampered.auth_tag.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(supervisor.cancel_remote_request(&tampered).is_err());
    let mismatched = cancel_envelope(&config, &target_key, "request-target", 1, "request-other");
    assert!(supervisor.cancel_remote_request(&mismatched).is_err());
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!target.is_finished());
    assert!(!unrelated.is_finished());

    let cancel = cancel_envelope(&config, &target_key, "request-target", 1, "request-target");
    assert!(matches!(
        supervisor.cancel_remote_request(&cancel),
        Ok(true)
    ));
    let target_result = target.await.expect("join target execution");
    assert_eq!(target_result.0, ExecutionStatus::Cancelled);
    let unrelated_result = unrelated.await.expect("join unrelated execution");
    assert_eq!(unrelated_result.0, ExecutionStatus::Completed);
    assert!(unrelated_result.2.contains("unrelated-ok"));

    let child_pid: i32 = std::fs::read_to_string(&child_path)
        .expect("read target child pid")
        .parse()
        .expect("parse target child pid");
    let descendant_reaped = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let present = unsafe { libc::kill(child_pid, 0) } == 0;
            if !present {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        descendant_reaped.is_ok(),
        "target descendant survived cancellation"
    );

    supervisor.clear_remote_requests();
    let (_after_cancel_tx, after_cancel_rx) = tokio::sync::watch::channel(false);
    let after = process_request(&config, "after-request");
    let after_result = supervisor
        .run_process(&after, "request-after", 3, after_cancel_rx)
        .await;
    assert_eq!(after_result.0, ExecutionStatus::Completed);
    assert!(after_result.2.contains("after-ok"));
}

#[tokio::test]
async fn helper_guard_stages_only_allowlisted_regular_files() {
    let request_root = tempfile::tempdir().expect("request root");
    let allowed_root = tempfile::tempdir().expect("allowed root");
    let outside_root = tempfile::tempdir().expect("outside root");
    let allowed_path = allowed_root.path().join("upload.txt");
    let outside_path = outside_root.path().join("secret.txt");
    std::fs::write(&allowed_path, b"allowed").expect("allowed file");
    std::fs::write(&outside_path, b"outside").expect("outside file");
    let allowlist = Allowlist::new(
        vec![allowed_root.path().canonicalize().expect("allowed path")],
        2,
        AllowlistLimits::default(),
    )
    .expect("allowlist");
    let socket_root = tempfile::tempdir().expect("socket root");
    let guard = FileGuardHandle::start(socket_root.path(), request_root.path(), 4, allowlist)
        .await
        .expect("guard");

    let accepted = guard_request(
        &guard.socket_path,
        &allowed_path.canonicalize().expect("canonical upload"),
    )
    .await;
    assert_eq!(
        accepted.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let staged = accepted
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("staged path");
    assert!(std::path::Path::new(staged).starts_with(request_root.path()));
    assert_eq!(std::fs::read(staged).expect("staged contents"), b"allowed");

    let rejected = guard_request(
        &guard.socket_path,
        &outside_path.canonicalize().expect("canonical outside"),
    )
    .await;
    assert_eq!(
        rejected.get("ok").and_then(serde_json::Value::as_bool),
        Some(false)
    );

    let download_path = allowed_root
        .path()
        .canonicalize()
        .expect("canonical allowed root")
        .join("download.txt");
    std::fs::write(&download_path, b"old download").expect("existing download");
    let prepared = guard_request_value(
        &guard.socket_path,
        serde_json::json!({
            "operation": "prepare_download",
            "path": download_path,
            "token": null,
        }),
    )
    .await;
    assert_eq!(
        prepared.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let staging_path = prepared
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("download staging path");
    assert!(std::path::Path::new(staging_path).starts_with(
        allowed_root
            .path()
            .canonicalize()
            .expect("canonical staging root")
    ));
    let token = prepared
        .get("token")
        .and_then(serde_json::Value::as_str)
        .expect("download token");
    std::fs::write(staging_path, b"downloaded").expect("staged download");
    let committed = guard_request_value(
        &guard.socket_path,
        serde_json::json!({
            "operation": "commit_download",
            "path": staging_path,
            "token": token,
        }),
    )
    .await;
    assert_eq!(
        committed.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        std::fs::read(download_path).expect("download contents"),
        b"downloaded"
    );
    guard.stop().await;

    let limited_root = tempfile::tempdir().expect("limited allowlist root");
    let limited_root_path = limited_root.path().canonicalize().expect("limited root");
    let limited_allowlist = Allowlist::new(
        vec![limited_root_path.clone()],
        3,
        AllowlistLimits {
            max_file_bytes: 4,
            max_total_bytes: 8,
            max_file_count: 1,
        },
    )
    .expect("limited allowlist");
    let limited_socket = tempfile::tempdir().expect("limited socket root");
    let limited_request = tempfile::tempdir().expect("limited request root");
    let limited_guard = FileGuardHandle::start(
        limited_socket.path(),
        limited_request.path(),
        5,
        limited_allowlist,
    )
    .await
    .expect("limited guard");
    let limited_destination = limited_root_path.join("one.txt");
    std::fs::write(&limited_destination, b"old").expect("limited existing output");
    let first = guard_request_value(
        &limited_guard.socket_path,
        serde_json::json!({
            "operation": "prepare_download",
            "path": limited_destination,
            "token": null,
        }),
    )
    .await;
    assert_eq!(
        first.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let second = guard_request_value(
        &limited_guard.socket_path,
        serde_json::json!({
            "operation": "prepare_download",
            "path": limited_root_path.join("two.txt"),
            "token": null,
        }),
    )
    .await;
    assert_eq!(
        second.get("ok").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let first_staging = first
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("reserved staging path");
    let first_token = first
        .get("token")
        .and_then(serde_json::Value::as_str)
        .expect("reserved staging token");
    std::fs::write(first_staging, b"large").expect("oversized staged output");
    let oversized = guard_request_value(
        &limited_guard.socket_path,
        serde_json::json!({
            "operation": "commit_download",
            "path": first_staging,
            "token": first_token,
        }),
    )
    .await;
    assert_eq!(
        oversized.get("ok").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        std::fs::read(&limited_destination).expect("unchanged limited output"),
        b"old"
    );
    assert!(!std::path::Path::new(first_staging).exists());
    limited_guard.stop().await;
}

#[test]
fn helper_preamble_fails_closed_without_an_allowlist() {
    let script =
        helper_guard_script(None, "agent-remote:session-test", "cliLog('done')").expect("preamble");
    assert!(script.contains("helper file allowlist is not configured"));
    assert!(script.contains("globalThis.setInputFiles = rejectHelperFile"));
    assert!(script.contains("globalThis.download.saveAs = rejectHelperFile"));
    assert!(script.contains("const agentRemoteDefaultTaskSpace = \"agent-remote:session-test\";"));
    assert!(script.contains("globalThis.useOrCreateTaskSpace = async function"));
    assert!(script
        .contains("agentRemoteUseOrCreateTaskSpace.call(globalThis, agentRemoteDefaultTaskSpace"));
    assert!(!script.contains("globalThis.takeOverTaskSpace ="));
    assert!(!script.contains("globalThis.claimTaskSpace ="));
    assert!(script.ends_with("cliLog('done')"));
}

#[test]
fn helper_preamble_rejects_a_non_dedicated_task_space() {
    assert!(helper_guard_script(None, "user-owned-space", "cliLog('done')").is_err());
}

async fn guard_request(socket: &std::path::Path, path: &std::path::Path) -> serde_json::Value {
    guard_request_value(
        socket,
        serde_json::json!({
            "operation": "upload",
            "path": path,
            "token": null,
        }),
    )
    .await
}

async fn guard_request_value(
    socket: &std::path::Path,
    value: serde_json::Value,
) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).await.expect("connect guard");
    let mut request = serde_json::to_vec(&value).expect("request");
    request.push(b'\n');
    stream.write_all(&request).await.expect("write request");
    stream.shutdown().await.expect("finish request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    serde_json::from_slice(&response).expect("response")
}
