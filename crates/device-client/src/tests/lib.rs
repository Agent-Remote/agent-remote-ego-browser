use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn server_origin_is_canonical_and_cannot_redirect_via_url_fields() {
    assert_eq!(
        canonical_server_url("https://control.example.test").expect("canonical origin"),
        "https://control.example.test"
    );
    assert_eq!(
        canonical_server_url("https://control.example.test:8443/")
            .expect("canonical explicit port"),
        "https://control.example.test:8443"
    );
    for invalid in [
        "http://control.example.test",
        "https://user@control.example.test",
        "https://control.example.test/api",
        "https://control.example.test/?next=https://other.example",
        "https://control.example.test/#fragment",
    ] {
        assert!(canonical_server_url(invalid).is_err(), "accepted {invalid}");
    }
    assert!(validate_api_id("binding-safe_1.2").is_ok());
    for invalid in ["", "../binding", "binding/path", "binding?other"] {
        assert!(validate_api_id(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn pause_reasons_are_a_finite_content_free_set() {
    for reason in [
        "user_pause",
        "task_space_takeover",
        "task_space_monitor_unavailable",
    ] {
        assert!(is_content_free_pause_reason(reason));
    }
    assert!(!is_content_free_pause_reason("sensitive-browser-content"));
}

#[test]
fn proof_signing_binds_payload_operation_and_independent_generations() {
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let challenge = b"01234567890123456789012345678901";
    let host = "bridge.example.test";
    let public_key = identity.public_key_b64();
    let binding_id = "dce2bb88-9e78-4c0d-b3ae-f9098fb70cb1";
    let payload = serde_json::json!({
        "generation": 8,
        "allowlist_revision": 7,
        "learning_bundle_digest": null
    });
    let binding_generation = identity.generation.saturating_add(7);
    let signature = identity
        .sign_request(
            "renew_binding",
            binding_generation,
            Some(binding_id),
            challenge,
            host,
            &payload,
        )
        .expect("sign payload-bound proof");
    assert!(DeviceIdentity::verify_request(
        "renew_binding",
        &identity.device_id,
        identity.generation,
        binding_generation,
        Some(binding_id),
        &identity.release_profile,
        &identity.credential_profile,
        host,
        challenge,
        &payload,
        &public_key,
        &signature,
    ));

    let mut changed_payload = payload.clone();
    changed_payload["allowlist_revision"] = serde_json::json!(8);
    assert!(!DeviceIdentity::verify_request(
        "renew_binding",
        &identity.device_id,
        identity.generation,
        binding_generation,
        Some(binding_id),
        &identity.release_profile,
        &identity.credential_profile,
        host,
        challenge,
        &changed_payload,
        &public_key,
        &signature,
    ));
    assert!(!DeviceIdentity::verify_request(
        "stop_binding",
        &identity.device_id,
        identity.generation,
        binding_generation,
        Some(binding_id),
        &identity.release_profile,
        &identity.credential_profile,
        host,
        challenge,
        &payload,
        &public_key,
        &signature,
    ));
}

async fn read_json_request(stream: &mut TcpStream) -> (String, serde_json::Value) {
    let mut request = Vec::new();
    let (header_end, content_length) = loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "request ended before headers were complete");
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() <= 16 * 1024, "request exceeded test bound");
        if let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        {
            let headers =
                String::from_utf8(request[..header_end].to_vec()).expect("UTF-8 request headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .expect("content length");
            break (header_end, content_length);
        }
    };
    while request.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "request ended before body was complete");
        request.extend_from_slice(&chunk[..read]);
    }
    let headers = String::from_utf8(request[..header_end].to_vec()).expect("UTF-8 request headers");
    let body = serde_json::from_slice(&request[header_end..header_end + content_length])
        .expect("JSON request body");
    (headers, body)
}

async fn write_json_response(stream: &mut TcpStream, body: &serde_json::Value) {
    let body = serde_json::to_vec(body).expect("serialize response");
    let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write response headers");
    stream.write_all(&body).await.expect("write response body");
}

#[tokio::test]
async fn device_revoke_uses_independent_pop_endpoint_and_exact_identity() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("server address");
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let expected_identity = identity.clone();
    let challenge = [7_u8; 32];
    let challenge_text = URL_SAFE_NO_PAD.encode(challenge);
    let expected_device_id = identity.device_id.clone();
    let server = tokio::spawn(async move {
        let (mut challenge_stream, _) = listener.accept().await.expect("challenge request");
        let (challenge_headers, challenge_body) = read_json_request(&mut challenge_stream).await;
        assert!(
            challenge_headers.starts_with("POST /api/v1/ego-browser/proof-challenges HTTP/1.1\r\n")
        );
        assert!(challenge_headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer egbc_test-token\r\n"));
        assert_eq!(
            challenge_body,
            serde_json::json!({
                "operation": "revoke_device",
                "ego_browser_device_id": expected_device_id,
                "generation": expected_identity.generation,
                "binding_id": null,
            })
        );
        write_json_response(
            &mut challenge_stream,
            &serde_json::json!({"data": {"challenge": challenge_text}}),
        )
        .await;

        let (mut revoke_stream, _) = listener.accept().await.expect("revoke request");
        let (revoke_headers, revoke_body) = read_json_request(&mut revoke_stream).await;
        assert!(revoke_headers.starts_with(&format!(
            "POST /api/v1/ego-browser/devices/{}/revoke HTTP/1.1\r\n",
            expected_identity.device_id
        )));
        assert!(revoke_headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer egbc_test-token\r\n"));
        let proof_challenge = revoke_body["proof_challenge"]
            .as_str()
            .expect("proof challenge");
        let proof_signature = revoke_body["proof_signature"]
            .as_str()
            .expect("proof signature");
        assert_eq!(proof_challenge, URL_SAFE_NO_PAD.encode(challenge));
        let unsigned_payload = serde_json::json!({
            "generation": expected_identity.generation,
            "reason": "device_revoked",
        });
        assert!(DeviceIdentity::verify_request(
            "revoke_device",
            &expected_identity.device_id,
            expected_identity.generation,
            expected_identity.generation,
            None,
            &expected_identity.release_profile,
            &expected_identity.credential_profile,
            "127.0.0.1",
            &challenge,
            &unsigned_payload,
            &expected_identity.public_key_b64(),
            proof_signature,
        ));
        write_json_response(
            &mut revoke_stream,
            &serde_json::json!({
                "data": {
                    "id": expected_identity.device_id,
                    "status": "revoked"
                }
            }),
        )
        .await;
    });

    let client = DeviceApiClient {
        http: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client"),
        base_url: format!("http://{address}"),
        token: "egbc_test-token".into(),
        identity: Some(identity),
    };
    let response = client.revoke_device().await.expect("revoke device");
    assert_eq!(response["data"]["status"], "revoked");
    server.await.expect("test server");
}

#[tokio::test]
async fn device_registration_rotation_is_signed_by_the_new_generation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("server address");
    let mut identity = DeviceIdentity::generate("community-local-trust", "community_file");
    identity.device_id = "rotation-device".into();
    identity.generation = 2;
    let expected_identity = identity.clone();
    let challenge = [9_u8; 32];
    let challenge_text = URL_SAFE_NO_PAD.encode(challenge);
    let payload = serde_json::json!({
        "device_id": identity.device_id,
        "public_key": identity.public_key_b64(),
        "encryption_public_key": identity.encryption_public_key_b64(),
        "generation": identity.generation,
        "release_profile": identity.release_profile,
        "credential_profile": identity.credential_profile,
        "platform": "macos",
    });
    let expected_payload = payload.clone();
    let server = tokio::spawn(async move {
        let (mut challenge_stream, _) = listener.accept().await.expect("challenge request");
        let (challenge_headers, challenge_body) = read_json_request(&mut challenge_stream).await;
        assert!(challenge_headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer user_test-token\r\n"));
        assert_eq!(
            challenge_body,
            serde_json::json!({
                "operation": "register_device",
                "ego_browser_device_id": expected_identity.device_id,
                "generation": expected_identity.generation,
                "binding_id": null,
            })
        );
        write_json_response(
            &mut challenge_stream,
            &serde_json::json!({"data": {"challenge": challenge_text}}),
        )
        .await;

        let (mut register_stream, _) = listener.accept().await.expect("register request");
        let (register_headers, mut register_body) = read_json_request(&mut register_stream).await;
        assert!(
            register_headers.starts_with("POST /api/v1/ego-browser/devices/register HTTP/1.1\r\n")
        );
        assert!(register_headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer user_test-token\r\n"));
        let proof_challenge = register_body
            .as_object_mut()
            .expect("registration object")
            .remove("proof_challenge")
            .and_then(|value| value.as_str().map(str::to_owned))
            .expect("proof challenge");
        let proof_signature = register_body
            .as_object_mut()
            .expect("registration object")
            .remove("proof_signature")
            .and_then(|value| value.as_str().map(str::to_owned))
            .expect("proof signature");
        assert_eq!(proof_challenge, URL_SAFE_NO_PAD.encode(challenge));
        assert_eq!(register_body, expected_payload);
        assert!(DeviceIdentity::verify_request(
            "register_device",
            &expected_identity.device_id,
            expected_identity.generation,
            expected_identity.generation,
            None,
            &expected_identity.release_profile,
            &expected_identity.credential_profile,
            "127.0.0.1",
            &challenge,
            &register_body,
            &expected_identity.public_key_b64(),
            &proof_signature,
        ));
        write_json_response(
            &mut register_stream,
            &serde_json::json!({"data": {"id": expected_identity.device_id}}),
        )
        .await;
    });

    let client = DeviceApiClient {
        http: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client"),
        base_url: format!("http://{address}"),
        token: "user_test-token".into(),
        identity: Some(identity),
    };
    let response = client
        .register_device(payload)
        .await
        .expect("rotate device registration");
    assert_eq!(response["data"]["id"], "rotation-device");
    server.await.expect("test server");
}

#[cfg(unix)]
fn test_store() -> (tempfile::TempDir, CredentialStore) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let directory = temporary.path().canonicalize().expect("canonical path");
    let store = CredentialStore::new(directory).expect("credential store");
    (temporary, store)
}

#[cfg(unix)]
#[test]
fn active_binding_handoff_is_owner_only_and_device_bound() {
    let (_temporary, store) = test_store();
    let binding = ActiveBinding {
        version: 1,
        binding_id: "binding-local-selection".into(),
        generation: 7,
        device_id: "device-local".into(),
        task_space_label: "agent-remote:session-local".into(),
        authorization_mode: "ego_browser_script_full_trust".into(),
        user_confirmation: true,
    };
    store
        .save_active_binding(&binding)
        .expect("save active binding");
    assert_eq!(
        store
            .load_active_binding("device-local")
            .expect("load active binding"),
        binding
    );
    assert!(store.load_active_binding("different-device").is_err());
    let metadata = fs::metadata(&store.active_binding_path).expect("binding metadata");
    assert_eq!(metadata.permissions().mode() & 0o077, 0);

    fs::set_permissions(
        &store.active_binding_path,
        fs::Permissions::from_mode(0o644),
    )
    .expect("make binding unsafe");
    assert!(matches!(
        store.load_active_binding("device-local"),
        Err(CredentialError::UnsafePermissions)
    ));
}

#[cfg(unix)]
#[test]
fn identity_rotation_is_monotonic_retryable_and_clears_the_old_handoff() {
    let (_temporary, store) = test_store();
    let current = DeviceIdentity::generate("community-local-trust", "community_file");
    let current_credential = CommunityCredential {
        version: 1,
        device_id: current.device_id.clone(),
        server_url: "https://control.example.test".into(),
        token: "egbc_current-token".into(),
        credential_id: Some("credential-current".into()),
        credential_profile: "community_file".into(),
        expires_at_unix: 100,
        revision: 3,
    };
    store
        .save_identity(&current)
        .expect("save current identity");
    store
        .save(&current_credential)
        .expect("save current credential");
    store
        .save_active_binding(&ActiveBinding {
            version: 1,
            binding_id: "binding-before-rotation".into(),
            generation: 7,
            device_id: current.device_id.clone(),
            task_space_label: "agent-remote:session-before-rotation".into(),
            authorization_mode: "ego_browser_script_full_trust".into(),
            user_confirmation: true,
        })
        .expect("save old handoff");

    let pending = store
        .prepare_identity_rotation(&current)
        .expect("prepare rotation");
    assert_eq!(pending.device_id, current.device_id);
    assert_eq!(pending.generation, current.generation + 1);
    assert_ne!(pending.public_key_b64(), current.public_key_b64());
    assert_ne!(
        pending.encryption_public_key_b64(),
        current.encryption_public_key_b64()
    );
    let recovered = store
        .prepare_identity_rotation(&current)
        .expect("recover pending rotation");
    assert_eq!(recovered.public_key_b64(), pending.public_key_b64());
    assert_eq!(
        recovered.encryption_public_key_b64(),
        pending.encryption_public_key_b64()
    );
    let pending_metadata =
        fs::metadata(&store.pending_key_rotation_path).expect("pending identity metadata");
    assert_eq!(pending_metadata.permissions().mode() & 0o777, 0o600);

    // Simulate a local failure after the new key was installed but before
    // the returned credential was saved. The exact pending key remains the
    // retry authority instead of generating a third, divergent key.
    store
        .save_identity(&pending)
        .expect("partially commit identity");
    let installed = store
        .load_identity(
            current.device_id.clone(),
            "community-local-trust".into(),
            "community_file".into(),
        )
        .expect("load partially committed identity");
    let recovered = store
        .prepare_identity_rotation(&installed)
        .expect("recover partially committed rotation");
    assert_eq!(recovered.generation, pending.generation);
    assert_eq!(recovered.public_key_b64(), pending.public_key_b64());

    let rotated_credential = CommunityCredential {
        token: "egbc_rotated-token".into(),
        credential_id: Some("credential-rotated".into()),
        expires_at_unix: 200,
        revision: 4,
        ..current_credential
    };
    store
        .commit_identity_rotation(&pending, &rotated_credential)
        .expect("commit rotation");
    assert_eq!(
        store
            .load_identity(
                pending.device_id.clone(),
                "community-local-trust".into(),
                "community_file".into(),
            )
            .expect("load rotated identity")
            .generation,
        pending.generation
    );
    assert_eq!(
        store.load_for_rotation().expect("load rotated credential"),
        rotated_credential
    );
    assert!(matches!(
        store.load_active_binding(&pending.device_id),
        Err(CredentialError::Missing)
    ));
    assert!(matches!(
        read_owner_file(&store.pending_key_rotation_path),
        Err(CredentialError::Missing)
    ));
}

#[cfg(unix)]
#[test]
fn credential_files_require_exact_0600_permissions() {
    let (_temporary, store) = test_store();
    let credential = CommunityCredential {
        version: 1,
        device_id: "strict-mode-device".into(),
        server_url: "https://control.example.test".into(),
        token: "egbc_strict-mode-token".into(),
        credential_id: Some("strict-mode-credential".into()),
        credential_profile: "community_file".into(),
        expires_at_unix: 100,
        revision: 1,
    };
    store.save(&credential).expect("save credential");
    fs::set_permissions(&store.credential_path, fs::Permissions::from_mode(0o700))
        .expect("change credential mode");
    assert!(matches!(
        store.load_for_rotation(),
        Err(CredentialError::UnsafePermissions)
    ));
}

#[cfg(unix)]
#[test]
fn credential_clear_validates_every_target_before_removing_any_file() {
    use std::os::unix::fs::symlink;

    let (_temporary, store) = test_store();
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let credential = CommunityCredential {
        version: 1,
        device_id: identity.device_id.clone(),
        server_url: "https://control.example.test".into(),
        token: "egbc_test-token".into(),
        credential_id: Some("credential-1".into()),
        credential_profile: "community_file".into(),
        expires_at_unix: 100,
        revision: 1,
    };
    store.save(&credential).expect("save credential");
    store.save_identity(&identity).expect("save identity");
    symlink(&store.credential_path, &store.active_binding_path).expect("unsafe handoff link");

    assert!(matches!(store.clear(), Err(CredentialError::InvalidPath)));
    assert!(store.credential_path.exists());
    assert!(store.key_path.exists());
    fs::remove_file(&store.active_binding_path).expect("remove unsafe link");

    store.clear().expect("clear credential state");
    assert!(!store.credential_path.exists());
    assert!(!store.key_path.exists());
}

#[cfg(unix)]
#[test]
fn policy_capabilities_require_verified_resources() {
    let (_temporary, store) = test_store();
    let (_, initial) = store.load_policy(None, None).expect("default policy");
    assert_eq!(initial.allowlist_revision, 1);
    assert!(initial.allowlist.is_none());
    assert!(initial.learning_bundle.is_none());
    assert!(!initial
        .capabilities()
        .iter()
        .any(|value| value == "ego_browser_file_allowlist_v1"));
    assert!(!initial
        .capabilities()
        .iter()
        .any(|value| value == "ego_browser_site_learning_v1"));

    let root = tempfile::tempdir().expect("allowlist root");
    let update = store
        .prepare_allowlist_update(vec![root
            .path()
            .canonicalize()
            .expect("canonical allowlist root")])
        .expect("prepared policy");
    store
        .commit_policy_update(&update)
        .expect("committed policy");
    let (document, verified) = store.load_policy(None, None).expect("verified policy");
    assert_eq!(document.allowlist_revision, 2);
    assert!(verified.allowlist.is_some());
    assert!(verified.allowlist_roots_digest.is_some());
    assert!(verified
        .capabilities()
        .iter()
        .any(|value| value == "ego_browser_file_allowlist_v1"));
}

#[cfg(unix)]
#[test]
fn policy_update_uses_exact_compare_and_swap() {
    let (_temporary, store) = test_store();
    let first_root = tempfile::tempdir().expect("first root");
    let second_root = tempfile::tempdir().expect("second root");
    let first = store
        .prepare_allowlist_update(vec![first_root.path().canonicalize().expect("first path")])
        .expect("first update");
    let stale = store
        .prepare_allowlist_update(vec![second_root
            .path()
            .canonicalize()
            .expect("second path")])
        .expect("stale update");
    store.commit_policy_update(&first).expect("first commit");
    assert!(matches!(
        store.commit_policy_update(&stale),
        Err(CredentialError::PolicyConflict)
    ));
}

#[cfg(unix)]
#[test]
fn policy_transaction_excludes_a_second_process_writer() {
    let (temporary, store) = test_store();
    let competing_store =
        CredentialStore::new(temporary.path().to_path_buf()).expect("competing store");
    let transaction = store.begin_policy_update().expect("first transaction");
    assert!(matches!(
        competing_store.begin_policy_update(),
        Err(CredentialError::PolicyConflict)
    ));

    let root = tempfile::tempdir().expect("allowlist root");
    let update = transaction
        .prepare_allowlist_update(vec![root.path().canonicalize().expect("root path")])
        .expect("prepared update");
    transaction
        .commit_policy_update(&update)
        .expect("committed update");
    drop(transaction);

    competing_store
        .begin_policy_update()
        .expect("lock released after transaction");
}

#[cfg(unix)]
#[test]
fn policy_tamper_and_unsafe_permissions_fail_closed() {
    let (_temporary, store) = test_store();
    let root = tempfile::tempdir().expect("allowlist root");
    let update = store
        .prepare_allowlist_update(vec![root.path().canonicalize().expect("root path")])
        .expect("update");
    store.commit_policy_update(&update).expect("commit");

    let mut document = store.load_policy_document().expect("document");
    document.allowlist_roots_digest = Some(format!("sha256:{}", "0".repeat(64)));
    fs::write(
        &store.policy_path,
        serde_json::to_vec(&document).expect("serialize policy"),
    )
    .expect("tamper policy");
    assert!(matches!(
        store.load_policy(None, None),
        Err(CredentialError::PolicyInvalid)
    ));

    fs::set_permissions(&store.policy_path, fs::Permissions::from_mode(0o644))
        .expect("unsafe mode");
    assert!(matches!(
        store.load_policy(None, None),
        Err(CredentialError::UnsafePermissions)
    ));
}
