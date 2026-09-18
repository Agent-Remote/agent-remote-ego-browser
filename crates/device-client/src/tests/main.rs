use super::*;
use ego_browser_device::{migrate_legacy_device_store, StoredIdentityMetadata, CORE_CAPABILITIES};
use tokio::io::AsyncReadExt;

#[cfg(unix)]
#[test]
fn legacy_default_store_migrates_without_overwriting_canonical_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let legacy = temporary.path().join("legacy");
    let canonical = temporary.path().join("canonical");
    fs::create_dir_all(&legacy).expect("legacy directory");
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).expect("legacy permissions");
    let credential = legacy.join("ego-browser-credential.json");
    fs::write(&credential, b"legacy-state").expect("legacy state");
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
        .expect("legacy state permissions");

    migrate_legacy_device_store(&legacy, &canonical).expect("migrate legacy store");
    assert!(!legacy.exists());
    assert_eq!(
        fs::read(canonical.join("ego-browser-credential.json")).unwrap(),
        b"legacy-state"
    );

    migrate_legacy_device_store(&legacy, &canonical).expect("idempotent migration");
}

#[cfg(unix)]
#[test]
fn legacy_store_migration_rejects_symlinked_state() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let legacy = temporary.path().join("legacy");
    let canonical = temporary.path().join("canonical");
    fs::create_dir_all(&legacy).expect("legacy directory");
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).expect("legacy permissions");
    let outside = temporary.path().join("outside");
    fs::write(&outside, b"secret").expect("outside state");
    symlink(&outside, legacy.join("ego-browser-device-key.bin")).expect("state symlink");
    assert!(matches!(
        migrate_legacy_device_store(&legacy, &canonical),
        Err(CredentialError::InvalidPath)
    ));
    assert!(!canonical.exists());
}

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
fn admission_api_errors_use_one_stable_lifecycle_code() {
    for code in [
        "EGO_BROWSER_ENROLLMENT_DISABLED",
        "EGO_BROWSER_ENROLLMENT_ADMISSION_DISABLED",
        "EGO_BROWSER_EXECUTION_ADMISSION_DISABLED",
    ] {
        let error = CredentialError::ApiCode {
            status: 503,
            code: code.to_owned(),
        };
        assert_eq!(error.log_code(), "admission_disabled");
        assert!(!error.is_retryable_ensure_error());
    }
}

#[test]
fn local_compatibility_errors_use_one_stable_lifecycle_code() {
    let error = CredentialError::CompatibilityMismatch;
    assert_eq!(error.log_code(), "compatibility_mismatch");
    assert_eq!(
        top_level_error_line(&error),
        "ego-browser-device error=compatibility_mismatch"
    );
}

#[test]
fn ensure_rejects_a_retained_identity_on_a_different_server_origin() {
    let credential = CommunityCredential {
        version: 1,
        device_id: "device-origin".to_owned(),
        server_url: "https://old.example".to_owned(),
        token: "redacted".to_owned(),
        credential_id: Some("credential-origin".to_owned()),
        release_profile: "community-local-trust".to_owned(),
        credential_profile: "community_file".to_owned(),
        expires_at_unix: 4_000_000_000,
        revision: 1,
    };
    let metadata = StoredIdentityMetadata {
        version: 1,
        device_id: "device-origin".to_owned(),
        server_url: "https://old.example".to_owned(),
        release_profile: "community-local-trust".to_owned(),
        credential_profile: "community_file".to_owned(),
    };
    let error = crate::registration::validate_requested_origin(
        "https://new.example",
        Some(&credential),
        Some(&metadata),
    )
    .expect_err("origin change must require explicit switch-server");
    assert_eq!(error.log_code(), "identity_origin_conflict");
    assert!(crate::registration::validate_requested_origin(
        "https://old.example",
        Some(&credential),
        Some(&metadata),
    )
    .is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn ensure_rejects_an_orphaned_corrupt_key_without_replacing_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let store_directory = temporary.path().join("device-store");
    let store = CredentialStore::new(store_directory.clone()).expect("credential store");
    let key_path = store_directory.join("ego-browser-device-key.bin");
    let original_key = b"orphaned-corrupt-device-key";
    fs::write(&key_path, original_key).expect("write corrupt key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("set corrupt key permissions");

    let error = crate::registration::ensure(
        &store,
        vec!["--server".to_owned(), "https://control.example".to_owned()],
    )
    .await
    .expect_err("orphaned key must require explicit identity recovery");

    assert!(matches!(
        error.downcast_ref::<CredentialError>(),
        Some(CredentialError::Malformed)
    ));
    assert_eq!(
        fs::read(&key_path).expect("read retained key"),
        original_key
    );
    for name in [
        "ego-browser-device-metadata.json",
        "ego-browser-pending-registration.json",
        "ego-browser-credential.json",
        "ego-browser-local-admission.json",
    ] {
        assert!(
            !store_directory.join(name).exists(),
            "ensure unexpectedly created {name}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ensure_rejects_release_profile_change_without_migrating_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let store_directory = temporary.path().join("device-store");
    let store = CredentialStore::new(store_directory.clone()).expect("credential store");
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let credential = CommunityCredential {
        version: 1,
        device_id: identity.device_id.clone(),
        server_url: "https://control.example".to_owned(),
        token: "egbc_retained-token".to_owned(),
        credential_id: Some("credential-retained".to_owned()),
        release_profile: identity.release_profile.clone(),
        credential_profile: identity.credential_profile.clone(),
        expires_at_unix: 4_000_000_000,
        revision: 1,
    };
    store.save_identity(&identity).expect("save identity");
    store
        .save_identity_metadata(&identity, &credential.server_url)
        .expect("save identity metadata");
    store.save(&credential).expect("save credential");
    let key_path = store_directory.join("ego-browser-device-key.bin");
    let original_key = fs::read(&key_path).expect("read original key");

    let error = crate::registration::ensure(
        &store,
        vec![
            "--server".to_owned(),
            credential.server_url.clone(),
            "--release-profile".to_owned(),
            "different-profile".to_owned(),
        ],
    )
    .await
    .expect_err("profile migration must require an explicit upgrade flow");

    assert!(matches!(
        error.downcast_ref::<CredentialError>(),
        Some(CredentialError::CompatibilityMismatch)
    ));
    assert_eq!(
        fs::read(&key_path).expect("read retained key"),
        original_key
    );
    assert!(!store_directory
        .join("ego-browser-pending-registration.json")
        .exists());
    assert_eq!(
        store.load_for_rotation().expect("retained credential"),
        credential
    );
}

#[test]
fn pending_ensure_reuses_only_a_credential_outside_refresh_skew() {
    let mut credential = CommunityCredential {
        version: 1,
        device_id: "device-refresh".to_owned(),
        server_url: "https://control.example".to_owned(),
        token: "redacted".to_owned(),
        credential_id: Some("credential-refresh".to_owned()),
        release_profile: "community-local-trust".to_owned(),
        credential_profile: "community_file".to_owned(),
        expires_at_unix: 10_301,
        revision: 1,
    };
    assert!(crate::registration::credential_is_fresh(
        &credential,
        10_000
    ));
    credential.expires_at_unix = 10_300;
    assert!(!crate::registration::credential_is_fresh(
        &credential,
        10_000
    ));
    credential.expires_at_unix = 9_999;
    assert!(!crate::registration::credential_is_fresh(
        &credential,
        10_000
    ));
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
#[cfg(not(target_os = "macos"))]
fn production_signer_requires_the_canonical_trust_pin() {
    let canonical = TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256.to_owned();
    assert_eq!(
        signer_certificate_sha256_for_profile(
            &[
                "--release-profile".into(),
                "community-local-trust".into(),
                "--signer-certificate-sha256".into(),
                canonical.clone(),
            ],
            None
        )
        .expect("canonical pin"),
        canonical
    );
    assert!(signer_certificate_sha256_for_profile(
        &[
            "--release-profile".into(),
            "community-local-trust".into(),
            "--signer-certificate-sha256".into(),
            "a".repeat(64),
        ],
        None
    )
    .is_err());
}

#[test]
fn development_signer_sentinel_is_restricted_to_development_profiles() {
    assert_eq!(
        signer_certificate_sha256_for_profile(
            &["--release-profile".into(), "logic-test".into()],
            None
        )
        .expect("development sentinel"),
        "development"
    );
    assert!(signer_certificate_sha256_for_profile(
        &[
            "--release-profile".into(),
            "community-local-trust".into(),
            "--signer-certificate-sha256".into(),
            "development".into(),
        ],
        None
    )
    .is_err());
}

#[test]
fn malformed_release_manifest_is_rejected_before_digest_use() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("release-manifest.json");
    fs::write(&path, br#"{"schema_version":3,"components":{}}"#).expect("manifest");
    assert!(validate_release_manifest(&path).is_err());
}

fn root_release_manifest(version: &str, replaces_profile: &str) -> serde_json::Value {
    let common = |name: &str, component_version: &str| {
        serde_json::json!({
            "repository": format!("Agent-Remote/{name}"),
            "release_workflow": "release.yml",
            "version": component_version,
            "commit": "a".repeat(40)
        })
    };
    let artifact_url = format!(
        "https://github.com/Agent-Remote/agent-remote-ego-browser/releases/download/v{version}/agent-remote-ego-browser-macos-universal-{version}.tar.gz"
    );
    serde_json::json!({
        "schema_version": 4,
        "distribution_version": "9.0.0",
        "components": {
            "agent-remote-server": common("agent-remote-server", "1.0.0"),
            "agent-remote-node": common("agent-remote-node", "1.0.0"),
            "agent-remote-cli": common("agent-remote-cli", "1.0.0"),
            "agent-remote-admin-web": common("agent-remote-admin-web", "1.0.0"),
            "agent-remote-local-app": common("agent-remote-local-app", "1.0.0"),
            "agent-remote-ego-browser": {
                "admission_policy_ref": "server-policy:ego-browser-v1",
                "allowed_server_origins": ["$active_login_origin"],
                "apple_notarized": false,
                "artifact_sha256": "b".repeat(64),
                "artifact_url": artifact_url,
                "bridge_manifest_sha256": "c".repeat(64),
                "bridge_protocol_version": PROTOCOL_VERSION,
                "bridge_version": version,
                "commit": "d".repeat(40),
                "credential_profile": "community_file",
                "ego_lite_installer_commit": EGO_LITE_INSTALLER_COMMIT,
                "ego_lite_installer_sha256": EGO_LITE_INSTALLER_SHA256,
                "ego_lite_installer_url": format!(
                    "https://raw.githubusercontent.com/citrolabs/ego-lite/{EGO_LITE_INSTALLER_COMMIT}/skills/ego-browser/scripts/install.sh"
                ),
                "ego_lite_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
                "hardened_runtime": true,
                "issued_at": "2026-09-14T00:00:00Z",
                "learning_bundle_digest": "e".repeat(64),
                "learning_bundle_signing_key_id": "ego-browser-learning-2026-09-v2",
                "local_ego_browser_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
                "nested_signatures_verified": true,
                "outbound_policy": "application-enforced",
                "production_ready": true,
                "profile": "community-local-trust",
                "profile_id": "community-local-trust",
                "profile_version": version,
                "protocol_version": PROTOCOL_VERSION,
                "public_distribution": false,
                "readiness_blockers": [],
                "release_published": true,
                "release_workflow": "release.yml",
                "replaces_profile": replaces_profile,
                "repository": "Agent-Remote/agent-remote-ego-browser",
                "signer_certificate_sha256": TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256,
                "signing_type": "project-self-signed",
                "skill_commit": EGO_LITE_INSTALLER_COMMIT,
                "skill_tree_sha256": SUPPORTED_SKILL_TREE_SHA256,
                "skill_version": SUPPORTED_SKILL_VERSION,
                "valid_platforms": ["macos"],
                "version": version,
                "wrapper_version": version
            }
        }
    })
}

#[test]
fn schema_four_profile_authenticates_only_the_compiled_bridge_version() {
    let current = root_release_manifest(env!("CARGO_PKG_VERSION"), REPLACED_COMMUNITY_PROFILE);
    let evidence = validate_release_manifest_value(&current).expect("current schema-four profile");
    assert_eq!(evidence.profile, "community-local-trust");

    let stable = root_release_manifest("0.1.11", "community-local-trust@0.1.10");
    assert!(validate_release_manifest_value(&stable).is_err());
}

#[test]
fn schema_three_root_remains_compatible_only_for_the_compiled_version() {
    let mut legacy = root_release_manifest(env!("CARGO_PKG_VERSION"), REPLACED_COMMUNITY_PROFILE);
    legacy["schema_version"] = serde_json::json!(3);
    let browser = legacy["components"]["agent-remote-ego-browser"]
        .as_object_mut()
        .expect("browser component");
    for field in [
        "admission_policy_ref",
        "allowed_server_origins",
        "artifact_sha256",
        "artifact_url",
        "bridge_manifest_sha256",
        "bridge_protocol_version",
        "bridge_version",
        "ego_lite_installer_commit",
        "ego_lite_installer_sha256",
        "ego_lite_installer_url",
        "ego_lite_runtime_version",
        "issued_at",
        "profile_id",
        "profile_version",
        "replaces_profile",
        "valid_platforms",
        "wrapper_version",
    ] {
        browser.remove(field);
    }
    validate_release_manifest_value(&legacy).expect("same-version schema-three profile");
}

#[test]
fn signing_evidence_schema_one_is_validated_against_the_builtin_pin() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("SIGNING-EVIDENCE.json");
    let evidence = serde_json::json!({
        "schema_version": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "profile": "community-local-trust",
        "production_ready": true,
        "readiness_blockers": [],
        "apple_notarized": false,
        "public_distribution": false,
        "signing_type": "project-self-signed",
        "signer_certificate_sha256": TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256,
        "bridge_signature_verified": true,
        "device_client_signature_verified": true,
        "nested_signatures_verified": true,
        "hardened_runtime": true,
        "outbound_policy": "application-enforced",
        "credential_profile": "community_file",
        "learning_bundle_digest": "a".repeat(64),
        "learning_bundle_signing_key_id": "ego-browser-learning-2026-09-v2"
    });
    fs::write(&path, serde_json::to_vec(&evidence).expect("evidence")).expect("write evidence");
    let parsed = validate_release_artifact(&path).expect("validated signing evidence");
    assert_eq!(parsed.profile, "community-local-trust");
    assert_eq!(
        parsed.signer_certificate_sha256,
        TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256
    );

    let mut stale = evidence;
    stale["version"] = serde_json::json!("0.1.11");
    fs::write(&path, serde_json::to_vec(&stale).expect("stale evidence"))
        .expect("write stale evidence");
    assert!(validate_release_artifact(&path).is_err());
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
fn installed_certificate_pin_path_follows_canonical_release_layout() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let executable = temporary
        .path()
        .join("releases/0.1.11/bin/ego-browser-device");
    fs::create_dir_all(executable.parent().expect("binary parent")).expect("release layout");
    fs::write(&executable, b"binary").expect("binary");
    let expected = temporary
        .path()
        .canonicalize()
        .expect("canonical temporary directory")
        .join("TRUSTED_CERTIFICATE_SHA256");
    assert_eq!(installed_certificate_pin_path(&executable), Some(expected));
    let unrelated = temporary.path().join("bin/ego-browser-device");
    fs::create_dir_all(unrelated.parent().expect("unrelated parent")).expect("unrelated layout");
    fs::write(&unrelated, b"binary").expect("unrelated binary");
    assert_eq!(installed_certificate_pin_path(&unrelated), None);
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
fn canonical_registration_response_requires_explicit_lifecycle_fields() {
    let mut identity = DeviceIdentity::generate("community-local-trust", "community_file");
    identity.device_id = "canonical-response-device".into();
    identity.generation = 3;
    let certificate = "a".repeat(64);
    let policy_digest = "b".repeat(64);
    let capability_digest = "c".repeat(64);
    let submitted = serde_json::json!({
        "platform": "macos",
        "bridge_protocol_version": PROTOCOL_VERSION,
        "bridge_version": env!("CARGO_PKG_VERSION"),
        "local_ego_browser_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
        "ego_lite_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
        "skill_version": SUPPORTED_SKILL_VERSION,
        "allowlist_revision": 1,
        "allowlist_roots_digest": null,
        "learning_bundle_digest": null,
        "capabilities": CORE_CAPABILITIES,
        "policy_digest": policy_digest,
        "capability_digest": capability_digest,
    });
    let expires_at = "2099-01-01T00:00:00Z";
    let expires_in =
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .expect("parse credential expiry")
            .unix_timestamp() as u64
            - super::now();
    let response = serde_json::json!({
        "data": {
            "id": identity.device_id,
            "device_id": identity.device_id,
            "generation": identity.generation,
            "device_generation": identity.generation,
            "status": "active",
            "public_key": identity.public_key_b64(),
            "signing_public_key": identity.public_key_b64(),
            "encryption_public_key": identity.encryption_public_key_b64(),
            "release_profile": identity.release_profile,
            "credential_profile": identity.credential_profile,
            "signer_certificate_sha256": certificate,
            "server_origin": "https://control.example.test",
            "platform": "macos",
            "bridge_protocol_version": PROTOCOL_VERSION,
            "bridge_version": env!("CARGO_PKG_VERSION"),
            "local_ego_browser_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
            "ego_lite_runtime_version": SUPPORTED_LOCAL_RUNTIME_VERSION,
            "skill_version": SUPPORTED_SKILL_VERSION,
            "allowlist_revision": 1,
            "allowlist_roots_digest": null,
            "learning_bundle_digest": null,
            "capabilities": CORE_CAPABILITIES,
            "policy_digest": policy_digest,
            "capability_digest": capability_digest,
            "credential": {
                "id": "credential-canonical",
                "ego_browser_device_id": identity.device_id,
                "credential_profile": identity.credential_profile,
                "generation": identity.generation,
                "device_generation": identity.generation,
                "revision": 7,
                "credential_revision": 7,
                "expires_at": expires_at,
                "credential_expires_at": expires_at,
                "credential_scope": "device",
                "access_token": "egbc_canonical-response-token",
                "token_type": "bearer",
                "expires_in": expires_in,
            }
        }
    });

    credential_from_registration_response_strict(
        &response,
        "https://control.example.test",
        &identity,
        &certificate,
        &submitted,
        Some(6),
    )
    .expect("validate canonical response");

    for field in [
        "device_id",
        "device_generation",
        "signing_public_key",
        "server_origin",
        "platform",
        "bridge_protocol_version",
        "bridge_version",
        "local_ego_browser_runtime_version",
        "ego_lite_runtime_version",
        "skill_version",
        "allowlist_revision",
        "allowlist_roots_digest",
        "learning_bundle_digest",
        "capabilities",
        "policy_digest",
        "capability_digest",
    ] {
        let mut missing = response.clone();
        missing["data"]
            .as_object_mut()
            .expect("device object")
            .remove(field);
        assert!(credential_from_registration_response_strict(
            &missing,
            "https://control.example.test",
            &identity,
            &certificate,
            &submitted,
            Some(6),
        )
        .is_err());
    }

    for field in [
        "device_generation",
        "credential_revision",
        "credential_expires_at",
        "credential_scope",
    ] {
        let mut missing = response.clone();
        missing["data"]["credential"]
            .as_object_mut()
            .expect("credential object")
            .remove(field);
        assert!(credential_from_registration_response_strict(
            &missing,
            "https://control.example.test",
            &identity,
            &certificate,
            &submitted,
            Some(6),
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

#[cfg(unix)]
#[tokio::test]
async fn device_service_heartbeat_reflects_the_shared_local_admission_gate() {
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
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let credential = CommunityCredential {
        version: 1,
        device_id: identity.device_id.clone(),
        server_url: "https://control.example.test".into(),
        token: "egbc_service-token".into(),
        credential_id: Some("credential-service".into()),
        release_profile: identity.release_profile.clone(),
        credential_profile: identity.credential_profile.clone(),
        expires_at_unix: 4_000_000_000,
        revision: 1,
    };
    store.save_identity(&identity).expect("identity");
    store.save(&credential).expect("credential");
    let binding = ActiveBinding {
        version: 1,
        binding_id: "binding-service".into(),
        generation: 2,
        device_id: identity.device_id.clone(),
        task_space_label: "agent-remote:11111111-2222-3333-4444-555555555555".into(),
        authorization_mode: "ego_browser_script_full_trust".into(),
        user_confirmation: true,
    };
    store.save_active_binding(&binding).expect("active binding");
    store.open_local_admission(&binding).expect("open gate");

    let socket_path = store.device_service_socket_path();
    let listener = prepare_device_service_listener(&socket_path).expect("device listener");
    let server_store = store.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept admitted peer");
        serve_device_peer_with_store(stream, server_store).await;
    });
    let mut client = UnixStream::connect(&socket_path)
        .await
        .expect("connect peer");
    let mut heartbeat = [0_u8; DEVICE_PEER_HEARTBEAT.len()];
    client
        .read_exact(&mut heartbeat)
        .await
        .expect("read alive heartbeat");
    assert_eq!(&heartbeat, DEVICE_PEER_HEARTBEAT);
    drop(client);
    server.await.expect("join admitted service");

    store.close_local_admission().expect("close gate");
    let listener = prepare_device_service_listener(&socket_path).expect("rebind device listener");
    let server_store = store.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept closed peer");
        serve_device_peer_with_store(stream, server_store).await;
    });
    let mut client = UnixStream::connect(&socket_path)
        .await
        .expect("connect closed peer");
    let mut heartbeat = [0_u8; DEVICE_PEER_ADMISSION_CLOSED.len()];
    client
        .read_exact(&mut heartbeat)
        .await
        .expect("read closed heartbeat");
    assert_eq!(&heartbeat, DEVICE_PEER_ADMISSION_CLOSED);
    drop(client);
    server.await.expect("join closed service");
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_local_admission_closes_the_peer_without_an_explicit_close_frame() {
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
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let credential = CommunityCredential {
        version: 1,
        device_id: identity.device_id.clone(),
        server_url: "https://control.example.test".into(),
        token: "egbc_invalid-admission-token".into(),
        credential_id: Some("credential-invalid-admission".into()),
        release_profile: identity.release_profile.clone(),
        credential_profile: identity.credential_profile.clone(),
        expires_at_unix: 4_000_000_000,
        revision: 1,
    };
    store.save_identity(&identity).expect("identity");
    store.save(&credential).expect("credential");
    let binding = ActiveBinding {
        version: 1,
        binding_id: "binding-invalid-admission".into(),
        generation: 2,
        device_id: identity.device_id.clone(),
        task_space_label: "agent-remote:11111111-2222-3333-4444-555555555555".into(),
        authorization_mode: "ego_browser_script_full_trust".into(),
        user_confirmation: true,
    };
    store.save_active_binding(&binding).expect("active binding");
    store.open_local_admission(&binding).expect("open gate");
    fs::write(store.local_admission_path(), b"{not-json").expect("damage admission");

    let socket_path = store.device_service_socket_path();
    let listener = prepare_device_service_listener(&socket_path).expect("device listener");
    let server_store = store.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept invalid peer");
        serve_device_peer_with_store(stream, server_store).await;
    });
    let mut client = UnixStream::connect(&socket_path)
        .await
        .expect("connect invalid peer");
    let mut heartbeat = [0_u8; DEVICE_PEER_HEARTBEAT.len()];
    assert!(client.read_exact(&mut heartbeat).await.is_err());
    server.await.expect("join invalid service");
}
