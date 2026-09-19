use super::*;
use ego_browser_device::{public_value_sha256, PendingRegistration};

fn pending_fixture(store: &CredentialStore, created_at_unix: u64) -> PendingRegistration {
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    store.save_identity(&identity).unwrap();
    let pending = PendingRegistration {
        version: 1,
        device_id: identity.device_id.clone(),
        device_generation: identity.generation,
        server_url: "https://control.example".into(),
        release_profile: identity.release_profile.clone(),
        credential_profile: identity.credential_profile.clone(),
        enrollment_mode: "initial".into(),
        signing_public_key_sha256: public_value_sha256(&identity.public_key_b64()),
        encryption_public_key_sha256: public_value_sha256(&identity.encryption_public_key_b64()),
        idempotency_key: "original-registration-operation-key".into(),
        created_at_unix,
        last_error_code: Some("pending_expired".into()),
    };
    // An interrupted first enrollment may have only its pending record and key.
    store.save_pending_registration(&pending).unwrap();
    pending
}

#[tokio::test]
async fn explicit_reenrollment_recovers_expired_pending_without_replacing_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CredentialStore::new(temporary.path().join("device")).unwrap();
    let original = pending_fixture(&store, 1);
    let key_path = temporary.path().join("device/ego-browser-device-key.bin");
    let original_key = fs::read(&key_path).unwrap();
    let args = vec![
        "--re-enroll".into(),
        "--token".into(),
        "test-user-token".into(),
    ];

    // The isolated store has no signed policy, so execution stops before HTTP.
    let error = crate::registration::ensure(&store, args.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CredentialError>(),
        Some(CredentialError::CompatibilityMismatch)
    ));
    let recovered = store.load_pending_registration().unwrap();
    assert_eq!(recovered.enrollment_mode, "re_enroll");
    assert_ne!(recovered.idempotency_key, original.idempotency_key);
    assert!(!recovered.is_expired(now()));
    assert_eq!(recovered.device_id, original.device_id);
    assert_eq!(recovered.device_generation, original.device_generation);
    assert_eq!(
        recovered.signing_public_key_sha256,
        original.signing_public_key_sha256
    );
    assert_eq!(
        recovered.encryption_public_key_sha256,
        original.encryption_public_key_sha256
    );
    assert_eq!(fs::read(&key_path).unwrap(), original_key);

    crate::registration::ensure(&store, args).await.unwrap_err();
    assert_eq!(store.load_pending_registration().unwrap(), recovered);
}

#[tokio::test]
async fn expired_recovery_rejects_implicit_or_mismatched_requests_without_losing_state() {
    for (options, expected) in [
        (vec![], "pending_expired"),
        (vec!["--force-refresh"], "pending_expired"),
        (vec!["--re-enroll"], "token"),
        (
            vec![
                "--re-enroll",
                "--token",
                "test",
                "--server",
                "https://other.example",
            ],
            "identity_origin_conflict",
        ),
        (
            vec![
                "--re-enroll",
                "--token",
                "test",
                "--release-profile",
                "other",
            ],
            "compatibility_mismatch",
        ),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let store = CredentialStore::new(temporary.path().join("device")).unwrap();
        let original = pending_fixture(&store, 1);
        let error =
            crate::registration::ensure(&store, options.into_iter().map(str::to_owned).collect())
                .await
                .unwrap_err();
        let code = error
            .downcast_ref::<CredentialError>()
            .map(|error| error.log_code().to_owned())
            .unwrap_or_else(|| error.to_string());
        assert!(code.contains(expected), "unexpected error: {code}");
        assert_eq!(store.read_pending_registration().unwrap(), original);
    }
}

#[tokio::test]
async fn reenrollment_rejects_expired_pending_with_different_key_digest() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CredentialStore::new(temporary.path().join("device")).unwrap();
    let mut original = pending_fixture(&store, 1);
    original.signing_public_key_sha256 = "0".repeat(64);
    store.save_pending_registration(&original).unwrap();
    let error = crate::registration::ensure(
        &store,
        vec!["--re-enroll".into(), "--token".into(), "test".into()],
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CredentialError>(),
        Some(CredentialError::Malformed)
    ));
    assert_eq!(store.read_pending_registration().unwrap(), original);
}
