use super::{decode_response, inner_request_from_permit, WrapperError};
use ego_browser_bridge_protocol::{ConcurrencyMode, RequestPermit};

fn test_permit() -> RequestPermit {
    RequestPermit {
        binding_id: "binding-test".into(),
        generation: 1,
        request_id: "request-test".into(),
        sequence: 1,
        expires_at_unix_ms: u64::MAX,
        max_payload_bytes: 1024,
        max_script_bytes: 1024,
        default_task_space: "agent-remote:session-test".into(),
        allowlist_revision: 1,
        learning_bundle_digest: None,
        concurrency_mode: ConcurrencyMode::Binding,
        task_space_scope: None,
        tab_scope: None,
    }
}

#[test]
fn broker_execution_errors_preserve_their_codes() {
    let cipher = super::SessionCipher::new(&[7; 32]);
    for code in [
        "bridge_unavailable",
        "lease_renewal_required",
        "lease_expired",
        "binding_revoked",
        "protocol_error",
        "concurrency_conflict",
    ] {
        let frame = serde_json::to_vec(&serde_json::json!({
            "protocol": super::PROTOCOL_VERSION, "type": "execute_result",
            "status": "error", "error": code,
        }))
        .unwrap();
        let error = decode_response(&frame, &cipher, &test_permit()).unwrap_err();
        assert!(matches!(error, WrapperError::Status(_)));
        assert_eq!(error.to_string(), code);
    }
}

#[test]
fn broker_error_frames_require_exact_protocol_shape_and_known_codes() {
    let cipher = super::SessionCipher::new(&[7; 32]);
    for (field, value) in [
        ("protocol", "wrong"),
        ("type", "permit_response"),
        ("status", "ok"),
        ("error", "untrusted-error-text"),
        ("extra", "unexpected"),
    ] {
        let mut frame = serde_json::json!({
            "protocol": super::PROTOCOL_VERSION, "type": "execute_result",
            "status": "error", "error": "bridge_unavailable",
        });
        frame[field] = value.into();
        let error = decode_response(
            &serde_json::to_vec(&frame).unwrap(),
            &cipher,
            &test_permit(),
        )
        .unwrap_err();
        assert!(matches!(error, WrapperError::Protocol(_)));
        assert!(!error.to_string().contains("untrusted-error-text"));
    }
    let duplicate = br#"{"protocol":"ego-browser-bridge-v1","type":"execute_result","status":"error","error":"bridge_unavailable","error":"lease_expired"}"#;
    assert!(matches!(
        decode_response(duplicate, &cipher, &test_permit()),
        Err(WrapperError::Protocol(_))
    ));
}

#[test]
fn inner_request_uses_the_broker_permit_task_space() {
    let permit = RequestPermit {
        binding_id: "binding-test".into(),
        generation: 1,
        request_id: "request-test".into(),
        sequence: 1,
        expires_at_unix_ms: u64::MAX,
        max_payload_bytes: 1024,
        max_script_bytes: 1024,
        default_task_space: "agent-remote:session-test".into(),
        allowlist_revision: 1,
        learning_bundle_digest: None,
        concurrency_mode: ConcurrencyMode::TaskSpace,
        task_space_scope: Some("agent-remote:session-test".into()),
        tab_scope: None,
    };
    let request = inner_request_from_permit(
        b"cliLog('done')".to_vec(),
        1_000,
        "workspace-default".into(),
        &permit,
    )
    .expect("inner request");

    assert_eq!(request.default_task_space, permit.default_task_space);
    assert_eq!(request.task_space_scope, permit.task_space_scope);
}
