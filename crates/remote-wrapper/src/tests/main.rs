use super::inner_request_from_permit;
use ego_browser_bridge_protocol::{ConcurrencyMode, RequestPermit};

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
