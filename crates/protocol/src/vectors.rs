use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    canonical_json, device_proof_message, parse_strict_json, BridgeCapability, DeviceProofContext,
    InnerCancelRequest, InnerExecuteRequest, OuterEnvelope, RequestPermit,
};

const VECTORS: &[u8] = include_bytes!("../../../protocol/test-vectors/ego-browser-bridge-v1.json");

#[test]
fn shared_protocol_vectors_match_rust_contract() {
    let vectors: Value = parse_strict_json(VECTORS).expect("strict vector document");
    assert_eq!(vectors["schema_version"], 1);

    for case in vectors["canonical_json"]
        .as_array()
        .expect("canonical cases")
    {
        let actual = canonical_json(&case["input"]).expect("canonical JSON");
        assert_eq!(
            std::str::from_utf8(&actual).expect("canonical UTF-8"),
            case["canonical"].as_str().expect("canonical value")
        );
    }

    let proof = &vectors["device_pop_v2"];
    let context = DeviceProofContext {
        operation: proof["operation"].as_str().expect("proof operation"),
        device_id: proof["device_id"].as_str().expect("proof device"),
        device_generation: proof["device_generation"]
            .as_u64()
            .expect("device generation"),
        operation_generation: proof["operation_generation"]
            .as_u64()
            .expect("operation generation"),
        binding_id: proof["binding_id"].as_str(),
        release_profile: proof["release_profile"].as_str().expect("release profile"),
        credential_profile: proof["credential_profile"]
            .as_str()
            .expect("credential profile"),
        server_host: proof["server_host"].as_str().expect("server host"),
    };
    let challenge = URL_SAFE_NO_PAD
        .decode(proof["challenge"].as_str().expect("challenge"))
        .expect("challenge encoding");
    let canonical_payload = canonical_json(&proof["payload"]).expect("proof payload");
    assert_eq!(
        std::str::from_utf8(&canonical_payload).expect("payload UTF-8"),
        proof["canonical_payload"]
            .as_str()
            .expect("canonical payload")
    );
    let message = device_proof_message(&context, &challenge, &proof["payload"])
        .expect("device proof transcript");
    assert_eq!(
        format!("{:x}", Sha256::digest(&message)),
        proof["message_sha256"].as_str().expect("message digest")
    );
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(proof["public_key"].as_str().expect("public key"))
        .expect("public key encoding")
        .try_into()
        .expect("public key length");
    let signature = URL_SAFE_NO_PAD
        .decode(proof["signature"].as_str().expect("signature"))
        .expect("signature encoding");
    assert!(VerifyingKey::from_bytes(&public_key)
        .expect("public key")
        .verify_strict(
            &message,
            &Signature::from_slice(&signature).expect("signature length")
        )
        .is_ok());

    let outer: OuterEnvelope =
        serde_json::from_value(vectors["valid_outer"].clone()).expect("valid outer vector");
    outer.validate(16 * 1024 * 1024).expect("outer metadata");
    outer.validate_key_wrap().expect("outer key wrap");
    let cancel_outer: OuterEnvelope =
        serde_json::from_value(vectors["valid_cancel_outer"].clone()).expect("valid cancel outer");
    cancel_outer
        .validate(16 * 1024 * 1024)
        .expect("cancel outer metadata");
    assert!(cancel_outer.validate_key_wrap().is_err());
    for raw in vectors["invalid_outer_json"]
        .as_array()
        .expect("invalid JSON vectors")
    {
        assert!(
            parse_strict_json::<OuterEnvelope>(raw.as_str().expect("raw JSON").as_bytes()).is_err()
        );
    }
    for value in vectors["invalid_outer"]
        .as_array()
        .expect("invalid outer vectors")
    {
        let invalid: OuterEnvelope =
            serde_json::from_value(value.clone()).expect("typed invalid outer");
        assert!(invalid.validate(16 * 1024 * 1024).is_err());
    }

    let capability: BridgeCapability =
        serde_json::from_value(vectors["capability"].clone()).expect("capability vector");
    capability.validate().expect("capability contract");
    let inner: InnerExecuteRequest =
        serde_json::from_value(vectors["valid_inner"].clone()).expect("inner vector");
    inner.validate(&capability).expect("inner contract");
    let cancel: InnerCancelRequest =
        serde_json::from_value(vectors["valid_cancel_inner"].clone()).expect("valid cancel inner");
    cancel.validate().expect("cancel inner contract");

    let mut wrong_default = inner.clone();
    wrong_default.default_task_space = "user-owned-space".into();
    assert!(wrong_default.validate(&capability).is_err());
    let mut mismatched_scope = inner;
    mismatched_scope.task_space_scope = Some("agent-remote:another-session".into());
    assert!(mismatched_scope.validate(&capability).is_err());

    let permit: RequestPermit = serde_json::from_value(serde_json::json!({
        "binding_id": "binding-vector-1",
        "generation": 3,
        "request_id": "request-vector-1",
        "sequence": 17,
        "expires_at_unix_ms": u64::MAX,
        "max_payload_bytes": 16777216,
        "max_script_bytes": 1048576,
        "default_task_space": "agent-remote:session-vector-1",
        "allowlist_revision": 2,
        "learning_bundle_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "concurrency_mode": "task_space_tab",
        "task_space_scope": "agent-remote:session-vector-1",
        "tab_scope": "target-vector-1"
    }))
    .expect("permit vector");
    permit.validate(&capability, 1, 1).expect("permit contract");
    let mut mismatched_permit = permit;
    mismatched_permit.task_space_scope = Some("agent-remote:another-session".into());
    assert!(mismatched_permit.validate(&capability, 1, 1).is_err());
}

#[test]
fn checked_in_schemas_are_strict_objects() {
    for bytes in [
        include_bytes!("../../../protocol/schemas/outer-envelope.schema.json").as_slice(),
        include_bytes!("../../../protocol/schemas/inner-execute.schema.json").as_slice(),
        include_bytes!("../../../protocol/schemas/inner-cancel.schema.json").as_slice(),
        include_bytes!("../../../protocol/schemas/inner-response.schema.json").as_slice(),
        include_bytes!("../../../protocol/schemas/bridge-capability.schema.json").as_slice(),
        include_bytes!("../../../protocol/schemas/request-permit.schema.json").as_slice(),
    ] {
        let schema: Value = parse_strict_json(bytes).expect("strict schema JSON");
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        let required = schema["required"].as_array().expect("required fields");
        let properties = schema["properties"].as_object().expect("properties");
        assert_eq!(required.len(), properties.len());
        assert!(properties
            .keys()
            .all(|key| required.contains(&Value::String(key.clone()))));
    }
}
