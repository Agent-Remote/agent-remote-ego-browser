//! Local bridge control response internals.

use super::*;

pub(super) fn connected_payload(
    config: &BridgeConfig,
    identity: &DeviceIdentity,
) -> Result<serde_json::Value, BridgeError> {
    let capability = config.capability();
    capability
        .validate()
        .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
    Ok(serde_json::json!({
        "encryption_public_key": identity.encryption_public_key_b64(),
        "bridge_protocol_version": capability.bridge_protocol_version,
        "bridge_version": env!("CARGO_PKG_VERSION"),
        "local_ego_browser_runtime_version": capability.local_ego_browser_runtime_version,
        "ego_lite_runtime_version": capability.ego_lite_runtime_version,
        "skill_version": capability.skill_version,
        "release_profile": capability.release_profile,
        "signer_certificate_sha256": capability.signer_certificate_sha256,
        "credential_profile": capability.credential_profile,
        "allowlist_revision": capability.allowlist_revision,
        "allowlist_roots_digest": capability.allowlist_roots_digest,
        "learning_bundle_digest": capability.learning_bundle_digest,
        "max_parallel_requests": capability.max_parallel_requests,
        "capabilities": capability.capabilities,
        "local_browser_ready": true,
    }))
}

pub(super) fn parse_connected_response(
    response: &serde_json::Value,
    config: &BridgeConfig,
    identity: &DeviceIdentity,
) -> Result<LeaseSnapshot, BridgeError> {
    let data = response
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| BridgeError::ProtocolMessage("connected response is malformed".into()))?;
    let capability = config.capability();
    capability
        .validate()
        .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
    let binding_id = required_string(data, "id")?;
    if binding_id != config.binding_id {
        return Err(BridgeError::ProtocolMessage(
            "connected response binding does not match bridge configuration".into(),
        ));
    }
    require_string_eq(data, "control_channel", "ego_browser_bridge")?;
    require_string_eq(data, "relay_binding_kind", "ego_browser")?;
    require_string_eq(data, "authorization_mode", "ego_browser_script_full_trust")?;
    if required_u64(data, "authorization_policy_version")? != 1 {
        return Err(BridgeError::ProtocolMessage(
            "connected response authorization policy is invalid".into(),
        ));
    }
    let device_id = required_string(data, "ego_browser_device_id")?;
    if device_id != identity.device_id {
        return Err(BridgeError::ProtocolMessage(
            "connected response device identity mismatch".into(),
        ));
    }
    let encryption_key = required_string(data, "encryption_public_key")?;
    if encryption_key != identity.encryption_public_key_b64() {
        return Err(BridgeError::ProtocolMessage(
            "connected response encryption key mismatch".into(),
        ));
    }
    require_string_eq(data, "status", "active")?;
    require_string_eq(data, "lease_health", "healthy")?;
    require_string_eq(data, "task_space_label", &config.default_task_space)?;
    if required_string(data, "bridge_protocol_version")? != capability.bridge_protocol_version
        || required_string(data, "local_runtime_version")?
            != capability.local_ego_browser_runtime_version
        || required_string(data, "ego_lite_runtime_version")? != capability.ego_lite_runtime_version
        || required_string(data, "skill_version")? != capability.skill_version
        || required_string(data, "release_profile")? != release_profile_name(config.release_profile)
        || required_string(data, "signer_certificate_sha256")?
            != capability.signer_certificate_sha256
        || required_string(data, "credential_profile")?
            != credential_profile_name(config.credential_profile)
        || required_string(data, "remote_platform")? != REMOTE_PLATFORM
        || required_string(data, "local_platform")? != LOCAL_PLATFORM
    {
        return Err(BridgeError::ProtocolMessage(
            "connected response capability metadata does not match".into(),
        ));
    }
    if required_u64(data, "allowlist_revision")? != config.allowlist_revision
        || required_u64(data, "max_parallel_requests")?
            != u64::try_from(config.max_parallel_requests).unwrap_or(u64::MAX)
    {
        return Err(BridgeError::ProtocolMessage(
            "connected response limits do not match".into(),
        ));
    }
    if !optional_string_matches(
        data,
        "allowlist_roots_digest",
        config.allowlist_roots_digest.as_deref(),
    )? {
        return Err(BridgeError::ProtocolMessage(
            "connected response allowlist roots do not match".into(),
        ));
    }
    if !optional_string_matches(
        data,
        "learning_bundle_digest",
        config.learning_bundle_digest.as_deref(),
    )? {
        return Err(BridgeError::ProtocolMessage(
            "connected response learning bundle does not match".into(),
        ));
    }
    let mut response_capabilities = required_capabilities(data, "capabilities")?;
    response_capabilities.sort();
    let mut expected_capabilities = capability.capabilities.clone();
    expected_capabilities.sort();
    if response_capabilities != expected_capabilities {
        return Err(BridgeError::ProtocolMessage(
            "connected response capabilities do not match".into(),
        ));
    }
    let concurrency_mode = match required_string(data, "concurrency_mode")? {
        "task_space_tab" => ConcurrencyMode::TaskSpaceTab,
        "task_space" => ConcurrencyMode::TaskSpace,
        "binding" => ConcurrencyMode::Binding,
        _ => {
            return Err(BridgeError::ProtocolMessage(
                "connected response concurrency mode is invalid".into(),
            ))
        }
    };
    if !capability.supported_concurrency.contains(&concurrency_mode) {
        return Err(BridgeError::ProtocolMessage(
            "connected response concurrency mode is unsupported".into(),
        ));
    }
    let generation = required_u64(data, "generation")?;
    if generation != config.generation {
        return Err(BridgeError::ProtocolMessage(
            "connected response generation does not match".into(),
        ));
    }
    let now = now_seconds();
    let lease_until = required_timestamp(data, "lease_until")?;
    let absolute_ttl_until = required_timestamp(data, "absolute_ttl_until")?;
    if lease_until <= now || lease_until > absolute_ttl_until || absolute_ttl_until <= now {
        return Err(BridgeError::ProtocolMessage(
            "connected response lease metadata is invalid".into(),
        ));
    }
    let renew_interval_seconds = required_u64(data, "lease_renew_interval_seconds")?;
    let renew_failure_grace_seconds = required_u64(data, "lease_renew_failure_grace_seconds")?;
    Ok(LeaseSnapshot {
        generation,
        lease_until,
        absolute_ttl_until,
        renew_interval_seconds,
        renew_failure_grace_seconds,
    })
}

pub(super) fn parse_relay_ticket(
    response: &serde_json::Value,
    binding_id: &str,
    generation: u64,
) -> Result<RelayTicket, BridgeError> {
    let data = response
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| BridgeError::ProtocolMessage("relay ticket response is malformed".into()))?;
    if required_string(data, "role")? != "bridge"
        || required_u64(data, "generation")? != generation
        || required_string(data, "relay_binding_kind")? != "ego_browser"
    {
        return Err(BridgeError::ProtocolMessage(
            "relay ticket identity is invalid".into(),
        ));
    }
    let expected_path = relay_path(binding_id);
    let path = required_string(data, "relay_path")?.to_owned();
    if path != expected_path {
        return Err(BridgeError::ProtocolMessage(
            "relay ticket path is not the fixed browser endpoint".into(),
        ));
    }
    let token = required_string(data, "relay_ticket")?.to_owned();
    if token.len() > 4096
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(BridgeError::ProtocolMessage(
            "relay ticket encoding is invalid".into(),
        ));
    }
    let expires_at = parse_timestamp(required_string(data, "expires_at")?)?;
    if expires_at <= now_seconds() {
        return Err(BridgeError::LeaseExpired);
    }
    Ok(RelayTicket {
        path,
        token,
        expires_at,
    })
}
