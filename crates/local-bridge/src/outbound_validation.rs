//! Local bridge outbound validation internals.

use super::*;

pub(super) fn verify_policy_snapshot(
    store: &CredentialStore,
    config: &BridgeConfig,
) -> Result<(), BridgeError> {
    let (_, policy) = store
        .load_policy(Some(SUPPORTED_SKILL_VERSION), Some(&config.runtime_version))
        .map_err(map_credential_error)?;
    if !config.policy_matches(&policy) {
        return Err(BridgeError::ProtocolMessage(
            "local policy changed; explicit binding resume is required".into(),
        ));
    }
    Ok(())
}

pub(super) async fn probe_local_runtime(
    executable: &std::path::Path,
) -> Result<RuntimeProbe, BridgeError> {
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(executable)
            .arg("--version")
            .env_clear()
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await;
    match result {
        Ok(Ok(output)) if output.status.success() => {
            parse_runtime_probe_output(&output.stdout, &output.stderr).map_err(|_| {
                BridgeError::ProtocolMessage("ego-browser runtime probe is malformed".into())
            })
        }
        Ok(Ok(_)) => Err(BridgeError::ProtocolMessage(
            "ego-browser runtime probe failed".into(),
        )),
        Ok(Err(_)) | Err(_) => Err(BridgeError::ProtocolMessage(
            "ego-browser runtime is unavailable".into(),
        )),
    }
}

pub(super) fn relay_path(binding_id: &str) -> String {
    format!("/api/v1/ego-browser/bindings/{binding_id}/relay")
}

pub(super) fn required_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, BridgeError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4096)
        .ok_or_else(|| BridgeError::ProtocolMessage(format!("missing or invalid {field}")))
}

pub(super) fn require_string_eq(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected: &str,
) -> Result<(), BridgeError> {
    if required_string(object, field)? != expected {
        return Err(BridgeError::ProtocolMessage(format!(
            "connected response {field} does not match"
        )));
    }
    Ok(())
}

pub(super) fn optional_string_matches(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected: Option<&str>,
) -> Result<bool, BridgeError> {
    let value = object
        .get(field)
        .ok_or_else(|| BridgeError::ProtocolMessage(format!("missing {field}")))?;
    match expected {
        Some(expected) => Ok(value.as_str() == Some(expected)),
        None => Ok(value.is_null()),
    }
}

pub(super) fn required_capabilities(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<String>, BridgeError> {
    let values = object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| BridgeError::ProtocolMessage(format!("missing or invalid {field}")))?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let capability = value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| BridgeError::ProtocolMessage(format!("invalid {field}")))?;
        if result.iter().any(|existing| existing == capability) {
            return Err(BridgeError::ProtocolMessage(format!("duplicate {field}")));
        }
        result.push(capability.to_owned());
    }
    Ok(result)
}

pub(super) fn required_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, BridgeError> {
    let value = object
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| BridgeError::ProtocolMessage(format!("missing or invalid {field}")))?;
    if value == 0 {
        return Err(BridgeError::ProtocolMessage(format!(
            "missing or invalid {field}"
        )));
    }
    Ok(value)
}

pub(super) fn credential_profile_name(profile: CredentialProfile) -> &'static str {
    match profile {
        CredentialProfile::CommunityFile => "community_file",
        CredentialProfile::KeychainAccessGroup => "keychain_access_group",
    }
}

pub(super) fn required_timestamp(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, BridgeError> {
    parse_timestamp(required_string(object, field)?)
}

pub(super) fn parse_timestamp(value: &str) -> Result<u64, BridgeError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| BridgeError::ProtocolMessage("invalid control-plane timestamp".into()))?;
    let seconds = parsed
        .unix_timestamp()
        .try_into()
        .map_err(|_| BridgeError::ProtocolMessage("invalid control-plane timestamp".into()))?;
    Ok(seconds)
}

pub(super) fn release_profile_name(profile: ReleaseProfile) -> &'static str {
    match profile {
        ReleaseProfile::LogicTest => "logic-test",
        ReleaseProfile::DevelopmentLocal => "development-local",
        ReleaseProfile::CommunityLocalTrust => "community-local-trust",
        ReleaseProfile::DeveloperId => "developer-id",
    }
}

pub(super) fn is_retryable_control_error(error: &ego_browser_device::CredentialError) -> bool {
    matches!(
        error,
        ego_browser_device::CredentialError::Network
            | ego_browser_device::CredentialError::Api(500..=599)
    )
}

pub(super) fn map_credential_error(error: ego_browser_device::CredentialError) -> BridgeError {
    match error {
        ego_browser_device::CredentialError::Api(status) => {
            BridgeError::ProtocolMessage(format!("control-plane request failed (HTTP {status})"))
        }
        other => BridgeError::ProtocolMessage(other.to_string()),
    }
}

pub(super) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
