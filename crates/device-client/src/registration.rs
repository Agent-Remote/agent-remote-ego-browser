//! Device registration and identity rotation commands.

use super::*;
use tokio::io::AsyncReadExt;

/// Read a registration credential without putting it in the process argument
/// list. The bootstrap installer and the agent-remote CLI use this path so a
/// short-lived user token is never exposed through `ps` or shell history.
async fn token_from_args(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let inline = option(args, "--token")?;
    let stdin_count = args
        .iter()
        .filter(|value| value.as_str() == "--token-stdin")
        .count();
    if stdin_count > 1 {
        return Err("--token-stdin may only be supplied once".into());
    }
    if inline.is_some() && stdin_count != 0 {
        return Err("--token and --token-stdin are mutually exclusive".into());
    }
    if let Some(token) = inline {
        return Ok(token);
    }
    if stdin_count == 0 {
        return Err("--token or --token-stdin is required".into());
    }

    let mut raw = String::new();
    tokio::io::stdin()
        .take((TOKEN_MAX_BYTES + 1) as u64)
        .read_to_string(&mut raw)
        .await
        .map_err(|_| "failed to read registration token from stdin")?;
    normalize_stdin_token(&raw)
}

pub(super) fn normalize_stdin_token(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let token = raw.trim_end_matches(['\r', '\n']);
    if token.is_empty() {
        return Err("registration token from stdin is empty".into());
    }
    if token.len() > TOKEN_MAX_BYTES {
        return Err("registration token from stdin is too long".into());
    }
    Ok(token.to_owned())
}

pub(super) async fn register(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let server = canonical_server_url(&option(&args, "--server")?.ok_or("--server is required")?)?;
    let token = token_from_args(&args).await?;
    let signer_certificate_sha256 = signer_certificate_sha256(&args)?;
    let runtime = probe_runtime()?;
    let identity = DeviceIdentity::generate("community-local-trust", "community_file");
    let (_, policy) = store.load_policy(
        Some(SUPPORTED_SKILL_VERSION),
        Some(&runtime.ego_browser_version),
    )?;
    let payload = registration_payload(&identity, &runtime, &policy, &signer_certificate_sha256);
    let body = DeviceApiClient::with_user_token(&server, &token, identity.clone())?
        .register_device(payload.clone())
        .await?;
    let credential = credential_from_registration_response(
        &body,
        &server,
        &identity,
        &signer_certificate_sha256,
        &payload,
        None,
    )?;
    store.save_identity(&identity)?;
    store.save(&credential)?;
    println!("registered ego-browser device {}", credential.device_id);
    Ok(())
}

pub(super) async fn device_rotate(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !args.iter().any(|value| value == "--confirm") {
        return Err("explicit --confirm is required to rotate the device identity".into());
    }
    let token = option(&args, "--token")?.ok_or("--token is required")?;
    let signer_certificate_sha256 = signer_certificate_sha256(&args)?;
    let previous_credential = store.load_for_rotation()?;
    let current = store.load_identity(
        previous_credential.device_id.clone(),
        "community-local-trust".into(),
        previous_credential.credential_profile.clone(),
    )?;
    let next = store.prepare_identity_rotation(&current)?;
    let runtime = probe_runtime()?;
    let (_, policy) = store.load_policy(
        Some(SUPPORTED_SKILL_VERSION),
        Some(&runtime.ego_browser_version),
    )?;
    let payload = registration_payload(&next, &runtime, &policy, &signer_certificate_sha256);
    let body =
        DeviceApiClient::with_user_token(&previous_credential.server_url, &token, next.clone())?
            .register_device(payload.clone())
            .await?;
    let credential = credential_from_registration_response(
        &body,
        &previous_credential.server_url,
        &next,
        &signer_certificate_sha256,
        &payload,
        Some(previous_credential.revision),
    )?;
    store.commit_identity_rotation(&next, &credential)?;
    println!(
        "rotated ego-browser device {} to generation {}; prior bindings and credentials were revoked",
        credential.device_id, next.generation
    );
    Ok(())
}

fn registration_payload(
    identity: &DeviceIdentity,
    runtime: &RuntimeProbe,
    policy: &VerifiedLocalPolicy,
    signer_certificate_sha256: &str,
) -> serde_json::Value {
    serde_json::json!({
        "device_id": identity.device_id,
        "public_key": identity.public_key_b64(),
        "encryption_public_key": identity.encryption_public_key_b64(),
        "generation": identity.generation,
        "release_profile": identity.release_profile,
        "credential_profile": identity.credential_profile,
        "platform": "macos",
        "bridge_protocol_version": PROTOCOL_VERSION,
        "bridge_version": env!("CARGO_PKG_VERSION"),
        "local_ego_browser_runtime_version": runtime.ego_browser_version,
        "ego_lite_runtime_version": runtime.ego_browser_version,
        "skill_version": SUPPORTED_SKILL_VERSION,
        "signer_certificate_sha256": signer_certificate_sha256,
        "allowlist_revision": policy.allowlist_revision,
        "allowlist_roots_digest": policy.allowlist_roots_digest,
        "learning_bundle_digest": policy.learning_bundle_digest(),
        "capabilities": policy.capabilities()
    })
}

pub(super) fn credential_from_registration_response(
    response: &serde_json::Value,
    server_url: &str,
    identity: &DeviceIdentity,
    signer_certificate_sha256: &str,
    submitted: &serde_json::Value,
    previous_revision: Option<u64>,
) -> Result<CommunityCredential, Box<dyn std::error::Error>> {
    let data = response
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or("registration response did not include device data")?;
    let public_key = identity.public_key_b64();
    let encryption_public_key = identity.encryption_public_key_b64();
    let exact_identity = data.get("id").and_then(serde_json::Value::as_str)
        == Some(identity.device_id.as_str())
        && data.get("generation").and_then(serde_json::Value::as_u64) == Some(identity.generation)
        && data.get("status").and_then(serde_json::Value::as_str) == Some("active")
        && data.get("public_key").and_then(serde_json::Value::as_str) == Some(public_key.as_str())
        && data
            .get("encryption_public_key")
            .and_then(serde_json::Value::as_str)
            == Some(encryption_public_key.as_str())
        && data
            .get("release_profile")
            .and_then(serde_json::Value::as_str)
            == Some(identity.release_profile.as_str())
        && data
            .get("credential_profile")
            .and_then(serde_json::Value::as_str)
            == Some(identity.credential_profile.as_str())
        && data
            .get("signer_certificate_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(signer_certificate_sha256)
        && registration_policy_matches(data, submitted);
    if !exact_identity {
        return Err("registration response did not match the submitted device identity".into());
    }
    let issued = data
        .get("credential")
        .and_then(serde_json::Value::as_object)
        .ok_or("registration response did not include an ego-browser credential")?;
    let revision = issued
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or("registration response did not include a credential revision")?;
    if revision == 0 || previous_revision.is_some_and(|previous| revision <= previous) {
        return Err("registration response did not advance the credential revision".into());
    }
    if issued
        .get("ego_browser_device_id")
        .and_then(serde_json::Value::as_str)
        != Some(identity.device_id.as_str())
        || issued
            .get("credential_profile")
            .and_then(serde_json::Value::as_str)
            != Some(identity.credential_profile.as_str())
        || issued.get("generation").and_then(serde_json::Value::as_u64) != Some(identity.generation)
        || issued.get("token_type").and_then(serde_json::Value::as_str) != Some("bearer")
    {
        return Err("registration credential did not match the submitted device identity".into());
    }
    let expires_in = issued
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or("registration response did not include credential expiry")?;
    let credential = CommunityCredential {
        version: 1,
        device_id: identity.device_id.clone(),
        server_url: server_url.to_owned(),
        token: issued
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or("registration response did not include a credential token")?
            .to_owned(),
        credential_id: Some(
            issued
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or("registration response did not include a credential ID")?
                .to_owned(),
        ),
        credential_profile: identity.credential_profile.clone(),
        expires_at_unix: now().saturating_add(expires_in),
        revision,
    };
    Ok(credential)
}

fn registration_policy_matches(
    response: &serde_json::Map<String, serde_json::Value>,
    submitted: &serde_json::Value,
) -> bool {
    let Some(submitted) = submitted.as_object() else {
        return false;
    };
    for field in [
        "platform",
        "bridge_protocol_version",
        "bridge_version",
        "local_ego_browser_runtime_version",
        "ego_lite_runtime_version",
        "skill_version",
        "allowlist_revision",
        "allowlist_roots_digest",
        "learning_bundle_digest",
    ] {
        if response.get(field) != submitted.get(field) {
            return false;
        }
    }
    string_array_members_match(response.get("capabilities"), submitted.get("capabilities"))
}

fn string_array_members_match(
    actual: Option<&serde_json::Value>,
    expected: Option<&serde_json::Value>,
) -> bool {
    let (Some(actual), Some(expected)) = (
        actual.and_then(serde_json::Value::as_array),
        expected.and_then(serde_json::Value::as_array),
    ) else {
        return false;
    };
    if !actual.iter().all(serde_json::Value::is_string)
        || !expected.iter().all(serde_json::Value::is_string)
    {
        return false;
    }
    let mut actual = actual
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    let mut expected = expected
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

pub(super) async fn synchronize_registered_policy(
    store: &CredentialStore,
    args: &[String],
    runtime: &RuntimeProbe,
    policy: &VerifiedLocalPolicy,
) -> Result<Option<CommunityCredential>, Box<dyn std::error::Error>> {
    let previous = match store.load_for_rotation() {
        Ok(credential) => credential,
        Err(CredentialError::Missing) => {
            if has_option(args, "--token") || has_option(args, "--signer-certificate-sha256") {
                return Err(
                    "policy synchronization options require an already registered device".into(),
                );
            }
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let token = option(args, "--token")?
        .ok_or("--token is required to change policy for a registered device")?;
    let certificate = signer_certificate_sha256(args)?;
    let identity = store.load_identity(
        previous.device_id.clone(),
        "community-local-trust".into(),
        previous.credential_profile.clone(),
    )?;
    let payload = registration_payload(&identity, runtime, policy, &certificate);
    let response =
        DeviceApiClient::with_user_token(&previous.server_url, &token, identity.clone())?
            .register_device(payload.clone())
            .await?;
    let credential = credential_from_registration_response(
        &response,
        &previous.server_url,
        &identity,
        &certificate,
        &payload,
        Some(previous.revision),
    )?;
    Ok(Some(credential))
}

pub(super) fn confirmed_allowlist_generation(
    response: &serde_json::Value,
    binding_id: &str,
    device_id: &str,
    generation: u64,
    policy: &VerifiedLocalPolicy,
    expected_task_space: Option<&str>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let data = response
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or("allowlist confirmation did not include binding data")?;
    let next_generation = generation
        .checked_add(1)
        .ok_or("allowlist confirmation generation is exhausted")?;
    let task_space = data
        .get("task_space_label")
        .and_then(serde_json::Value::as_str)
        .ok_or("allowlist confirmation did not include a Task Space label")?;
    let expected_capabilities = serde_json::json!(policy.capabilities());
    let exact = data.get("id").and_then(serde_json::Value::as_str) == Some(binding_id)
        && data
            .get("ego_browser_device_id")
            .and_then(serde_json::Value::as_str)
            == Some(device_id)
        && data.get("generation").and_then(serde_json::Value::as_u64) == Some(next_generation)
        && data.get("status").and_then(serde_json::Value::as_str) == Some("paused")
        && data.get("stop_reason").and_then(serde_json::Value::as_str) == Some("allowlist_changed")
        && data
            .get("authorization_mode")
            .and_then(serde_json::Value::as_str)
            == Some("ego_browser_script_full_trust")
        && data
            .get("allowlist_revision")
            .and_then(serde_json::Value::as_u64)
            == Some(policy.allowlist_revision)
        && data.get("allowlist_roots_digest")
            == Some(&serde_json::json!(policy.allowlist_roots_digest))
        && data.get("learning_bundle_digest")
            == Some(&serde_json::json!(policy.learning_bundle_digest()))
        && string_array_members_match(data.get("capabilities"), Some(&expected_capabilities))
        && expected_task_space.is_none_or(|expected| task_space == expected);
    if !exact {
        return Err("allowlist confirmation did not match the submitted policy".into());
    }
    Ok(next_generation)
}
