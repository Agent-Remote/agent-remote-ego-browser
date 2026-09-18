//! Device registration and identity rotation commands.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ego_browser_bridge_protocol::COMMUNITY_PROFILE_ID;
use ego_browser_device::{
    public_value_sha256, PendingRegistration, StoredIdentityMetadata, SUPPORTED_CREDENTIAL_PROFILE,
};
use rand::rngs::OsRng;
use rand::RngCore;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
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
    // Keep the script-facing alias on the idempotent ensure path.
    ensure(store, args).await
}

pub(super) async fn ensure(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _registration_lock = store.lock_registration()?;

    let pending = match store.load_pending_registration() {
        Ok(value) => Some(value),
        Err(CredentialError::Missing) => None,
        Err(CredentialError::PendingExpired) => {
            // Expiry requires explicit recovery, never a second identity.
            let _ = store.record_pending_registration_error(Some("pending_expired"));
            return Err(CredentialError::PendingExpired.into());
        }
        Err(error) => return Err(error.into()),
    };
    let existing_credential = match store.load_for_rotation() {
        Ok(value) => Some(value),
        Err(CredentialError::Missing) => None,
        Err(error) => return Err(error.into()),
    };
    let stored_identity = match store.load_identity_metadata() {
        Ok(value) => Some(value),
        Err(CredentialError::Missing) => None,
        Err(error) => return Err(error.into()),
    };

    let server = option(&args, "--server")?
        .or_else(|| pending.as_ref().map(|value| value.server_url.clone()))
        .or_else(|| {
            existing_credential
                .as_ref()
                .map(|value| value.server_url.clone())
        })
        .or_else(|| {
            stored_identity
                .as_ref()
                .map(|value| value.server_url.clone())
        })
        .ok_or("--server is required for the first ego-browser ensure")?;
    let server = canonical_server_url(&server)?;

    let token = token_from_args_if_present(&args).await?;
    let release_profile = option(&args, "--release-profile")?
        .or_else(|| std::env::var("EGO_BROWSER_RELEASE_PROFILE").ok())
        .or_else(|| {
            existing_credential
                .as_ref()
                .map(|value| value.release_profile.clone())
        })
        .or_else(|| {
            stored_identity
                .as_ref()
                .map(|value| value.release_profile.clone())
        })
        .unwrap_or_else(|| COMMUNITY_PROFILE_ID.to_owned());
    let credential_profile = option(&args, "--credential-profile")?
        .or_else(|| std::env::var("EGO_BROWSER_CREDENTIAL_PROFILE").ok())
        .or_else(|| {
            stored_identity
                .as_ref()
                .map(|value| value.credential_profile.clone())
        })
        .unwrap_or_else(|| "community_file".to_owned());
    if credential_profile != SUPPORTED_CREDENTIAL_PROFILE {
        return Err(CredentialError::UnsupportedCredentialProfile.into());
    }
    if pending.is_none() {
        validate_requested_identity_context(
            &server,
            &release_profile,
            &credential_profile,
            existing_credential.as_ref(),
            stored_identity.as_ref(),
        )?;
    }

    let identity = if let Some(pending) = pending.as_ref() {
        let identity = store.load_identity(
            pending.device_id.clone(),
            pending.release_profile.clone(),
            pending.credential_profile.clone(),
        )?;
        if pending.server_url != server {
            return Err(CredentialError::IdentityOriginConflict.into());
        }
        validate_pending_identity(store, pending, &identity)?;
        identity
    } else if let Some(credential) = existing_credential.as_ref() {
        store.load_identity(
            credential.device_id.clone(),
            release_profile.clone(),
            credential.credential_profile.clone(),
        )?
    } else if let Some(metadata) = stored_identity.as_ref() {
        if metadata.server_url != server {
            return Err(CredentialError::IdentityOriginConflict.into());
        }
        store.load_identity(
            metadata.device_id.clone(),
            metadata.release_profile.clone(),
            metadata.credential_profile.clone(),
        )?
    } else {
        // Never overwrite a key whose Device ID and origin cannot be proven.
        if store.identity_exists()? {
            return Err(CredentialError::Malformed.into());
        }
        let identity = DeviceIdentity::generate(&release_profile, &credential_profile);
        store.save_identity(&identity)?;
        identity
    };

    if identity.release_profile != release_profile && pending.is_none() {
        return Err(CredentialError::CompatibilityMismatch.into());
    }
    if identity.credential_profile != credential_profile && pending.is_none() {
        return Err(CredentialError::CompatibilityMismatch.into());
    }
    if identity.needs_encryption_key_rotation() {
        return Err(CredentialError::Malformed.into());
    }
    let enrollment_mode = pending
        .as_ref()
        .map(|value| value.enrollment_mode.clone())
        .unwrap_or_else(|| {
            if has_option(&args, "--re-enroll") {
                "re_enroll".to_owned()
            } else if existing_credential.is_some() || stored_identity.is_some() {
                "ensure".to_owned()
            } else {
                "initial".to_owned()
            }
        });
    if !matches!(
        enrollment_mode.as_str(),
        "initial" | "ensure" | "re_enroll" | "rotate"
    ) {
        return Err(CredentialError::Malformed.into());
    }
    // Retain non-secret origin metadata when short-lived credentials are retired.
    store.save_identity_metadata(&identity, &server)?;

    // A credential fast path must not hide damaged identity state.
    if let (Some(pending), Some(credential)) = (pending.as_ref(), existing_credential.as_ref()) {
        if credential_matches_identity(credential, &identity, &server)
            && credential_is_fresh(credential, now())
        {
            let _ = local_registration_inputs(store, &args, &identity)?;
            // A matching credential proves a post-commit crash; do not issue another.
            store.clear_pending_registration()?;
            println!(
                "ego-browser device {} is already enrolled",
                credential.device_id
            );
            return Ok(());
        }
        let _ = pending;
    }
    if pending.is_none()
        && existing_credential.as_ref().is_some_and(|credential| {
            credential_matches_identity(credential, &identity, &server)
                && credential_is_fresh(credential, now())
        })
        && !has_option(&args, "--force-refresh")
    {
        let _ = local_registration_inputs(store, &args, &identity)?;
        println!(
            "ego-browser device {} is already enrolled",
            existing_credential
                .as_ref()
                .map(|credential| credential.device_id.as_str())
                .unwrap_or("unknown")
        );
        return Ok(());
    }

    let idempotency_key = if let Some(pending) = pending.as_ref() {
        validate_pending_identity(store, pending, &identity)?;
        pending.idempotency_key.clone()
    } else {
        let key = new_idempotency_key();
        let pending = PendingRegistration {
            version: 1,
            device_id: identity.device_id.clone(),
            device_generation: identity.generation,
            server_url: server.clone(),
            release_profile: identity.release_profile.clone(),
            credential_profile: identity.credential_profile.clone(),
            enrollment_mode: enrollment_mode.clone(),
            signing_public_key_sha256: public_value_sha256(&identity.public_key_b64()),
            encryption_public_key_sha256: public_value_sha256(
                &identity.encryption_public_key_b64(),
            ),
            idempotency_key: key.clone(),
            created_at_unix: now(),
            last_error_code: None,
        };
        store.save_pending_registration(&pending)?;
        key
    };

    // Persist recovery state before any fallible probe can strand the key.
    let (runtime, policy, signer_certificate_sha256) =
        local_registration_inputs(store, &args, &identity)?;

    let payload = registration_payload(
        &identity,
        &runtime,
        &policy,
        &signer_certificate_sha256,
        &enrollment_mode,
    );

    let token = token.ok_or("--token or --token-stdin is required for an ego-browser ensure")?;
    let api = DeviceApiClient::with_user_token(&server, &token, identity.clone())?;
    let body = match ensure_with_retry(&api, payload.clone(), &idempotency_key).await {
        Ok(body) => body,
        Err(error) => {
            let _ = store.record_pending_registration_error(Some(error.log_code()));
            return Err(error.into());
        }
    };
    let credential = credential_from_registration_response_strict(
        &body,
        &server,
        &identity,
        &signer_certificate_sha256,
        &payload,
        existing_credential.as_ref().map(|value| value.revision),
    )?;
    store.save(&credential)?;
    store.save_identity_metadata(&identity, &server)?;
    store.clear_pending_registration()?;
    println!("registered ego-browser device {}", credential.device_id);
    Ok(())
}

/// Retries only an idempotent enrollment exchange with unchanged identity.
async fn ensure_with_retry(
    client: &DeviceApiClient,
    payload: serde_json::Value,
    idempotency_key: &str,
) -> Result<serde_json::Value, CredentialError> {
    let delays = [1_u64, 2, 4, 8];
    let mut retry_index = 0_usize;
    loop {
        match client.ensure_device(payload.clone(), idempotency_key).await {
            Ok(value) => return Ok(value),
            Err(error) if error.is_retryable_ensure_error() && retry_index < delays.len() => {
                let delay = retry_delay(delays[retry_index]);
                retry_index += 1;
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn retry_delay(seconds: u64) -> Duration {
    if let Ok(value) = std::env::var("EGO_BROWSER_ENSURE_RETRY_DELAY_MS") {
        if let Ok(milliseconds) = value.parse::<u64>() {
            if milliseconds <= 60_000 {
                return Duration::from_millis(milliseconds.saturating_mul(seconds));
            }
        }
    }
    Duration::from_secs(seconds)
}

async fn token_from_args_if_present(
    args: &[String],
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if has_option(args, "--token") || has_option(args, "--token-stdin") {
        return Ok(Some(token_from_args(args).await?));
    }
    Ok(None)
}

fn new_idempotency_key() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_pending_identity(
    _store: &CredentialStore,
    pending: &PendingRegistration,
    identity: &DeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    if pending.device_id != identity.device_id
        || pending.device_generation != identity.generation
        || pending.release_profile != identity.release_profile
        || pending.credential_profile != identity.credential_profile
        || pending.signing_public_key_sha256 != public_value_sha256(&identity.public_key_b64())
        || pending.encryption_public_key_sha256
            != public_value_sha256(&identity.encryption_public_key_b64())
    {
        return Err(CredentialError::Malformed.into());
    }
    Ok(())
}

pub(super) fn validate_requested_origin(
    server: &str,
    credential: Option<&CommunityCredential>,
    metadata: Option<&StoredIdentityMetadata>,
) -> Result<(), CredentialError> {
    if credential.is_some_and(|value| value.server_url != server)
        || metadata.is_some_and(|value| value.server_url != server)
    {
        return Err(CredentialError::IdentityOriginConflict);
    }
    Ok(())
}

fn validate_requested_identity_context(
    server: &str,
    release_profile: &str,
    credential_profile: &str,
    credential: Option<&CommunityCredential>,
    metadata: Option<&StoredIdentityMetadata>,
) -> Result<(), CredentialError> {
    validate_requested_origin(server, credential, metadata)?;
    if credential.is_some_and(|value| {
        value.release_profile != release_profile || value.credential_profile != credential_profile
    }) || metadata.is_some_and(|value| {
        value.release_profile != release_profile || value.credential_profile != credential_profile
    }) {
        return Err(CredentialError::CompatibilityMismatch);
    }
    Ok(())
}

fn credential_matches_identity(
    credential: &CommunityCredential,
    identity: &DeviceIdentity,
    server: &str,
) -> bool {
    credential.device_id == identity.device_id
        && credential.server_url == server
        && credential.release_profile == identity.release_profile
        && credential.credential_profile == identity.credential_profile
        && credential.revision > 0
}

pub(super) fn credential_is_fresh(credential: &CommunityCredential, now_unix: u64) -> bool {
    credential.expires_at_unix > now_unix.saturating_add(300)
}

pub(super) async fn device_rotate(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !args.iter().any(|value| value == "--confirm") {
        return Err("explicit --confirm is required to rotate the device identity".into());
    }
    let _registration_lock = store.lock_registration()?;
    let token = token_from_args(&args).await?;
    let previous_credential = store.load_for_rotation()?;
    let current = store.load_identity(
        previous_credential.device_id.clone(),
        previous_credential.release_profile.clone(),
        previous_credential.credential_profile.clone(),
    )?;
    if store.finish_interrupted_identity_rotation(&current, &previous_credential)? {
        println!(
            "ego-browser device {} is already rotated to generation {}",
            current.device_id, current.generation
        );
        return Ok(());
    }
    let signer_certificate_sha256 =
        signer_certificate_sha256_for_profile(&args, Some(&current.release_profile))
            .map_err(|_| CredentialError::CompatibilityMismatch)?;
    let existing_rotation = store.load_pending_rotation()?;
    let prepared_identity = store.load_pending_identity_rotation(&current)?;
    if existing_rotation.is_some() && prepared_identity.is_none() {
        // Metadata without its prepared key is not a recoverable pre-commit state.
        return Err(CredentialError::RotationConflict.into());
    }
    let has_active_binding = match store.load_active_binding(&current.device_id) {
        Ok(_) => true,
        Err(CredentialError::Missing) => false,
        Err(error) => return Err(error.into()),
    };
    if has_active_binding && existing_rotation.is_none() && prepared_identity.is_none() {
        return Err("an active binding must be stopped before rotating the device identity".into());
    }
    let next = match prepared_identity {
        Some(identity) => identity,
        None => store.prepare_identity_rotation(&current)?,
    };
    // Persist the operation key before the request so recovery reuses it.
    let rotation = store.load_or_create_pending_rotation(
        &current,
        &next,
        previous_credential.revision,
        None,
    )?;
    let current_is_target = current.generation == rotation.target_generation
        && current.public_key_b64() == next.public_key_b64()
        && current.encryption_public_key_b64() == next.encryption_public_key_b64();
    let runtime = probe_runtime().map_err(|_| CredentialError::CompatibilityMismatch)?;
    let (_, policy) = store
        .load_policy(
            Some(SUPPORTED_SKILL_VERSION),
            Some(&runtime.ego_browser_version),
        )
        .map_err(map_local_policy_error)?;
    let payload = registration_payload(
        &next,
        &runtime,
        &policy,
        &signer_certificate_sha256,
        "rotate",
    );
    let body =
        DeviceApiClient::with_user_token(&previous_credential.server_url, &token, next.clone())?
            .rotate_device(payload.clone(), &rotation.idempotency_key)
            .await?;
    let credential = credential_from_registration_response_strict(
        &body,
        &previous_credential.server_url,
        &next,
        &signer_certificate_sha256,
        &payload,
        (!current_is_target).then_some(previous_credential.revision),
    )?;
    if current_is_target && credential.revision < previous_credential.revision {
        return Err(CredentialError::RotationConflict.into());
    }
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
    enrollment_mode: &str,
) -> serde_json::Value {
    serde_json::json!({
        "device_id": identity.device_id,
        "public_key": identity.public_key_b64(),
        "encryption_public_key": identity.encryption_public_key_b64(),
        "signing_public_key": identity.public_key_b64(),
        "device_generation": identity.generation,
        "generation": identity.generation,
        "release_profile": identity.release_profile,
        "credential_profile": identity.credential_profile,
        "enrollment_mode": enrollment_mode,
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
        "capabilities": policy.capabilities(),
        "policy_digest": policy_digest(policy),
        "capability_digest": capability_digest(policy)
    })
}

fn policy_digest(policy: &VerifiedLocalPolicy) -> String {
    let value = serde_json::json!({
        "allowlist_revision": policy.allowlist_revision,
        "allowlist_roots_digest": policy.allowlist_roots_digest,
        "learning_bundle_digest": policy.learning_bundle_digest(),
    });
    public_value_sha256(&value.to_string())
}

fn capability_digest(policy: &VerifiedLocalPolicy) -> String {
    let mut capabilities = policy.capabilities();
    capabilities.sort_unstable();
    public_value_sha256(&capabilities.join("\n"))
}

/// Parses legacy `/register` responses that may omit server_origin.
#[allow(dead_code)]
pub(super) fn credential_from_registration_response(
    response: &serde_json::Value,
    server_url: &str,
    identity: &DeviceIdentity,
    signer_certificate_sha256: &str,
    submitted: &serde_json::Value,
    previous_revision: Option<u64>,
) -> Result<CommunityCredential, Box<dyn std::error::Error>> {
    credential_from_registration_response_with_origin(
        response,
        server_url,
        identity,
        signer_certificate_sha256,
        submitted,
        previous_revision,
        false,
    )
}

/// Validates canonical ensure and rotate responses, including Server origin.
pub(super) fn credential_from_registration_response_strict(
    response: &serde_json::Value,
    server_url: &str,
    identity: &DeviceIdentity,
    signer_certificate_sha256: &str,
    submitted: &serde_json::Value,
    previous_revision: Option<u64>,
) -> Result<CommunityCredential, Box<dyn std::error::Error>> {
    credential_from_registration_response_with_origin(
        response,
        server_url,
        identity,
        signer_certificate_sha256,
        submitted,
        previous_revision,
        true,
    )
}

fn credential_from_registration_response_with_origin(
    response: &serde_json::Value,
    server_url: &str,
    identity: &DeviceIdentity,
    signer_certificate_sha256: &str,
    submitted: &serde_json::Value,
    previous_revision: Option<u64>,
    require_server_origin: bool,
) -> Result<CommunityCredential, Box<dyn std::error::Error>> {
    let data = response
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or("registration response did not include device data")?;
    let public_key = identity.public_key_b64();
    let encryption_public_key = identity.encryption_public_key_b64();
    // Only the legacy parser may fall back to ambiguous field aliases.
    let response_device_id = if require_server_origin {
        data.get("device_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        explicit_or_legacy_string(data, "device_id", "id")
    }
    .ok_or("registration response did not include a device ID")?;
    let response_public_key = if require_server_origin {
        data.get("signing_public_key")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        explicit_or_legacy_string(data, "signing_public_key", "public_key")
    }
    .ok_or("registration response did not include a signing public key")?;
    let response_generation = if require_server_origin {
        data.get("device_generation")
            .and_then(serde_json::Value::as_u64)
    } else {
        explicit_or_legacy_u64(data, "device_generation", "generation")
    }
    .ok_or("registration response did not include a device generation")?;
    let exact_identity = response_device_id == identity.device_id
        && response_generation == identity.generation
        && data.get("status").and_then(serde_json::Value::as_str) == Some("active")
        && response_public_key == public_key
        && if require_server_origin {
            // Contradictory legacy aliases indicate a tampered response.
            data.get("id")
                .is_none_or(|value| value.as_str() == Some(identity.device_id.as_str()))
                && data
                    .get("generation")
                    .is_none_or(|value| value.as_u64() == Some(identity.generation))
                && data
                    .get("public_key")
                    .is_none_or(|value| value.as_str() == Some(public_key.as_str()))
        } else {
            value_u64(data, "device_generation", "generation") == Some(identity.generation)
                && explicit_or_legacy_string(data, "public_key", "signing_public_key")
                    .is_some_and(|value| value == public_key)
        }
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
        && if require_server_origin {
            data.get("server_origin")
                .and_then(serde_json::Value::as_str)
                == Some(server_url)
        } else {
            data.get("server_origin")
                .is_none_or(|value| value.as_str() == Some(server_url))
        }
        && registration_policy_matches(data, submitted, require_server_origin);
    if !exact_identity {
        return Err(CredentialError::CompatibilityMismatch.into());
    }
    let issued = data
        .get("credential")
        .and_then(serde_json::Value::as_object)
        .ok_or("registration response did not include an ego-browser credential")?;
    let revision = if require_server_origin {
        issued
            .get("credential_revision")
            .and_then(serde_json::Value::as_u64)
    } else {
        explicit_or_legacy_u64(issued, "credential_revision", "revision")
    }
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
        || if require_server_origin {
            issued
                .get("device_generation")
                .and_then(serde_json::Value::as_u64)
                != Some(identity.generation)
                || issued
                    .get("generation")
                    .is_some_and(|value| value.as_u64() != Some(identity.generation))
                || issued
                    .get("revision")
                    .is_some_and(|value| value.as_u64() != Some(revision))
        } else {
            explicit_or_legacy_u64(issued, "device_generation", "generation")
                != Some(identity.generation)
        }
        || issued.get("token_type").and_then(serde_json::Value::as_str) != Some("bearer")
        || if require_server_origin {
            issued
                .get("credential_scope")
                .and_then(serde_json::Value::as_str)
                != Some("device")
        } else {
            issued
                .get("credential_scope")
                .is_some_and(|value| value.as_str() != Some("device"))
        }
    {
        return Err(CredentialError::CompatibilityMismatch.into());
    }
    let expires_in = issued
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or("registration response did not include credential expiry")?;
    let expires_at_unix = parse_credential_expiry(issued, expires_in, require_server_origin)?;
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
        release_profile: identity.release_profile.clone(),
        credential_profile: identity.credential_profile.clone(),
        expires_at_unix,
        revision,
    };
    Ok(credential)
}

fn explicit_or_legacy_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    preferred: &str,
    compatibility: &str,
) -> Option<u64> {
    let preferred = object.get(preferred).and_then(serde_json::Value::as_u64);
    let compatibility = object
        .get(compatibility)
        .and_then(serde_json::Value::as_u64);
    match (preferred, compatibility) {
        (Some(left), Some(right)) if left != right => None,
        (Some(value), _) | (_, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn value_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    preferred: &str,
    compatibility: &str,
) -> Option<u64> {
    explicit_or_legacy_u64(object, preferred, compatibility)
}

fn explicit_or_legacy_string(
    object: &serde_json::Map<String, serde_json::Value>,
    preferred: &str,
    compatibility: &str,
) -> Option<String> {
    let preferred = object.get(preferred).and_then(serde_json::Value::as_str);
    let compatibility = object
        .get(compatibility)
        .and_then(serde_json::Value::as_str);
    match (preferred, compatibility) {
        (Some(left), Some(right)) if left != right => None,
        (Some(value), _) | (_, Some(value)) => Some(value.to_owned()),
        (None, None) => None,
    }
}

fn parse_credential_expiry(
    issued: &serde_json::Map<String, serde_json::Value>,
    expires_in: u64,
    require_explicit: bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    let explicit = issued
        .get("credential_expires_at")
        .and_then(serde_json::Value::as_str);
    let legacy = issued.get("expires_at").and_then(serde_json::Value::as_str);
    if require_explicit && explicit.is_none() {
        return Err("registration response did not include credential_expires_at".into());
    }
    if let (Some(left), Some(right)) = (explicit, legacy) {
        if left != right {
            return Err("credential expiry fields disagree".into());
        }
    }
    if let Some(value) = explicit.or(legacy) {
        let parsed = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| "registration response credential expiry is invalid")?;
        let timestamp = parsed.unix_timestamp();
        if timestamp <= 0 {
            return Err("registration response credential expiry is invalid".into());
        }
        let now = now();
        if timestamp as u64 <= now {
            return Err("registration response credential is already expired".into());
        }
        // Allow integer truncation, but reject a stale or tampered expiry pair.
        let expected = now.saturating_add(expires_in);
        let delta = (timestamp as u64).abs_diff(expected);
        if delta > 5 {
            return Err("registration response credential expiry does not match expires_in".into());
        }
        return Ok(timestamp as u64);
    }
    Ok(now().saturating_add(expires_in))
}

fn registration_policy_matches(
    response: &serde_json::Map<String, serde_json::Value>,
    submitted: &serde_json::Value,
    require_explicit: bool,
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
        "policy_digest",
        "capability_digest",
    ] {
        if require_explicit && (!response.contains_key(field) || !submitted.contains_key(field)) {
            return false;
        }
        if response.get(field) != submitted.get(field) {
            return false;
        }
    }
    if require_explicit
        && (!response.contains_key("capabilities") || !submitted.contains_key("capabilities"))
    {
        return false;
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
    let identity = store.load_identity(
        previous.device_id.clone(),
        previous.release_profile.clone(),
        previous.credential_profile.clone(),
    )?;
    let certificate = signer_certificate_sha256_for_profile(args, Some(&identity.release_profile))
        .map_err(|_| CredentialError::CompatibilityMismatch)?;
    let payload = registration_payload(&identity, runtime, policy, &certificate, "ensure");
    let idempotency_key = new_idempotency_key();
    let response = ensure_with_retry(
        &DeviceApiClient::with_user_token(&previous.server_url, &token, identity.clone())?,
        payload.clone(),
        &idempotency_key,
    )
    .await?;
    let credential = credential_from_registration_response_strict(
        &response,
        &previous.server_url,
        &identity,
        &certificate,
        &payload,
        Some(previous.revision),
    )?;
    Ok(Some(credential))
}

fn local_registration_inputs(
    store: &CredentialStore,
    args: &[String],
    identity: &DeviceIdentity,
) -> Result<(RuntimeProbe, VerifiedLocalPolicy, String), Box<dyn std::error::Error>> {
    let runtime = probe_runtime().map_err(|_| CredentialError::CompatibilityMismatch)?;
    let (_, policy) = store
        .load_policy(
            Some(SUPPORTED_SKILL_VERSION),
            Some(&runtime.ego_browser_version),
        )
        .map_err(map_local_policy_error)?;
    let signer_certificate_sha256 =
        signer_certificate_sha256_for_profile(args, Some(&identity.release_profile))
            .map_err(|_| CredentialError::CompatibilityMismatch)?;
    Ok((runtime, policy, signer_certificate_sha256))
}

pub(super) fn map_local_policy_error(error: CredentialError) -> CredentialError {
    match error {
        CredentialError::PolicyInvalid
        | CredentialError::LearningBundleInvalid
        | CredentialError::UnsupportedCredentialProfile => CredentialError::CompatibilityMismatch,
        other => other,
    }
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
