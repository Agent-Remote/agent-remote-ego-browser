#![cfg_attr(test, recursion_limit = "256")]

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::Duration;

use ego_browser_bridge_protocol::{
    parse_runtime_probe_output, RuntimeProbe, ACTIVE_LOGIN_ORIGIN, ADMISSION_POLICY_REF,
    COMMUNITY_PROFILE_ID, EGO_LITE_INSTALLER_COMMIT, EGO_LITE_INSTALLER_SHA256, PROTOCOL_VERSION,
    RELEASE_REPOSITORY_URL, REPLACED_COMMUNITY_PROFILE, SUPPORTED_LOCAL_RUNTIME_VERSION,
    SUPPORTED_SKILL_TREE_SHA256, SUPPORTED_SKILL_VERSION,
    TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256,
};
use ego_browser_device::{
    canonical_server_url, migrate_legacy_device_store, ActiveBinding, CommunityCredential,
    CredentialError, CredentialStore, DeviceApiClient, DeviceIdentity, VerifiedLocalPolicy,
    FULL_TRUST_WARNING, TOKEN_MAX_BYTES,
};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

mod device_service;
mod policy_commands;

use device_service::service;
#[cfg(test)]
use device_service::{
    metric_event, prepare_device_service_listener, same_user_peer, serve_device_peer,
    serve_device_peer_with_store,
};
#[cfg(test)]
use policy_commands::positional_paths;
use policy_commands::{allowlist, learning};

const DEVICE_PEER_HEARTBEAT: &[u8] = b"EGB1\n";
/// Signals local admission closure so the Bridge revokes in-memory work.
const DEVICE_PEER_ADMISSION_CLOSED: &[u8] = b"EGB0\n";
const DEVICE_PEER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", top_level_error_line(error.as_ref()));
        std::process::exit(2);
    }
}

fn top_level_error_line(error: &(dyn std::error::Error + 'static)) -> String {
    let code = error
        .downcast_ref::<CredentialError>()
        .map(CredentialError::log_code)
        .unwrap_or("operation_failed");
    format!("ego-browser-device error={code}")
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    let directory = config_dir()?;
    migrate_default_device_store(&directory)?;
    let store = CredentialStore::new(directory)?;
    match command.as_str() {
        "register" => register(&store, args.collect()).await?,
        "ensure" => ensure(&store, args.collect()).await?,
        "metadata" => local_metadata(&store, args.collect())?,
        "retire-local" => retire_local(&store, args.collect())?,
        "purge-local" => purge_local(&store, args.collect())?,
        "candidates" => {
            let credential = store.load(now())?;
            let identity = store.load_identity(
                credential.device_id.clone(),
                credential.release_profile.clone(),
                credential.credential_profile.clone(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &DeviceApiClient::with_identity(&credential, identity)?
                        .candidates()
                        .await?
                )?
            );
        }
        "claim" => claim(&store, args.collect()).await?,
        "status" => status(&store, args.collect()).await?,
        "allowlist" => allowlist(&store, args.collect()).await?,
        "learning" => learning(&store, args.collect()).await?,
        "service" => service(&store).await?,
        "device-rotate" => device_rotate(&store, args.collect()).await?,
        "device-revoke" => device_revoke(&store, args.collect()).await?,
        "pause" | "resume" | "stop" | "revoke" => {
            lifecycle(&store, &command, args.collect()).await?
        }
        "help" | "--help" | "-h" => print_help(),
        _ => return Err("unknown command; use --help".into()),
    }
    Ok(())
}

fn local_metadata(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !args.is_empty() {
        return Err("usage: ego-browser-device metadata".into());
    }
    println!("{}", serde_json::to_string(&store.local_metadata()?)?);
    Ok(())
}

fn retire_local(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.as_slice() != ["--confirmed-stopped"] {
        return Err("usage: ego-browser-device retire-local --confirmed-stopped".into());
    }
    store.close_local_admission()?;
    store.retire_runtime_state()?;
    println!("retired local ego-browser runtime credential");
    Ok(())
}

fn purge_local(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.as_slice() != ["--confirmed-revoked"] {
        return Err("usage: ego-browser-device purge-local --confirmed-revoked".into());
    }
    store.close_local_admission()?;
    store.clear()?;
    println!("removed local ego-browser identity and credentials");
    Ok(())
}

mod binding_commands;
mod registration;

use binding_commands::*;
use registration::*;

fn config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::var_os("EGO_BROWSER_DEVICE_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/agent-remote-ego-browser"))
}

fn migrate_default_device_store(canonical: &Path) -> Result<(), CredentialError> {
    if env::var_os("EGO_BROWSER_DEVICE_HOME").is_some() {
        return Ok(());
    }
    let home = env::var_os("HOME").ok_or(CredentialError::InvalidPath)?;
    let home = PathBuf::from(home);
    let expected = home.join(".config/agent-remote-ego-browser");
    if canonical != expected {
        return Ok(());
    }
    let legacy = home.join(".config/agent-remote/ego-browser-device");
    migrate_legacy_device_store(&legacy, canonical)
}

fn option(args: &[String], name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut result = None;
    for (index, value) in args.iter().enumerate() {
        if value != name {
            continue;
        }
        if result.is_some() {
            return Err(format!("{name} may only be supplied once").into());
        }
        let candidate = args
            .get(index + 1)
            .filter(|candidate| !candidate.starts_with('-'))
            .ok_or_else(|| format!("{name} requires a value"))?;
        result = Some(candidate.clone());
    }
    Ok(result)
}

fn has_option(args: &[String], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

fn signer_certificate_sha256_for_profile(
    args: &[String],
    retained_profile: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let explicit_profile = option(args, "--release-profile")?
        .or_else(|| env::var("EGO_BROWSER_RELEASE_PROFILE").ok())
        .or_else(|| retained_profile.map(str::to_owned));
    let manifest = discover_release_manifest(args)?;
    let profile = explicit_profile
        .clone()
        .or_else(|| manifest.as_ref().map(|value| value.profile.clone()))
        .unwrap_or_else(|| COMMUNITY_PROFILE_ID.to_owned());

    if matches!(profile.as_str(), "logic-test" | "development-local") {
        let digest = option(args, "--signer-certificate-sha256")?
            .or_else(|| env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256").ok())
            .or_else(|| {
                manifest
                    .as_ref()
                    .map(|value| value.signer_certificate_sha256.clone())
            })
            .unwrap_or_else(|| "development".to_owned())
            .to_ascii_lowercase();
        if digest == "development" {
            return Ok(digest);
        }
        return validate_digest(&digest);
    }
    if profile != COMMUNITY_PROFILE_ID {
        return Err(format!("unsupported ego-browser release profile: {profile}").into());
    }

    let installed_pin = discover_installed_certificate_pin()?;
    let digest = option(args, "--signer-certificate-sha256")?
        .or(installed_pin)
        .or_else(|| env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256").ok())
        .or_else(|| {
            manifest
                .as_ref()
                .map(|value| value.signer_certificate_sha256.clone())
        })
        .or_else(|| discover_signed_binary_digest().ok().flatten())
        .ok_or("signer certificate SHA-256 is unavailable from the verified release profile")?
        .to_ascii_lowercase();
    let digest = validate_digest(&digest)?;
    if digest != TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256 {
        return Err(
            "signer certificate SHA-256 does not match the built-in community trust pin".into(),
        );
    }
    #[cfg(target_os = "macos")]
    {
        let observed = discover_signed_binary_digest()?
            .ok_or("signed ego-browser binary certificate is unavailable")?;
        if observed != digest {
            return Err(
                "signed ego-browser binary certificate does not match the trusted pin".into(),
            );
        }
    }
    Ok(digest)
}

fn installed_certificate_pin_path(executable: &Path) -> Option<PathBuf> {
    let executable = executable.canonicalize().ok()?;
    let bin = executable.parent()?;
    if bin.file_name().and_then(OsStr::to_str) != Some("bin") {
        return None;
    }
    let release = bin.parent()?;
    let releases = release.parent()?;
    if releases.file_name().and_then(OsStr::to_str) != Some("releases") {
        return None;
    }
    Some(releases.parent()?.join("TRUSTED_CERTIFICATE_SHA256"))
}

/// Reads the installer pin only from a regular owner-only file.
fn discover_installed_certificate_pin() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(executable) = env::current_exe()
        .ok()
        .and_then(|path| installed_certificate_pin_path(&path))
    else {
        return Ok(None);
    };
    let path_metadata = match fs::symlink_metadata(&executable) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("trusted certificate pin is unavailable: {error}").into()),
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err("trusted certificate pin is not a regular file".into());
    }
    #[cfg(unix)]
    if path_metadata.uid() != unsafe { libc::geteuid() }
        || path_metadata.nlink() != 1
        || path_metadata.permissions().mode() & 0o777 != 0o400
    {
        return Err("trusted certificate pin permissions are unsafe".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&executable)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.file_type().is_symlink() || !opened_metadata.is_file() {
        return Err("trusted certificate pin is not a regular file".into());
    }
    #[cfg(unix)]
    if opened_metadata.uid() != unsafe { libc::geteuid() }
        || opened_metadata.nlink() != 1
        || opened_metadata.permissions().mode() & 0o777 != 0o400
    {
        return Err("trusted certificate pin permissions are unsafe".into());
    }
    #[cfg(unix)]
    if opened_metadata.dev() != path_metadata.dev() || opened_metadata.ino() != path_metadata.ino()
    {
        return Err("trusted certificate pin changed while opening".into());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(66).read_to_end(&mut bytes)?;
    if bytes.len() > 65 {
        return Err("trusted certificate pin is oversized".into());
    }
    let value = std::str::from_utf8(&bytes)?.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err("trusted certificate pin is empty".into());
    }
    Ok(Some(validate_digest(value)?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleaseManifestEvidence {
    profile: String,
    signer_certificate_sha256: String,
}

fn validate_digest(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let digest = value.to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("signer certificate SHA-256 is invalid".into());
    }
    Ok(digest)
}

fn discover_release_manifest(
    args: &[String],
) -> Result<Option<ReleaseManifestEvidence>, Box<dyn std::error::Error>> {
    let candidates = [
        option(args, "--release-manifest")?.map(PathBuf::from),
        env::var_os("EGO_BROWSER_RELEASE_MANIFEST").map(PathBuf::from),
        env::var_os("AGENT_REMOTE_RELEASE_MANIFEST").map(PathBuf::from),
        env::var_os("EGO_BROWSER_SIGNING_EVIDENCE").map(PathBuf::from),
    ];
    match candidates.into_iter().flatten().next() {
        Some(path) => Ok(Some(validate_release_artifact(&path)?)),
        None => Ok(None),
    }
}

fn validate_release_artifact(
    path: &std::path::Path,
) -> Result<ReleaseManifestEvidence, Box<dyn std::error::Error>> {
    let value = read_release_json(path)?;
    match value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(serde_json::Value::as_u64)
    {
        Some(3 | 4) => validate_release_manifest_value(&value),
        Some(1) => validate_signing_evidence_value(&value),
        _ => Err("unsupported release evidence schema".into()),
    }
}

#[cfg(test)]
fn validate_release_manifest(
    path: &std::path::Path,
) -> Result<ReleaseManifestEvidence, Box<dyn std::error::Error>> {
    validate_release_manifest_value(&read_release_json(path)?)
}

fn read_release_json(
    path: &std::path::Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "release manifest is unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("release manifest must be a regular file".into());
    }
    let bytes = fs::read(path).map_err(|_| "release manifest is unreadable")?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("release manifest size is invalid".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "release manifest is not valid JSON".into())
}

fn validate_release_manifest_value(
    value: &serde_json::Value,
) -> Result<ReleaseManifestEvidence, Box<dyn std::error::Error>> {
    let object = value
        .as_object()
        .ok_or("release manifest must be a JSON object")?;
    require_exact_keys(
        object,
        &["schema_version", "distribution_version", "components"],
    )?;
    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("release manifest schema is invalid")?;
    if !matches!(schema_version, 3 | 4)
        || !valid_semver(
            object
                .get("distribution_version")
                .and_then(serde_json::Value::as_str),
        )
    {
        return Err("release manifest header is invalid".into());
    }
    let components = object
        .get("components")
        .and_then(serde_json::Value::as_object)
        .ok_or("release manifest components are invalid")?;
    // Validate this component without coupling to sibling manifest entries.
    const EXPECTED_COMPONENT_COUNT: usize = 6;
    const EGO_BROWSER_COMPONENT: &str = "agent-remote-ego-browser";
    if components.len() != EXPECTED_COMPONENT_COUNT
        || !components.contains_key(EGO_BROWSER_COMPONENT)
    {
        return Err("release manifest component inventory is invalid".into());
    }
    for (name, value) in components {
        let component = value
            .as_object()
            .ok_or("release manifest component is invalid")?;
        if name == EGO_BROWSER_COMPONENT {
            validate_ego_browser_component(component, schema_version)?;
        } else {
            require_exact_keys(
                component,
                &["commit", "release_workflow", "repository", "version"],
            )?;
            validate_common_component(component, name)?;
        }
    }
    let browser = components
        .get(EGO_BROWSER_COMPONENT)
        .and_then(serde_json::Value::as_object)
        .expect("validated browser component");
    let digest = browser
        .get("signer_certificate_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or("release manifest signer certificate is missing")?;
    let digest = validate_digest(digest)?;
    if digest != TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256 {
        return Err(
            "release manifest signer certificate does not match the built-in trust pin".into(),
        );
    }
    Ok(ReleaseManifestEvidence {
        profile: COMMUNITY_PROFILE_ID.to_owned(),
        signer_certificate_sha256: digest,
    })
}

fn validate_signing_evidence_value(
    value: &serde_json::Value,
) -> Result<ReleaseManifestEvidence, Box<dyn std::error::Error>> {
    let object = value
        .as_object()
        .ok_or("signing evidence must be a JSON object")?;
    const KEYS: [&str; 17] = [
        "schema_version",
        "version",
        "profile",
        "production_ready",
        "readiness_blockers",
        "apple_notarized",
        "public_distribution",
        "signing_type",
        "signer_certificate_sha256",
        "bridge_signature_verified",
        "device_client_signature_verified",
        "nested_signatures_verified",
        "hardened_runtime",
        "outbound_policy",
        "credential_profile",
        "learning_bundle_digest",
        "learning_bundle_signing_key_id",
    ];
    require_exact_keys(object, &KEYS)?;
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || !valid_semver(object.get("version").and_then(serde_json::Value::as_str))
        || object.get("version").and_then(serde_json::Value::as_str)
            != Some(env!("CARGO_PKG_VERSION"))
        || object.get("profile").and_then(serde_json::Value::as_str) != Some(COMMUNITY_PROFILE_ID)
        || object
            .get("signing_type")
            .and_then(serde_json::Value::as_str)
            != Some("project-self-signed")
        || object
            .get("outbound_policy")
            .and_then(serde_json::Value::as_str)
            != Some("application-enforced")
        || object
            .get("credential_profile")
            .and_then(serde_json::Value::as_str)
            != Some("community_file")
    {
        return Err("signing evidence profile is invalid".into());
    }
    for field in [
        "production_ready",
        "bridge_signature_verified",
        "device_client_signature_verified",
        "nested_signatures_verified",
        "hardened_runtime",
    ] {
        if object.get(field) != Some(&serde_json::Value::Bool(true)) {
            return Err("signing evidence readiness is invalid".into());
        }
    }
    for field in ["apple_notarized", "public_distribution"] {
        if object.get(field) != Some(&serde_json::Value::Bool(false)) {
            return Err("signing evidence trust fields are invalid".into());
        }
    }
    if object
        .get("readiness_blockers")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|items| !items.is_empty())
    {
        return Err("signing evidence blockers are invalid".into());
    }
    let digest = object
        .get("signer_certificate_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or("signing evidence signer certificate is missing")?;
    let digest = validate_digest(digest)?;
    if digest != TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256 {
        return Err(
            "signing evidence signer certificate does not match the built-in trust pin".into(),
        );
    }
    let learning_digest = object
        .get("learning_bundle_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or("signing evidence learning digest is missing")?;
    if !valid_hex(Some(learning_digest), 64) {
        return Err("signing evidence learning digest is invalid".into());
    }
    let key_id = object
        .get("learning_bundle_signing_key_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("signing evidence learning key ID is missing")?;
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("signing evidence learning key ID is invalid".into());
    }
    Ok(ReleaseManifestEvidence {
        profile: COMMUNITY_PROFILE_ID.to_owned(),
        signer_certificate_sha256: digest,
    })
}

fn require_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err("release manifest fields are invalid".into());
    }
    Ok(())
}

fn valid_semver(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_hex(value: Option<&str>, length: usize) -> bool {
    value.is_some_and(|value| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_common_component(
    component: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = format!("Agent-Remote/{name}");
    if component
        .get("repository")
        .and_then(serde_json::Value::as_str)
        != Some(repository.as_str())
        || !valid_semver(component.get("version").and_then(serde_json::Value::as_str))
        || !valid_hex(
            component.get("commit").and_then(serde_json::Value::as_str),
            40,
        )
    {
        return Err("release manifest component metadata is invalid".into());
    }
    let workflow = component
        .get("release_workflow")
        .and_then(serde_json::Value::as_str)
        .ok_or("release manifest workflow is invalid")?;
    if workflow.is_empty()
        || (!workflow.ends_with(".yml") && !workflow.ends_with(".yaml"))
        || workflow.contains('/')
    {
        return Err("release manifest workflow is invalid".into());
    }
    Ok(())
}

fn validate_ego_browser_component(
    component: &serde_json::Map<String, serde_json::Value>,
    schema_version: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    const LEGACY_KEYS: [&str; 23] = [
        "apple_notarized",
        "commit",
        "credential_profile",
        "hardened_runtime",
        "learning_bundle_digest",
        "learning_bundle_signing_key_id",
        "local_ego_browser_runtime_version",
        "nested_signatures_verified",
        "outbound_policy",
        "profile",
        "production_ready",
        "protocol_version",
        "public_distribution",
        "readiness_blockers",
        "release_published",
        "release_workflow",
        "repository",
        "signer_certificate_sha256",
        "signing_type",
        "skill_commit",
        "skill_tree_sha256",
        "skill_version",
        "version",
    ];
    const PROFILE_KEYS: [&str; 17] = [
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
    ];
    let keys = if schema_version == 4 {
        LEGACY_KEYS
            .into_iter()
            .chain(PROFILE_KEYS)
            .collect::<Vec<_>>()
    } else {
        LEGACY_KEYS.to_vec()
    };
    require_exact_keys(component, &keys)?;
    validate_common_component(component, "agent-remote-ego-browser")?;
    let release_repository = RELEASE_REPOSITORY_URL
        .strip_prefix("https://github.com/")
        .ok_or("Cargo release repository metadata is invalid")?;
    let expected = [
        ("repository", release_repository),
        ("profile", COMMUNITY_PROFILE_ID),
        ("signing_type", "project-self-signed"),
        ("outbound_policy", "application-enforced"),
        ("credential_profile", "community_file"),
        ("protocol_version", PROTOCOL_VERSION),
        ("skill_version", SUPPORTED_SKILL_VERSION),
        ("skill_commit", EGO_LITE_INSTALLER_COMMIT),
        ("skill_tree_sha256", SUPPORTED_SKILL_TREE_SHA256),
        (
            "local_ego_browser_runtime_version",
            SUPPORTED_LOCAL_RUNTIME_VERSION,
        ),
    ];
    for (field, value) in expected {
        if component.get(field).and_then(serde_json::Value::as_str) != Some(value) {
            return Err("release manifest ego-browser profile is invalid".into());
        }
    }
    if component.get("version").and_then(serde_json::Value::as_str)
        != Some(env!("CARGO_PKG_VERSION"))
    {
        return Err("release manifest does not authenticate this Bridge version".into());
    }
    for field in ["apple_notarized", "public_distribution"] {
        if component.get(field) != Some(&serde_json::Value::Bool(false)) {
            return Err("release manifest ego-browser trust fields are invalid".into());
        }
    }
    for field in [
        "hardened_runtime",
        "nested_signatures_verified",
        "production_ready",
        "release_published",
    ] {
        if component.get(field) != Some(&serde_json::Value::Bool(true)) {
            return Err("release manifest ego-browser readiness is invalid".into());
        }
    }
    if component
        .get("readiness_blockers")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|items| !items.is_empty())
    {
        return Err("release manifest ego-browser readiness blockers are invalid".into());
    }
    if !valid_hex(
        component
            .get("signer_certificate_sha256")
            .and_then(serde_json::Value::as_str),
        64,
    ) || !valid_hex(
        component
            .get("learning_bundle_digest")
            .and_then(serde_json::Value::as_str),
        64,
    ) {
        return Err("release manifest ego-browser digest fields are invalid".into());
    }
    if schema_version == 4 {
        validate_signed_release_profile(component)?;
    }
    Ok(())
}

fn validate_signed_release_profile(
    component: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let version = env!("CARGO_PKG_VERSION");
    let exact = [
        ("profile_id", COMMUNITY_PROFILE_ID),
        ("profile_version", version),
        ("bridge_version", version),
        ("wrapper_version", version),
        ("bridge_protocol_version", PROTOCOL_VERSION),
        ("ego_lite_runtime_version", SUPPORTED_LOCAL_RUNTIME_VERSION),
        ("admission_policy_ref", ADMISSION_POLICY_REF),
        ("ego_lite_installer_commit", EGO_LITE_INSTALLER_COMMIT),
        ("ego_lite_installer_sha256", EGO_LITE_INSTALLER_SHA256),
        ("replaces_profile", REPLACED_COMMUNITY_PROFILE),
    ];
    for (field, expected) in exact {
        if component.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err("release manifest signed profile is incompatible".into());
        }
    }
    let artifact_url = format!(
        "{RELEASE_REPOSITORY_URL}/releases/download/v{version}/agent-remote-ego-browser-macos-universal-{version}.tar.gz"
    );
    let installer_url = format!(
        "https://raw.githubusercontent.com/citrolabs/ego-lite/{EGO_LITE_INSTALLER_COMMIT}/skills/ego-browser/scripts/install.sh"
    );
    if component
        .get("artifact_url")
        .and_then(serde_json::Value::as_str)
        != Some(artifact_url.as_str())
        || component
            .get("ego_lite_installer_url")
            .and_then(serde_json::Value::as_str)
            != Some(installer_url.as_str())
        || !valid_hex(
            component
                .get("artifact_sha256")
                .and_then(serde_json::Value::as_str),
            64,
        )
        || !valid_hex(
            component
                .get("bridge_manifest_sha256")
                .and_then(serde_json::Value::as_str),
            64,
        )
        || component.get("valid_platforms") != Some(&serde_json::json!(["macos"]))
        || component.get("allowed_server_origins")
            != Some(&serde_json::json!([ACTIVE_LOGIN_ORIGIN]))
    {
        return Err("release manifest signed profile fields are invalid".into());
    }
    let issued_at = component
        .get("issued_at")
        .and_then(serde_json::Value::as_str)
        .ok_or("release manifest profile issue time is missing")?;
    if !issued_at.ends_with('Z')
        || time::OffsetDateTime::parse(issued_at, &time::format_description::well_known::Rfc3339)
            .is_err()
    {
        return Err("release manifest profile issue time is invalid".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn discover_signed_binary_digest() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let binary = env::var_os("EGO_BROWSER_SIGNED_BINARY")
        .map(PathBuf::from)
        .or_else(|| env::current_exe().ok());
    let Some(binary) = binary else {
        return Ok(None);
    };
    if !binary.is_file() {
        return Ok(None);
    }
    let directory = env::temp_dir().join(format!(
        "ego-browser-codesign-{}-{}",
        std::process::id(),
        now()
    ));
    fs::create_dir(&directory)?;
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        let status = Command::new("codesign")
            .arg("-d")
            .arg("--extract-certificates")
            .arg(&binary)
            .current_dir(&directory)
            .status()?;
        if !status.success() {
            return Err("signed ego-browser binary certificate extraction failed".into());
        }
        let mut certificates = fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("codesign"))
            })
            .collect::<Vec<_>>();
        certificates.sort();
        let leaf = certificates
            .first()
            .ok_or("signed binary has no certificate leaf")?;
        Ok(format!("{:x}", Sha256::digest(fs::read(leaf)?)))
    })();
    let _ = fs::remove_dir_all(&directory);
    result.map(Some)
}

#[cfg(not(target_os = "macos"))]
fn discover_signed_binary_digest() -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(None)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_verified_policy(
    store: &CredentialStore,
) -> Result<(ego_browser_device::LocalPolicy, VerifiedLocalPolicy), Box<dyn std::error::Error>> {
    let runtime = probe_runtime().map_err(|_| CredentialError::CompatibilityMismatch)?;
    Ok(store
        .load_policy(
            Some(SUPPORTED_SKILL_VERSION),
            Some(&runtime.ego_browser_version),
        )
        .map_err(map_local_policy_error)?)
}

fn probe_runtime() -> Result<RuntimeProbe, Box<dyn std::error::Error>> {
    let explicit = env::var_os("EGO_BROWSER_EXECUTABLE");
    let search_path = env::var_os("PATH");
    let home = env::var_os("HOME");
    let candidates = runtime_executable_candidates(
        explicit.as_deref(),
        search_path.as_deref(),
        home.as_deref(),
    )?;
    probe_runtime_candidates(&candidates)
}

fn runtime_executable_candidates(
    explicit: Option<&OsStr>,
    search_path: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(explicit);
        if !path.is_absolute() {
            return Err("EGO_BROWSER_EXECUTABLE must be an absolute path".into());
        }
        let mut candidates = Vec::new();
        push_runtime_candidate(&mut candidates, path);
        if candidates.is_empty() {
            return Err("ego-browser runtime is unavailable".into());
        }
        return Ok(candidates);
    }

    let mut candidates = Vec::new();
    if let Some(search_path) = search_path {
        for directory in env::split_paths(search_path) {
            if !directory.as_os_str().is_empty() {
                push_runtime_candidate(&mut candidates, directory.join("ego-browser"));
            }
        }
    }
    if let Some(home) = home.filter(|value| !value.is_empty()).map(PathBuf::from) {
        push_runtime_candidate(&mut candidates, home.join(".local/bin/ego-browser"));
        push_runtime_candidate(
            &mut candidates,
            home.join(".local/share/ego/active_version_dir/Helpers/ego-browser"),
        );
        #[cfg(target_os = "macos")]
        push_ego_lite_app_candidates(&mut candidates, &home.join("Applications/ego lite.app"));
    }
    #[cfg(target_os = "macos")]
    push_ego_lite_app_candidates(&mut candidates, Path::new("/Applications/ego lite.app"));
    Ok(candidates)
}

#[cfg(target_os = "macos")]
fn push_ego_lite_app_candidates(candidates: &mut Vec<PathBuf>, app: &Path) {
    push_runtime_candidate(
        candidates,
        app.join("Contents/Frameworks/ego Framework.framework/Versions")
            .join(SUPPORTED_LOCAL_RUNTIME_VERSION)
            .join("Helpers/ego-browser"),
    );
    push_runtime_candidate(
        candidates,
        app.join(
            "Contents/Frameworks/ego Framework.framework/Versions/Current/Helpers/ego-browser",
        ),
    );
    push_runtime_candidate(candidates, app.join("Contents/MacOS/ego-browser"));
}

fn push_runtime_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    let Ok(path) = path.canonicalize() else {
        return;
    };
    let Ok(metadata) = path.metadata() else {
        return;
    };
    if !metadata.is_file() || !metadata_is_executable(&metadata) || candidates.contains(&path) {
        return;
    }
    candidates.push(path);
}

fn metadata_is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn probe_runtime_candidates(
    candidates: &[PathBuf],
) -> Result<RuntimeProbe, Box<dyn std::error::Error>> {
    let mut probe_failed = false;
    let mut probe_malformed = false;
    let mut version_mismatched = false;
    for executable in candidates {
        let output = match std::process::Command::new(executable)
            .arg("--version")
            .env_clear()
            .output()
        {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            probe_failed = true;
            continue;
        }
        let probe = match parse_runtime_probe_output(&output.stdout, &output.stderr) {
            Ok(probe) => probe,
            Err(_) => {
                probe_malformed = true;
                continue;
            }
        };
        if probe.ego_browser_version == SUPPORTED_LOCAL_RUNTIME_VERSION {
            return Ok(probe);
        }
        version_mismatched = true;
    }
    if version_mismatched {
        Err("EGO_BROWSER_VERSION_MISMATCH: unsupported local ego-browser runtime".into())
    } else if probe_malformed {
        Err("ego-browser runtime probe is malformed".into())
    } else if probe_failed {
        Err("ego-browser runtime probe failed".into())
    } else {
        Err("ego-browser runtime is unavailable".into())
    }
}

fn print_help() {
    println!("ego-browser-device independent device client");
    println!(
        "Usage: ego-browser-device ensure --server https://... [--token TOKEN | --token-stdin] [--re-enroll]"
    );
    println!("Usage: ego-browser-device register --server https://... [--token TOKEN | --token-stdin] --signer-certificate-sha256 HEX");
    println!("       ego-browser-device metadata");
    println!("       ego-browser-device retire-local --confirmed-stopped");
    println!("       ego-browser-device purge-local --confirmed-revoked");
    println!("       ego-browser-device candidates");
    println!("       ego-browser-device claim TOOL_SESSION --confirm");
    println!("       ego-browser-device status [BINDING]");
    println!("       ego-browser-device allowlist show");
    println!(
        "       ego-browser-device allowlist set ROOT... --confirm [--binding ID --binding-generation N | --token TOKEN --signer-certificate-sha256 HEX]"
    );
    println!("       ego-browser-device learning verify");
    println!(
        "       ego-browser-device learning set BUNDLE --confirm [--token TOKEN --signer-certificate-sha256 HEX]"
    );
    println!("       ego-browser-device service");
    println!("       ego-browser-device device-rotate --token TOKEN --signer-certificate-sha256 HEX --confirm");
    println!("       ego-browser-device device-revoke --confirm");
    println!("       ego-browser-device pause|stop|revoke BINDING --binding-generation N");
    println!("       ego-browser-device resume BINDING --binding-generation N --confirm");
    println!("Full-trust binding requires an explicit session selection and confirmation.");
}

#[cfg(all(test, unix))]
#[path = "tests/main.rs"]
mod tests;
