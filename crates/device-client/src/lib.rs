use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use ego_browser_bridge_protocol::{
    device_proof_message, is_dedicated_task_space, parse_strict_json,
    verify_learning_bundle_details, Allowlist, AllowlistLimits, DeviceProofContext,
    VerifiedLearningBundle, COMMUNITY_PROFILE_ID, TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
};

mod api;
mod credential_store;
mod identity;

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
/// Owner-only execution gate shared by the CLI and Bridge; invalid state is closed.
pub const LOCAL_ADMISSION_FILE_NAME: &str = "ego-browser-local-admission.json";
pub const LOCAL_ADMISSION_CLOSED: &str = "closed";
pub const LOCAL_ADMISSION_READY: &str = "ready";
pub const LOCAL_ADMISSION_OPEN: &str = "open";
// Only known state files are migrated; unknown files remain untouched.
const DEVICE_STORE_STATE_FILES: &[&str] = &[
    "ego-browser-credential.json",
    "ego-browser-device-key.bin",
    "ego-browser-device-metadata.json",
    "ego-browser-device-key.pending.bin",
    "ego-browser-pending-rotation.json",
    "ego-browser-pending-registration.json",
    "ego-browser-policy.json",
    ".ego-browser-policy.lock",
    "ego-browser-active-binding.json",
    "ego-browser-local-admission.json",
    ".ego-browser-registration.lock",
];

/// Migrates known legacy state without overwriting a canonical store.
pub fn migrate_legacy_device_store(legacy: &Path, canonical: &Path) -> Result<(), CredentialError> {
    if legacy == canonical {
        return Ok(());
    }
    let legacy_metadata = match fs::symlink_metadata(legacy) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CredentialError::Io(error)),
    };
    validate_store_directory_metadata(&legacy_metadata)?;
    validate_legacy_store_entries(legacy)?;

    match fs::symlink_metadata(canonical) {
        Ok(metadata) => validate_store_directory_metadata(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = canonical.parent() {
                fs::create_dir_all(parent).map_err(CredentialError::Io)?;
            }
            match fs::create_dir(canonical) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(canonical, fs::Permissions::from_mode(0o700))
                            .map_err(CredentialError::Io)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CredentialError::Io(error)),
            }
            let metadata = fs::symlink_metadata(canonical).map_err(CredentialError::Io)?;
            validate_store_directory_metadata(&metadata)?;
        }
        Err(error) => return Err(CredentialError::Io(error)),
    }

    let mut movable = Vec::new();
    for entry in fs::read_dir(legacy).map_err(CredentialError::Io)? {
        let entry = entry.map_err(CredentialError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(CredentialError::InvalidPath)?;
        let source = entry.path();
        let metadata = fs::symlink_metadata(&source).map_err(CredentialError::Io)?;
        if name == "device-service.sock" {
            // Never migrate a live service socket.
            if metadata.file_type().is_symlink() || !is_socket_file_type(&metadata) {
                return Err(CredentialError::InvalidPath);
            }
            continue;
        }
        if !DEVICE_STORE_STATE_FILES.contains(&name) {
            continue;
        }
        validate_owner_file_metadata(&metadata)?;
        let destination = canonical.join(name);
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(CredentialError::InvalidPath);
        }
        movable.push((source, destination));
    }

    for (source, destination) in movable {
        fs::rename(source, destination).map_err(CredentialError::Io)?;
    }
    let _ = fs::remove_dir(legacy);
    Ok(())
}

fn validate_legacy_store_entries(legacy: &Path) -> Result<(), CredentialError> {
    for entry in fs::read_dir(legacy).map_err(CredentialError::Io)? {
        let entry = entry.map_err(CredentialError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CredentialError::InvalidPath)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(CredentialError::Io)?;
        if name == "device-service.sock" {
            if metadata.file_type().is_symlink() || !is_socket_file_type(&metadata) {
                return Err(CredentialError::InvalidPath);
            }
            continue;
        }
        if DEVICE_STORE_STATE_FILES.contains(&name.as_str()) {
            validate_owner_file_metadata(&metadata)?;
        } else if metadata.file_type().is_symlink() {
            return Err(CredentialError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_socket_file_type(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_file_type(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_store_directory_metadata(metadata: &fs::Metadata) -> Result<(), CredentialError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CredentialError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(CredentialError::UnsafePermissions);
        }
    }
    Ok(())
}
/// Enrollment retry window; expired recovery state is retained.
pub const DEFAULT_PENDING_REGISTRATION_TTL_SECS: u64 = 24 * 60 * 60;
/// Maximum size accepted for a user registration credential.
pub const TOKEN_MAX_BYTES: usize = 4096;
pub const SUPPORTED_CREDENTIAL_PROFILE: &str = "community_file";
const MAX_ALLOWLIST_ROOTS: usize = 128;
const CONTROL_API_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_API_TIMEOUT: Duration = Duration::from_secs(15);

/// Capabilities that do not depend on optional local policy resources.
pub const CORE_CAPABILITIES: [&str; 5] = [
    "ego_browser_script_execute_v1",
    "ego_browser_snapshot_v1",
    "ego_browser_screenshot_artifact_v1",
    "ego_browser_task_space_v1",
    "ego_browser_concurrency_v1",
];

/// Full-trust authorization warning shown before binding.
pub const FULL_TRUST_WARNING: &str =
    "远端 fclaude 将以当前 macOS 用户身份执行完整 ego-browser heredoc，无 App Sandbox。脚本可访问该用户可见的文件、环境、网络、浏览器登录数据、Node 模块、子进程以及其他 Tab 和 Task Space，并可把数据发送到远端。停止只能终止受监管执行单元，不能回滚副作用或保证主动逃逸的进程已清理。";

/// Community credential file format. The PoP private key is kept in a separate owner-only file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommunityCredential {
    pub version: u32,
    pub device_id: String,
    pub server_url: String,
    pub token: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default = "default_release_profile")]
    pub release_profile: String,
    pub credential_profile: String,
    pub expires_at_unix: u64,
    pub revision: u64,
}

/// Non-secret lifecycle metadata; tokens and public keys are omitted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalDeviceMetadata {
    pub device_id: String,
    pub device_generation: u64,
    pub server_url: String,
    pub release_profile: String,
    pub credential_profile: String,
    pub credential_revision: u64,
    pub credential_expires_at_unix: u64,
}

/// Non-secret identity metadata retained after credential retirement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredIdentityMetadata {
    pub version: u32,
    pub device_id: String,
    pub server_url: String,
    pub release_profile: String,
    pub credential_profile: String,
}

fn default_release_profile() -> String {
    COMMUNITY_PROFILE_ID.to_owned()
}

/// Secret-free recovery state for one enrollment request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingRegistration {
    pub version: u32,
    pub device_id: String,
    pub device_generation: u64,
    pub server_url: String,
    pub release_profile: String,
    pub credential_profile: String,
    #[serde(default = "default_enrollment_mode")]
    pub enrollment_mode: String,
    pub signing_public_key_sha256: String,
    pub encryption_public_key_sha256: String,
    pub idempotency_key: String,
    pub created_at_unix: u64,
    #[serde(default)]
    pub last_error_code: Option<String>,
}

fn default_enrollment_mode() -> String {
    "initial".to_owned()
}

/// Secret-free rotation state; the pending private key remains owner-only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingRotation {
    pub version: u32,
    pub device_id: String,
    pub current_generation: u64,
    pub target_generation: u64,
    pub previous_credential_revision: u64,
    pub old_signing_public_key_sha256: String,
    pub old_encryption_public_key_sha256: String,
    pub target_signing_public_key_sha256: String,
    pub target_encryption_public_key_sha256: String,
    pub idempotency_key: String,
    pub created_at_unix: u64,
}

/// Reads a bounded retry window, falling back to 24 hours.
pub fn pending_registration_ttl_secs() -> u64 {
    std::env::var("EGO_BROWSER_PENDING_REGISTRATION_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 30 * 24 * 60 * 60)
        .unwrap_or(DEFAULT_PENDING_REGISTRATION_TTL_SECS)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl PendingRegistration {
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.created_at_unix
            .checked_add(pending_registration_ttl_secs())
            .is_none_or(|deadline| now_unix >= deadline)
    }
}

/// Owner-only handoff from an explicit Device Client claim to the Bridge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveBinding {
    pub version: u32,
    pub binding_id: String,
    pub generation: u64,
    pub device_id: String,
    pub task_space_label: String,
    pub authorization_mode: String,
    pub user_confirmation: bool,
}

/// Execution gate scoped to exact identity and binding generations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalAdmissionRecord {
    pub version: u32,
    pub state: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_generation: Option<u64>,
    #[serde(default)]
    pub binding_id: Option<String>,
    #[serde(default)]
    pub binding_generation: Option<u64>,
    pub updated_at_unix: u64,
}

/// Owner-controlled local policy persisted independently from credentials.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicy {
    pub version: u32,
    pub policy_revision: u64,
    pub allowlist_revision: u64,
    pub allowlist_roots: Vec<String>,
    pub allowlist_roots_digest: Option<String>,
    pub learning_bundle_root: Option<String>,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            policy_revision: 1,
            allowlist_revision: 1,
            allowlist_roots: Vec::new(),
            allowlist_roots_digest: None,
            learning_bundle_root: None,
        }
    }
}

impl LocalPolicy {
    /// Verify all local paths and the optional release-signed learning bundle.
    pub fn verify(
        &self,
        expected_skill_version: Option<&str>,
        expected_runtime_version: Option<&str>,
    ) -> Result<VerifiedLocalPolicy, CredentialError> {
        self.verify_with_key(
            expected_skill_version,
            expected_runtime_version,
            &TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
        )
    }

    fn verify_with_key(
        &self,
        expected_skill_version: Option<&str>,
        expected_runtime_version: Option<&str>,
        learning_key: &[u8; 32],
    ) -> Result<VerifiedLocalPolicy, CredentialError> {
        if self.version != 1
            || self.policy_revision == 0
            || self.allowlist_revision == 0
            || self.allowlist_roots.len() > MAX_ALLOWLIST_ROOTS
        {
            return Err(CredentialError::PolicyInvalid);
        }

        let allowlist = if self.allowlist_roots.is_empty() {
            if self.allowlist_roots_digest.is_some() {
                return Err(CredentialError::PolicyInvalid);
            }
            None
        } else {
            let roots = self
                .allowlist_roots
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let allowlist =
                Allowlist::new(roots, self.allowlist_revision, AllowlistLimits::default())
                    .map_err(|_| CredentialError::PolicyInvalid)?;
            let canonical_roots = canonical_root_strings(&allowlist)?;
            let digest = allowlist
                .roots_digest()
                .map_err(|_| CredentialError::PolicyInvalid)?;
            if canonical_roots != self.allowlist_roots
                || self.allowlist_roots_digest.as_deref() != Some(digest.as_str())
            {
                return Err(CredentialError::PolicyInvalid);
            }
            Some(allowlist)
        };

        let learning_bundle = match self.learning_bundle_root.as_deref() {
            None => None,
            Some(value) => {
                let root = PathBuf::from(value);
                if !root.is_absolute() || root.to_str() != Some(value) {
                    return Err(CredentialError::PolicyInvalid);
                }
                let verified = verify_learning_bundle_details(&root, learning_key)
                    .map_err(|_| CredentialError::LearningBundleInvalid)?;
                if expected_skill_version.is_some_and(|expected| expected != verified.skill_version)
                    || expected_runtime_version.is_some_and(|expected| {
                        expected != verified.local_ego_browser_runtime_version
                    })
                {
                    return Err(CredentialError::LearningBundleInvalid);
                }
                Some(verified)
            }
        };

        Ok(VerifiedLocalPolicy {
            policy_revision: self.policy_revision,
            allowlist_revision: self.allowlist_revision,
            allowlist_roots_digest: self.allowlist_roots_digest.clone(),
            allowlist,
            learning_bundle,
        })
    }

    fn with_allowlist_roots(&self, roots: Vec<PathBuf>) -> Result<Self, CredentialError> {
        if roots.is_empty() || roots.len() > MAX_ALLOWLIST_ROOTS {
            return Err(CredentialError::PolicyInvalid);
        }
        let allowlist = Allowlist::new(
            roots,
            self.allowlist_revision
                .checked_add(1)
                .ok_or(CredentialError::PolicyInvalid)?,
            AllowlistLimits::default(),
        )
        .map_err(|_| CredentialError::PolicyInvalid)?;
        let allowlist_roots = canonical_root_strings(&allowlist)?;
        let allowlist_roots_digest = Some(
            allowlist
                .roots_digest()
                .map_err(|_| CredentialError::PolicyInvalid)?,
        );
        Ok(Self {
            version: 1,
            policy_revision: self
                .policy_revision
                .checked_add(1)
                .ok_or(CredentialError::PolicyInvalid)?,
            allowlist_revision: allowlist.revision(),
            allowlist_roots,
            allowlist_roots_digest,
            learning_bundle_root: self.learning_bundle_root.clone(),
        })
    }

    fn with_learning_bundle_root(&self, root: PathBuf) -> Result<Self, CredentialError> {
        let canonical = root
            .canonicalize()
            .map_err(|_| CredentialError::LearningBundleInvalid)?;
        let canonical = canonical
            .to_str()
            .ok_or(CredentialError::PolicyInvalid)?
            .to_owned();
        let mut next = self.clone();
        next.policy_revision = next
            .policy_revision
            .checked_add(1)
            .ok_or(CredentialError::PolicyInvalid)?;
        next.learning_bundle_root = Some(canonical);
        Ok(next)
    }
}

fn canonical_root_strings(allowlist: &Allowlist) -> Result<Vec<String>, CredentialError> {
    allowlist
        .roots()
        .iter()
        .map(|root| {
            root.to_str()
                .map(str::to_owned)
                .ok_or(CredentialError::PolicyInvalid)
        })
        .collect()
}

/// Local policy resources after canonical path and signature verification.
#[derive(Clone, Debug)]
pub struct VerifiedLocalPolicy {
    pub policy_revision: u64,
    pub allowlist_revision: u64,
    pub allowlist_roots_digest: Option<String>,
    pub allowlist: Option<Allowlist>,
    pub learning_bundle: Option<VerifiedLearningBundle>,
}

impl VerifiedLocalPolicy {
    /// Return exactly the capabilities backed by verified local resources.
    pub fn capabilities(&self) -> Vec<String> {
        let mut capabilities = CORE_CAPABILITIES.map(str::to_owned).to_vec();
        if self.allowlist.is_some() {
            capabilities.push("ego_browser_file_allowlist_v1".to_owned());
        }
        if self.learning_bundle.is_some() {
            capabilities.push("ego_browser_site_learning_v1".to_owned());
        }
        capabilities
    }

    /// Return the verified learning bundle digest, if configured.
    pub fn learning_bundle_digest(&self) -> Option<&str> {
        self.learning_bundle
            .as_ref()
            .map(|bundle| bundle.digest.as_str())
    }
}

/// A local policy update prepared against an exact prior document.
#[derive(Clone, Debug)]
pub struct PreparedPolicyUpdate {
    previous: LocalPolicy,
    next: LocalPolicy,
}

impl PreparedPolicyUpdate {
    /// Return the policy that will become active after a successful CAS write.
    pub fn policy(&self) -> &LocalPolicy {
        &self.next
    }
}

/// Cross-process transaction that serializes one complete local policy change.
pub struct PolicyUpdateTransaction<'a> {
    store: &'a CredentialStore,
    _lock: File,
}

impl PolicyUpdateTransaction<'_> {
    /// Prepare a monotonic allowlist update while excluding other policy writers.
    pub fn prepare_allowlist_update(
        &self,
        roots: Vec<PathBuf>,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        self.store.prepare_allowlist_update_unlocked(roots)
    }

    /// Prepare a signed learning-bundle update while excluding other policy writers.
    pub fn prepare_learning_bundle_update(
        &self,
        root: PathBuf,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        self.store.prepare_learning_bundle_update_unlocked(root)
    }

    /// Prepare a verified migration from an older managed release bundle.
    pub fn prepare_managed_learning_bundle_update(
        &self,
        current_release: &Path,
        expected_skill_version: &str,
        expected_runtime_version: &str,
    ) -> Result<(VerifiedLocalPolicy, Option<PreparedPolicyUpdate>), CredentialError> {
        self.prepare_managed_learning_bundle_update_with_key(
            current_release,
            expected_skill_version,
            expected_runtime_version,
            &TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
        )
    }

    fn prepare_managed_learning_bundle_update_with_key(
        &self,
        current_release: &Path,
        expected_skill_version: &str,
        expected_runtime_version: &str,
        learning_key: &[u8; 32],
    ) -> Result<(VerifiedLocalPolicy, Option<PreparedPolicyUpdate>), CredentialError> {
        self.store.prepare_managed_learning_bundle_update_unlocked(
            current_release,
            expected_skill_version,
            expected_runtime_version,
            learning_key,
        )
    }

    /// Commit the exact policy document prepared by this transaction.
    pub fn commit_policy_update(
        &self,
        update: &PreparedPolicyUpdate,
    ) -> Result<(), CredentialError> {
        self.store.commit_policy_update_unlocked(update)
    }

    #[cfg(test)]
    fn commit_policy_update_with_key(
        &self,
        update: &PreparedPolicyUpdate,
        learning_key: &[u8; 32],
    ) -> Result<(), CredentialError> {
        self.store
            .commit_policy_update_unlocked_with_key(update, learning_key)
    }
}

/// Registered local device identity.
#[derive(Clone)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub signing_key: SigningKey,
    /// Independent X25519 key used only to unwrap per-request session keys.
    pub encryption_key: StaticSecret,
    pub generation: u64,
    pub release_profile: String,
    pub credential_profile: String,
    /// Legacy EGBKEY1 identities need an explicit re-registration before use.
    legacy_encryption_key: bool,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("generation", &self.generation)
            .field("release_profile", &self.release_profile)
            .field("credential_profile", &self.credential_profile)
            .field("legacy_encryption_key", &self.legacy_encryption_key)
            .finish_non_exhaustive()
    }
}

/// Strict owner-only community credential store.
#[derive(Clone)]
pub struct CredentialStore {
    directory: PathBuf,
    credential_path: PathBuf,
    key_path: PathBuf,
    identity_metadata_path: PathBuf,
    pending_key_rotation_path: PathBuf,
    pending_rotation_metadata_path: PathBuf,
    pending_registration_path: PathBuf,
    registration_lock_path: PathBuf,
    policy_path: PathBuf,
    policy_lock_path: PathBuf,
    active_binding_path: PathBuf,
    local_admission_path: PathBuf,
}

pub struct RegistrationLock {
    _file: File,
}

impl std::fmt::Debug for RegistrationLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RegistrationLock(..)")
    }
}

/// Minimal browser binding API client.
#[derive(Clone)]
pub struct DeviceApiClient {
    http: Client,
    base_url: String,
    token: String,
    identity: Option<DeviceIdentity>,
}

fn is_content_free_pause_reason(reason: &str) -> bool {
    matches!(
        reason,
        "user_pause" | "task_space_takeover" | "task_space_monitor_unavailable"
    )
}

fn control_api_client() -> Result<Client, CredentialError> {
    Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONTROL_API_CONNECT_TIMEOUT)
        .timeout(CONTROL_API_TIMEOUT)
        .build()
        .map_err(|_| CredentialError::Network)
}

/// Normalize and validate the only network origin used by the Bridge clients.
pub fn canonical_server_url(value: &str) -> Result<String, CredentialError> {
    let url = reqwest::Url::parse(value).map_err(|_| CredentialError::Malformed)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        return Err(CredentialError::Malformed);
    }
    let origin = url.origin().ascii_serialization();
    if !origin.starts_with("https://") || origin.len() > 512 {
        return Err(CredentialError::Malformed);
    }
    Ok(origin)
}

fn validate_api_id(value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(CredentialError::Malformed);
    }
    Ok(())
}

fn valid_community_credential(credential: &CommunityCredential, now_unix: Option<u64>) -> bool {
    credential.version == 1
        && !credential.release_profile.is_empty()
        && credential.release_profile.len() <= 128
        && credential
            .release_profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        && credential.credential_profile == "community_file"
        && validate_api_id(&credential.device_id).is_ok()
        && canonical_server_url(&credential.server_url)
            .is_ok_and(|value| value == credential.server_url)
        && !credential.token.is_empty()
        && credential.token.len() <= TOKEN_MAX_BYTES
        && credential.token.starts_with("egbc_")
        && credential
            .token
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        && now_unix.is_none_or(|now| credential.expires_at_unix > now)
        && credential.expires_at_unix > 0
        && credential.revision > 0
}

pub fn public_value_sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn decode_response(
    response: reqwest::Response,
) -> Result<serde_json::Value, CredentialError> {
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| CredentialError::Network)?;
    if status != StatusCode::OK && !status.is_success() {
        if let Some(code) = body
            .pointer("/error/code")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 96)
        {
            return Err(CredentialError::ApiCode {
                status: status.as_u16(),
                code: code.to_owned(),
            });
        }
        return Err(CredentialError::Api(status.as_u16()));
    }
    Ok(body)
}

fn read_owner_file(path: &Path) -> Result<Vec<u8>, CredentialError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CredentialError::Missing
        } else {
            CredentialError::Io(error)
        }
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(CredentialError::InvalidPath);
    }
    validate_owner_file_metadata(&path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(no_follow_flag());
    }
    let file = options.open(path).map_err(CredentialError::Io)?;
    let opened_metadata = file.metadata().map_err(CredentialError::Io)?;
    validate_owner_file_metadata(&opened_metadata)?;
    if !same_file_metadata(&path_metadata, &opened_metadata) {
        return Err(CredentialError::InvalidPath);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(CredentialError::Io)?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(CredentialError::TooLarge);
    }
    Ok(bytes)
}

fn validate_owner_file_metadata(metadata: &fs::Metadata) -> Result<(), CredentialError> {
    if !metadata.is_file() {
        return Err(CredentialError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(CredentialError::UnsafePermissions);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

fn atomic_owner_write(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<(), CredentialError> {
    let mut suffix = [0_u8; 8];
    getrandom_bytes(&mut suffix);
    let temporary = directory.join(format!(
        ".ego-browser-{label}-{:x}",
        u64::from_be_bytes(suffix)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&temporary).map_err(CredentialError::Io)?;
    let result = (|| {
        file.write_all(bytes).map_err(CredentialError::Io)?;
        file.sync_all().map_err(CredentialError::Io)?;
        drop(file);
        fs::rename(&temporary, destination).map_err(CredentialError::Io)?;
        let metadata = fs::symlink_metadata(destination).map_err(CredentialError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CredentialError::InvalidPath);
        }
        validate_owner_file_metadata(&metadata)?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(CredentialError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn no_follow_flag() -> i32 {
    #[cfg(unix)]
    {
        libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn getrandom_bytes(bytes: &mut [u8]) {
    use rand::RngCore;
    OsRng.fill_bytes(bytes);
}

/// Credential and API errors.
#[derive(Debug)]
pub enum CredentialError {
    Missing,
    InvalidPath,
    UnsafePermissions,
    Malformed,
    PolicyInvalid,
    PolicyConflict,
    RotationConflict,
    /// Local release evidence is incompatible.
    CompatibilityMismatch,
    /// Enrollment recovery requires explicit action after its retry window.
    PendingExpired,
    /// A retained identity belongs to another control-plane origin.
    IdentityOriginConflict,
    UnsupportedCredentialProfile,
    LocalLockBusy,
    LearningBundleInvalid,
    TooLarge,
    Network,
    Api(u16),
    /// A stable operational error returned by a control-plane endpoint.
    ApiCode {
        status: u16,
        code: String,
    },
    Io(std::io::Error),
}

impl CredentialError {
    /// Return a finite code suitable for persistent operational logs.
    pub fn log_code(&self) -> &'static str {
        match self {
            Self::Missing => "credential_missing",
            Self::InvalidPath => "credential_invalid_path",
            Self::UnsafePermissions => "credential_unsafe_permissions",
            Self::Malformed => "credential_malformed",
            Self::PolicyInvalid => "policy_invalid",
            Self::PolicyConflict => "policy_conflict",
            Self::RotationConflict => "rotation_conflict",
            Self::CompatibilityMismatch => "compatibility_mismatch",
            Self::PendingExpired => "pending_expired",
            Self::IdentityOriginConflict => "identity_origin_conflict",
            Self::UnsupportedCredentialProfile => "compatibility_mismatch",
            Self::LocalLockBusy => "local_lock_busy",
            Self::LearningBundleInvalid => "learning_bundle_invalid",
            Self::TooLarge => "credential_too_large",
            Self::Network | Self::Api(_) => "control_plane_error",
            Self::ApiCode { code, .. } => {
                let normalized = code.to_ascii_lowercase();
                match normalized.as_str() {
                    "login_required" | "common_unauthorized" => "login_required",
                    "server_profile_required" => "server_profile_required",
                    "device_conflict" | "ego_browser_device_conflict" => "device_conflict",
                    "device_generation_conflict"
                    | "ego_browser_generation_mismatch"
                    | "ego_browser_generation_invalid"
                    | "ego_browser_generation_exhausted" => "device_generation_conflict",
                    "device_not_found" | "ego_browser_device_not_found" => "device_not_found",
                    "device_revoked"
                    | "ego_browser_credential_revoked"
                    | "ego_browser_credential_expired" => "device_revoked",
                    "admission_disabled"
                    | "ego_browser_enrollment_disabled"
                    | "ego_browser_enrollment_admission_disabled"
                    | "ego_browser_execution_admission_disabled" => "admission_disabled",
                    "compatibility_mismatch"
                    | "ego_browser_profile_mismatch"
                    | "ego_browser_signer_mismatch"
                    | "ego_browser_version_mismatch"
                    | "ego_browser_capability_mismatch"
                    | "ego_browser_runtime_unsupported"
                    | "ego_browser_encryption_key_mismatch"
                    | "ego_browser_encryption_key_required"
                    | "ego_browser_credential_profile_unsupported" => "compatibility_mismatch",
                    "server_unreachable" => "server_unreachable",
                    "local_lock_busy" => "local_lock_busy",
                    _ => "control_plane_error",
                }
            }
            Self::Io(_) => "io_error",
        }
    }

    /// Reports whether an idempotent ensure request may be retried.
    pub fn is_retryable_ensure_error(&self) -> bool {
        match self {
            Self::Network => true,
            Self::Api(status) => matches!(*status, 408 | 425 | 429 | 500..=599),
            Self::ApiCode { status, code } => {
                let normalized = code.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "ego_browser_enrollment_disabled"
                        | "ego_browser_enrollment_admission_disabled"
                        | "ego_browser_execution_admission_disabled"
                        | "admission_disabled"
                        | "ego_browser_profile_mismatch"
                        | "ego_browser_signer_mismatch"
                        | "ego_browser_capability_mismatch"
                        | "ego_browser_generation_mismatch"
                        | "ego_browser_device_conflict"
                        | "ego_browser_idempotency_conflict"
                ) {
                    return false;
                }
                matches!(*status, 408 | 425 | 429 | 500..=599)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("ego-browser credential is missing"),
            Self::InvalidPath => formatter.write_str("ego-browser credential path is invalid"),
            Self::UnsafePermissions => {
                formatter.write_str("ego-browser credential permissions are unsafe")
            }
            Self::Malformed => formatter.write_str("ego-browser credential is malformed"),
            Self::PolicyInvalid => formatter.write_str("ego-browser local policy is invalid"),
            Self::PolicyConflict => {
                formatter.write_str("ego-browser local policy changed concurrently")
            }
            Self::RotationConflict => formatter
                .write_str("ego-browser device identity rotation conflicts with local state"),
            Self::CompatibilityMismatch => formatter.write_str(
                "the local ego-browser runtime, policy, release profile, or signer evidence is incompatible",
            ),
            Self::PendingExpired => formatter.write_str(
                "ego-browser pending enrollment expired; confirm re-enroll or forget-this-mac",
            ),
            Self::IdentityOriginConflict => formatter.write_str(
                "ego-browser identity belongs to a different control-plane origin; use switch-server",
            ),
            Self::UnsupportedCredentialProfile => formatter
                .write_str("the requested ego-browser credential storage profile is not supported"),
            Self::LocalLockBusy => {
                formatter.write_str("another ego-browser registration operation is in progress")
            }
            Self::LearningBundleInvalid => {
                formatter.write_str("ego-browser learning bundle verification failed")
            }
            Self::TooLarge => formatter.write_str("ego-browser credential is too large"),
            Self::Network => formatter.write_str("ego-browser control-plane request failed"),
            Self::Api(status) => write!(
                formatter,
                "ego-browser control-plane returned HTTP {status}"
            ),
            Self::ApiCode { status, code } => write!(
                formatter,
                "ego-browser control-plane returned HTTP {status} ({code})"
            ),
            Self::Io(error) => write!(formatter, "ego-browser credential I/O error: {error}"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
