use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use ego_browser_bridge_protocol::{
    device_proof_message, is_dedicated_task_space, parse_strict_json,
    verify_learning_bundle_details, Allowlist, AllowlistLimits, DeviceProofContext,
    VerifiedLearningBundle, TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
};

mod api;
mod credential_store;
mod identity;

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
/// Maximum size accepted for a user registration credential.
pub const TOKEN_MAX_BYTES: usize = 4096;
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
    pub credential_profile: String,
    pub expires_at_unix: u64,
    pub revision: u64,
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

    /// Commit the exact policy document prepared by this transaction.
    pub fn commit_policy_update(
        &self,
        update: &PreparedPolicyUpdate,
    ) -> Result<(), CredentialError> {
        self.store.commit_policy_update_unlocked(update)
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
    pending_key_rotation_path: PathBuf,
    policy_path: PathBuf,
    policy_lock_path: PathBuf,
    active_binding_path: PathBuf,
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

async fn decode_response(
    response: reqwest::Response,
) -> Result<serde_json::Value, CredentialError> {
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| CredentialError::Network)?;
    if status != StatusCode::OK && !status.is_success() {
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
    LearningBundleInvalid,
    TooLarge,
    Network,
    Api(u16),
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
            Self::LearningBundleInvalid => "learning_bundle_invalid",
            Self::TooLarge => "credential_too_large",
            Self::Network | Self::Api(_) => "control_plane_error",
            Self::Io(_) => "io_error",
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
            Self::LearningBundleInvalid => {
                formatter.write_str("ego-browser learning bundle verification failed")
            }
            Self::TooLarge => formatter.write_str("ego-browser credential is too large"),
            Self::Network => formatter.write_str("ego-browser control-plane request failed"),
            Self::Api(status) => write!(
                formatter,
                "ego-browser control-plane returned HTTP {status}"
            ),
            Self::Io(error) => write!(formatter, "ego-browser credential I/O error: {error}"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
