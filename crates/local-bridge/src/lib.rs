use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ego_browser_bridge_protocol::{
    aad_for_outer, canonical_json, collect_artifacts, encode_b64url, is_dedicated_task_space,
    opaque_id, parse_strict_json, unwrap_session_key, Allowlist, ArtifactLimits, BridgeCapability,
    ConcurrencyMode, CredentialProfile, Direction, ExecutionStatus, InnerCancelRequest,
    InnerExecuteRequest, InnerExecuteResponse, InnerMessageType, LeasePolicy, LeaseState,
    OuterEnvelope, OuterMessageType, ProtocolError, ReleaseProfile, RequestPermit, RequestScope,
    Scheduler, SessionCipher, ValidatedOutputPath, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_PIXELS,
    MAX_EXECUTE_TIMEOUT_MS, MAX_SCRIPT_BYTES, MAX_STDERR_BYTES, MAX_STDOUT_BYTES, PROTOCOL_VERSION,
    SUPPORTED_LOCAL_RUNTIME_VERSION, SUPPORTED_SKILL_VERSION,
};
use ego_browser_device::VerifiedLocalPolicy;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};

/// Local bridge configuration.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub executable: PathBuf,
    pub work_root: PathBuf,
    pub binding_id: String,
    pub generation: u64,
    pub allowlist_revision: u64,
    pub allowlist_roots_digest: Option<String>,
    pub allowlist: Option<Allowlist>,
    pub learning_bundle_digest: Option<String>,
    pub learning_bundle_root: Option<PathBuf>,
    pub local_policy_revision: u64,
    pub capabilities: Vec<String>,
    pub release_profile: ReleaseProfile,
    pub credential_profile: CredentialProfile,
    pub signer_certificate_sha256: String,
    pub runtime_version: String,
    pub ego_lite_version: String,
    pub skill_version: String,
    pub max_parallel_requests: usize,
    /// Dedicated Task Space used by the development fake broker. Production
    /// permits derive this value from the authenticated Node tool session.
    pub default_task_space: String,
    /// Development fake-broker nonce. Production wrapper admission is owned by
    /// the authenticated Node broker and never reaches this adapter.
    pub broker_startup_nonce: Option<String>,
}

impl BridgeConfig {
    /// Build a safe development configuration from environment and defaults.
    pub fn from_environment() -> Self {
        Self {
            executable: env::var_os("EGO_BROWSER_EXECUTABLE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ego-browser")),
            work_root: env::var_os("EGO_BROWSER_WORK_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    env::temp_dir()
                        .canonicalize()
                        .unwrap_or_else(|_| env::temp_dir())
                        .join("agent-remote-ego-browser")
                }),
            binding_id: env::var("EGO_BROWSER_BINDING_ID").unwrap_or_default(),
            generation: env::var("EGO_BROWSER_GENERATION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            allowlist_revision: 1,
            allowlist_roots_digest: None,
            allowlist: None,
            learning_bundle_digest: None,
            learning_bundle_root: None,
            local_policy_revision: 1,
            capabilities: vec![
                "ego_browser_script_execute_v1".into(),
                "ego_browser_snapshot_v1".into(),
                "ego_browser_screenshot_artifact_v1".into(),
                "ego_browser_task_space_v1".into(),
                "ego_browser_concurrency_v1".into(),
            ],
            release_profile: env::var("EGO_BROWSER_RELEASE_PROFILE")
                .ok()
                .and_then(|value| match value.as_str() {
                    "logic-test" | "logic_test" => Some(ReleaseProfile::LogicTest),
                    "development-local" | "development_local" => {
                        Some(ReleaseProfile::DevelopmentLocal)
                    }
                    "community-local-trust" | "community_local_trust" => {
                        Some(ReleaseProfile::CommunityLocalTrust)
                    }
                    "developer-id" | "developer_id" => Some(ReleaseProfile::DeveloperId),
                    _ => None,
                })
                .unwrap_or(ReleaseProfile::DevelopmentLocal),
            credential_profile: env::var("EGO_BROWSER_CREDENTIAL_PROFILE")
                .ok()
                .and_then(|value| match value.as_str() {
                    "community_file" | "community-file" => Some(CredentialProfile::CommunityFile),
                    "keychain_access_group" | "keychain-access-group" => {
                        Some(CredentialProfile::KeychainAccessGroup)
                    }
                    _ => None,
                })
                .unwrap_or(CredentialProfile::CommunityFile),
            signer_certificate_sha256: env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256")
                .unwrap_or_else(|_| "development".into()),
            runtime_version: SUPPORTED_LOCAL_RUNTIME_VERSION.into(),
            ego_lite_version: SUPPORTED_LOCAL_RUNTIME_VERSION.into(),
            skill_version: SUPPORTED_SKILL_VERSION.into(),
            max_parallel_requests: 4,
            default_task_space: env::var("EGO_BROWSER_DEFAULT_TASK_SPACE")
                .unwrap_or_else(|_| "agent-remote:development".into()),
            broker_startup_nonce: env::var("EGO_BROWSER_BROKER_NONCE").ok(),
        }
    }

    /// Replace optional policy metadata with independently verified local state.
    pub fn apply_verified_policy(&mut self, policy: &VerifiedLocalPolicy) {
        self.allowlist_revision = policy.allowlist_revision;
        self.allowlist_roots_digest = policy.allowlist_roots_digest.clone();
        self.allowlist = policy.allowlist.clone();
        self.learning_bundle_digest = policy.learning_bundle_digest().map(str::to_owned);
        self.learning_bundle_root = policy
            .learning_bundle
            .as_ref()
            .map(|bundle| bundle.root.clone());
        self.local_policy_revision = policy.policy_revision;
        self.capabilities = policy.capabilities();
        if let Some(bundle) = &policy.learning_bundle {
            self.skill_version = bundle.skill_version.clone();
        }
    }

    /// Check that a freshly verified policy is identical to the active snapshot.
    pub fn policy_matches(&self, policy: &VerifiedLocalPolicy) -> bool {
        self.local_policy_revision == policy.policy_revision
            && self.allowlist_revision == policy.allowlist_revision
            && self.allowlist_roots_digest == policy.allowlist_roots_digest
            && self.learning_bundle_digest.as_deref() == policy.learning_bundle_digest()
            && self.learning_bundle_root
                == policy
                    .learning_bundle
                    .as_ref()
                    .map(|bundle| bundle.root.clone())
            && self.capabilities == policy.capabilities()
    }

    /// Create the capability advertisement sent to the broker/wrapper.
    pub fn capability(&self) -> BridgeCapability {
        BridgeCapability {
            bridge_protocol_version: PROTOCOL_VERSION.into(),
            remote_wrapper_version: env!("CARGO_PKG_VERSION").into(),
            local_ego_browser_runtime_version: self.runtime_version.clone(),
            ego_lite_runtime_version: self.ego_lite_version.clone(),
            skill_version: self.skill_version.clone(),
            release_profile: self.release_profile,
            signer_certificate_sha256: self.signer_certificate_sha256.clone(),
            credential_profile: self.credential_profile,
            allowlist_revision: self.allowlist_revision,
            allowlist_roots_digest: self.allowlist_roots_digest.clone(),
            learning_bundle_digest: self.learning_bundle_digest.clone(),
            max_parallel_requests: self.max_parallel_requests,
            max_script_bytes: MAX_SCRIPT_BYTES,
            max_execute_timeout_ms: MAX_EXECUTE_TIMEOUT_MS,
            supported_concurrency: vec![
                ConcurrencyMode::TaskSpaceTab,
                ConcurrencyMode::TaskSpace,
                ConcurrencyMode::Binding,
            ],
            capabilities: self.capabilities.clone(),
            remote_platform: "linux".into(),
            local_platform: "macos".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub script_bytes: usize,
    pub timeout_ms: u64,
    pub cwd_label: String,
    pub concurrency_mode: ConcurrencyMode,
    pub task_space_scope: Option<String>,
    pub tab_scope: Option<String>,
    #[serde(default)]
    pub startup_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PermitResponse<'a> {
    protocol: &'static str,
    #[serde(rename = "type")]
    message_type: &'static str,
    status: &'static str,
    permit: &'a RequestPermit,
    session_key: String,
    capability: &'a BridgeCapability,
}

/// Shared supervisor state for revoke and cancellation.
pub struct BridgeSupervisor {
    config: BridgeConfig,
    _instance_lock: std::fs::File,
    remote_sequence_path: PathBuf,
    scheduler: Scheduler,
    lease: Mutex<LeaseState>,
    next_sequence: Mutex<u64>,
    issued_permits: Mutex<HashMap<u64, IssuedPermit>>,
    consumed_sequences: Mutex<HashSet<u64>>,
    highest_remote_sequence: Mutex<u64>,
    active_remote_requests: Mutex<HashMap<RemoteRequestKey, ActiveRemoteRequest>>,
    cancel_tx: watch::Sender<bool>,
}

#[derive(Clone)]
struct IssuedPermit {
    permit: RequestPermit,
    key: [u8; 32],
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RemoteRequestKey {
    binding_id: String,
    generation: u64,
    request_id: String,
    sequence: u64,
}

impl RemoteRequestKey {
    fn from_envelope(envelope: &OuterEnvelope) -> Self {
        Self {
            binding_id: envelope.binding_id.clone(),
            generation: envelope.generation,
            request_id: envelope.request_id.clone(),
            sequence: envelope.sequence,
        }
    }
}

#[derive(Clone)]
struct ActiveRemoteRequest {
    cancel_tx: watch::Sender<bool>,
    session_key: [u8; 32],
}

/// Prepared relay execution whose authorization and sequence were admitted in
/// WebSocket receive order before it can run concurrently.
pub type RemoteExecution =
    Pin<Box<dyn Future<Output = Result<OuterEnvelope, BridgeError>> + Send + 'static>>;

mod execution_runner;
mod file_guard;
mod process_control;
mod state_store;
mod supervisor_control;
mod supervisor_execution;
mod supervisor_remote;

pub use execution_runner::run_execution_supervisor;
use execution_runner::{constant_time_text_eq, execution_metric_events};
use file_guard::{helper_guard_script, FileGuardHandle};
use process_control::{
    join_capture, read_bounded, terminate_child, terminate_execution, ReaderEvent,
};
use state_store::{
    acquire_instance_lock, load_remote_sequence, now_millis, now_seconds, persist_remote_sequence,
    prepare_private_root, set_private_permissions,
};

/// Bridge operation errors.
#[derive(Debug)]
pub enum BridgeError {
    Unavailable,
    Revoked,
    LeaseExpired,
    LeaseRenewalRequired,
    Replay,
    Concurrency,
    Protocol(ProtocolError),
    Io(std::io::Error),
    ProtocolMessage(String),
}

impl BridgeError {
    fn protocol(message: impl Into<String>) -> Self {
        Self::ProtocolMessage(message.into())
    }

    /// Return a finite code suitable for persistent operational logs.
    pub fn log_code(&self) -> &'static str {
        match self {
            Self::Unavailable => "bridge_unavailable",
            Self::Revoked => "binding_revoked",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseRenewalRequired => "lease_renewal_required",
            Self::Replay => "replay",
            Self::Concurrency => "concurrency_conflict",
            Self::Protocol(_) | Self::ProtocolMessage(_) => "protocol_error",
            Self::Io(_) => "io_error",
        }
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("bridge_unavailable"),
            Self::Revoked => formatter.write_str("binding_revoked"),
            Self::LeaseExpired => formatter.write_str("lease_expired"),
            Self::LeaseRenewalRequired => formatter.write_str("lease_renewal_required"),
            Self::Replay => formatter.write_str("request replayed"),
            Self::Concurrency => formatter.write_str("concurrency_conflict"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "bridge I/O error: {error}"),
            Self::ProtocolMessage(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<ProtocolError> for BridgeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Expose the request type to the binary's socket loop without exposing secrets.
pub fn decode_permit_request(bytes: &[u8]) -> Result<serde_json::Value, BridgeError> {
    parse_strict_json(bytes).map_err(|error| BridgeError::protocol(error.to_string()))
}

/// Decode a permit request value into the internal validated type.
pub fn parse_permit_request(
    value: serde_json::Value,
) -> Result<(String, PermitRequestOwned), BridgeError> {
    let request: PermitRequest =
        serde_json::from_value(value).map_err(|error| BridgeError::protocol(error.to_string()))?;
    Ok((request.message_type.clone(), PermitRequestOwned(request)))
}

/// Owned permit request used by the binary transport adapter.
pub struct PermitRequestOwned(PermitRequest);

impl PermitRequestOwned {
    /// Issue this request through a supervisor.
    pub fn issue(
        &self,
        supervisor: &BridgeSupervisor,
    ) -> Result<([u8; 32], RequestPermit), BridgeError> {
        supervisor.issue_permit(&self.0)
    }
}

/// Serialize a permit response for the wrapper.
pub fn serialize_permit_response(
    permit: &RequestPermit,
    key: &[u8; 32],
    capability: &BridgeCapability,
) -> Result<Vec<u8>, BridgeError> {
    let response = PermitResponse {
        protocol: PROTOCOL_VERSION,
        message_type: "permit_response",
        status: "ok",
        permit,
        session_key: encode_b64url(key),
        capability,
    };
    canonical_json(&response).map_err(|error| BridgeError::protocol(error.to_string()))
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
