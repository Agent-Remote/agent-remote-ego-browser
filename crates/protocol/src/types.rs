use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{INNER_PROTOCOL_VERSION, LOCAL_PLATFORM, PROTOCOL_VERSION, REMOTE_PLATFORM};

/// Decoded outer payload in ciphertext, nonce, authentication-tag order.
pub type DecodedPayload = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Values visible to the server in an outer envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OuterEnvelope {
    pub protocol: String,
    pub channel: String,
    pub relay_binding_kind: String,
    #[serde(rename = "type")]
    pub message_type: OuterMessageType,
    pub request_id: String,
    pub binding_id: String,
    pub generation: u64,
    pub sequence: u64,
    pub direction: Direction,
    pub payload_bytes: usize,
    pub nonce: String,
    pub ciphertext: String,
    pub auth_tag: String,
    /// Request-only key-wrap material. Responses carry an empty string.
    pub key_wrap: String,
}

impl OuterEnvelope {
    /// Validate routing and replay metadata without decrypting the payload.
    pub fn validate(&self, max_wire_frame_bytes: usize) -> Result<(), ProtocolError> {
        if self.protocol != PROTOCOL_VERSION
            || self.channel != "ego_browser_bridge"
            || self.relay_binding_kind != "ego_browser"
        {
            return Err(ProtocolError::InvalidOuter("protocol or channel"));
        }
        if self.message_type != OuterMessageType::Execute
            && self.message_type != OuterMessageType::ExecuteResult
            && self.message_type != OuterMessageType::Cancel
        {
            return Err(ProtocolError::InvalidOuter("message type"));
        }
        if (self.direction == Direction::Request
            && self.message_type != OuterMessageType::Execute
            && self.message_type != OuterMessageType::Cancel)
            || (self.direction == Direction::Response
                && self.message_type != OuterMessageType::ExecuteResult)
        {
            return Err(ProtocolError::InvalidOuter("type or direction"));
        }
        if !valid_text_id(&self.request_id, 128) {
            return Err(ProtocolError::InvalidOuter("request_id"));
        }
        if !valid_text_id(&self.binding_id, 128) {
            return Err(ProtocolError::InvalidOuter("binding_id"));
        }
        if self.generation == 0 || self.sequence == 0 {
            return Err(ProtocolError::InvalidOuter("generation or sequence"));
        }
        if self.payload_bytes > max_wire_frame_bytes {
            return Err(ProtocolError::FrameTooLarge);
        }
        let ciphertext = decode_b64(&self.ciphertext)
            .map_err(|_| ProtocolError::InvalidOuter("ciphertext encoding"))?;
        let nonce =
            decode_b64(&self.nonce).map_err(|_| ProtocolError::InvalidOuter("nonce encoding"))?;
        let tag = decode_b64(&self.auth_tag)
            .map_err(|_| ProtocolError::InvalidOuter("auth tag encoding"))?;
        if nonce.len() != 12 || tag.len() != 16 || ciphertext.len() != self.payload_bytes {
            return Err(ProtocolError::InvalidOuter("payload lengths"));
        }
        if ciphertext.is_empty() {
            return Err(ProtocolError::InvalidOuter("empty ciphertext"));
        }
        let wrapped = decode_b64(&self.key_wrap)
            .map_err(|_| ProtocolError::InvalidOuter("key wrap encoding"))?;
        if self.message_type == OuterMessageType::Execute {
            if self.direction != Direction::Request
                || (!self.key_wrap.is_empty() && wrapped.len() != crate::KEY_WRAP_BYTES)
            {
                return Err(ProtocolError::InvalidOuter("key wrap length"));
            }
        } else if !self.key_wrap.is_empty() || !wrapped.is_empty() {
            return Err(ProtocolError::InvalidOuter("non-execute key wrap"));
        }
        // This bound includes the JSON envelope, not just ciphertext.
        let wire_size = serde_json::to_vec(self)
            .map_err(|_| ProtocolError::InvalidOuter("serialization"))?
            .len();
        if wire_size > max_wire_frame_bytes {
            return Err(ProtocolError::FrameTooLarge);
        }
        Ok(())
    }

    /// Require a complete key wrap on a request before local execution.
    pub fn validate_key_wrap(&self) -> Result<(), ProtocolError> {
        if self.message_type != OuterMessageType::Execute || self.direction != Direction::Request {
            return Err(ProtocolError::InvalidOuter("key wrap direction"));
        }
        let wrapped = decode_b64(&self.key_wrap)
            .map_err(|_| ProtocolError::InvalidOuter("key wrap encoding"))?;
        if wrapped.len() != crate::KEY_WRAP_BYTES {
            return Err(ProtocolError::InvalidOuter("key wrap length"));
        }
        Ok(())
    }

    /// Return the decoded ciphertext, nonce, and authentication tag.
    pub fn decoded_payload(&self) -> Result<DecodedPayload, ProtocolError> {
        Ok((
            decode_b64(&self.ciphertext)
                .map_err(|_| ProtocolError::InvalidOuter("ciphertext encoding"))?,
            decode_b64(&self.nonce).map_err(|_| ProtocolError::InvalidOuter("nonce encoding"))?,
            decode_b64(&self.auth_tag)
                .map_err(|_| ProtocolError::InvalidOuter("auth tag encoding"))?,
        ))
    }
}

/// Outer relay message type.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OuterMessageType {
    Execute,
    ExecuteResult,
    Hello,
    Renew,
    Cancel,
}

/// Direction of an outer frame.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

/// Inner request sent to the local bridge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InnerExecuteRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: InnerMessageType,
    pub script: String,
    pub timeout_ms: u64,
    pub cwd_label: String,
    pub default_task_space: String,
    pub concurrency_mode: ConcurrencyMode,
    pub task_space_scope: Option<String>,
    pub tab_scope: Option<String>,
    pub allowlist_revision: u64,
    pub learning_bundle_digest: Option<String>,
}

/// Inner cancellation request authenticated with the original request key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InnerCancelRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: InnerMessageType,
    pub request_id: String,
    pub sequence: u64,
}

impl InnerCancelRequest {
    /// Validate the exact request identity targeted by this cancellation.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != INNER_PROTOCOL_VERSION || self.message_type != InnerMessageType::Cancel
        {
            return Err(ProtocolError::InvalidInner("cancel protocol or type"));
        }
        if !valid_text_id(&self.request_id, 128) || self.sequence == 0 {
            return Err(ProtocolError::InvalidInner("cancel identity"));
        }
        Ok(())
    }
}

impl InnerExecuteRequest {
    /// Validate an execute request against the advertised capability.
    pub fn validate(&self, capability: &BridgeCapability) -> Result<(), ProtocolError> {
        if self.protocol != INNER_PROTOCOL_VERSION || self.message_type != InnerMessageType::Execute
        {
            return Err(ProtocolError::InvalidInner("protocol or type"));
        }
        if self.script.is_empty() || self.script.len() > capability.max_script_bytes {
            return Err(ProtocolError::ScriptTooLarge);
        }
        if self.timeout_ms == 0 || self.timeout_ms > capability.max_execute_timeout_ms {
            return Err(ProtocolError::InvalidInner("timeout_ms"));
        }
        if !valid_text_id(&self.cwd_label, 128) || self.cwd_label.contains("..") {
            return Err(ProtocolError::InvalidInner("cwd_label"));
        }
        if !is_dedicated_task_space(&self.default_task_space) {
            return Err(ProtocolError::InvalidInner("default_task_space"));
        }
        if self.allowlist_revision != capability.allowlist_revision {
            return Err(ProtocolError::CapabilityMismatch("allowlist_revision"));
        }
        if self.learning_bundle_digest != capability.learning_bundle_digest {
            return Err(ProtocolError::CapabilityMismatch("learning_bundle_digest"));
        }
        if !capability
            .supported_concurrency
            .contains(&self.concurrency_mode)
        {
            return Err(ProtocolError::CapabilityMismatch("concurrency_mode"));
        }
        if self.concurrency_mode == ConcurrencyMode::Binding {
            return Ok(());
        }
        let scope = self.task_space_scope.as_deref().unwrap_or_default();
        if !valid_text_id(scope, 256) || scope.contains('*') {
            return Err(ProtocolError::InvalidInner("task_space_scope"));
        }
        if scope != self.default_task_space {
            return Err(ProtocolError::InvalidInner("dedicated task space scope"));
        }
        if self.concurrency_mode == ConcurrencyMode::TaskSpaceTab {
            let tab = self.tab_scope.as_deref().unwrap_or_default();
            if !valid_text_id(tab, 256) || tab.contains('*') {
                return Err(ProtocolError::InvalidInner("tab_scope"));
            }
        }
        Ok(())
    }
}

/// Inner message type.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InnerMessageType {
    Execute,
    ExecuteResult,
    Cancel,
    Error,
    Doctor,
    Reload,
}

/// Inner response returned by the local bridge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InnerExecuteResponse {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: InnerMessageType,
    pub request_id: String,
    pub sequence: u64,
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub artifacts: Vec<ArtifactDescriptor>,
    pub duration_ms: u64,
}

/// Stable business status returned for a request.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Completed,
    ScriptError,
    Timeout,
    Cancelled,
    BridgeUnavailable,
    EgoRuntimeUnavailable,
    LeaseExpired,
    BindingRevoked,
    ProtocolError,
    ArtifactError,
    ConcurrencyConflict,
    LeaseRenewalRequired,
    UnknownResult,
}

/// Artifact metadata returned over the encrypted channel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub artifact_id: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub width: u32,
    pub height: u32,
    pub content_b64: String,
}

/// Supported normal-request concurrency scope.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyMode {
    TaskSpaceTab,
    TaskSpace,
    Binding,
}

/// Capabilities proven by a local bridge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeCapability {
    pub bridge_protocol_version: String,
    pub remote_wrapper_version: String,
    pub local_ego_browser_runtime_version: String,
    pub ego_lite_runtime_version: String,
    pub skill_version: String,
    pub release_profile: ReleaseProfile,
    pub signer_certificate_sha256: String,
    pub credential_profile: CredentialProfile,
    pub allowlist_revision: u64,
    pub allowlist_roots_digest: Option<String>,
    pub learning_bundle_digest: Option<String>,
    pub max_parallel_requests: usize,
    pub max_script_bytes: usize,
    pub max_execute_timeout_ms: u64,
    pub supported_concurrency: Vec<ConcurrencyMode>,
    pub capabilities: Vec<String>,
    pub remote_platform: String,
    pub local_platform: String,
}

impl BridgeCapability {
    /// Validate immutable platform and protocol claims.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.bridge_protocol_version != PROTOCOL_VERSION
            || self.remote_platform != REMOTE_PLATFORM
            || self.local_platform != LOCAL_PLATFORM
        {
            return Err(ProtocolError::CapabilityMismatch("platform or protocol"));
        }
        if self.allowlist_revision == 0 {
            return Err(ProtocolError::CapabilityMismatch("allowlist_revision"));
        }
        if self.max_parallel_requests == 0 || self.max_parallel_requests > 4 {
            return Err(ProtocolError::CapabilityMismatch("max_parallel_requests"));
        }
        if self.max_script_bytes == 0 || self.max_script_bytes > crate::MAX_SCRIPT_BYTES {
            return Err(ProtocolError::CapabilityMismatch("max_script_bytes"));
        }
        if self.max_execute_timeout_ms == 0
            || self.max_execute_timeout_ms > crate::MAX_EXECUTE_TIMEOUT_MS
        {
            return Err(ProtocolError::CapabilityMismatch("max_execute_timeout_ms"));
        }
        if !valid_text_id(&self.remote_wrapper_version, 64)
            || !valid_text_id(&self.local_ego_browser_runtime_version, 64)
            || !valid_text_id(&self.ego_lite_runtime_version, 64)
            || !valid_text_id(&self.skill_version, 64)
            || !valid_text_id(&self.signer_certificate_sha256, 128)
            || self.supported_concurrency.is_empty()
            || self.supported_concurrency.len() > 3
        {
            return Err(ProtocolError::CapabilityMismatch("capability metadata"));
        }
        if self
            .capabilities
            .iter()
            .any(|capability| capability.is_empty())
            || self
                .capabilities
                .iter()
                .any(|capability| !valid_text_id(capability, 128))
            || has_duplicates(&self.capabilities)
            || !self
                .capabilities
                .iter()
                .any(|c| c == "ego_browser_script_execute_v1")
        {
            return Err(ProtocolError::CapabilityMismatch("script capability"));
        }
        let has_allowlist = self
            .capabilities
            .iter()
            .any(|value| value == "ego_browser_file_allowlist_v1");
        let has_learning = self
            .capabilities
            .iter()
            .any(|value| value == "ego_browser_site_learning_v1");
        if has_allowlist != self.allowlist_roots_digest.is_some()
            || has_learning != self.learning_bundle_digest.is_some()
            || self
                .allowlist_roots_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256_digest(value))
            || self
                .learning_bundle_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256_digest(value))
        {
            return Err(ProtocolError::CapabilityMismatch(
                "optional policy capability",
            ));
        }
        Ok(())
    }
}

/// Device release profile.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseProfile {
    LogicTest,
    DevelopmentLocal,
    CommunityLocalTrust,
    DeveloperId,
}

/// Device credential storage profile.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfile {
    CommunityFile,
    KeychainAccessGroup,
}

/// One-time broker permit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestPermit {
    pub binding_id: String,
    pub generation: u64,
    pub request_id: String,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub max_payload_bytes: usize,
    pub max_script_bytes: usize,
    pub default_task_space: String,
    pub allowlist_revision: u64,
    pub learning_bundle_digest: Option<String>,
    pub concurrency_mode: ConcurrencyMode,
    pub task_space_scope: Option<String>,
    pub tab_scope: Option<String>,
}

impl RequestPermit {
    /// Validate broker metadata before a request is encrypted or executed.
    pub fn validate(
        &self,
        capability: &BridgeCapability,
        now_unix_ms: u64,
        script_bytes: usize,
    ) -> Result<(), ProtocolError> {
        if !valid_text_id(&self.binding_id, 128)
            || !valid_text_id(&self.request_id, 128)
            || self.generation == 0
            || self.sequence == 0
        {
            return Err(ProtocolError::InvalidInner("permit identity"));
        }
        if self.expires_at_unix_ms <= now_unix_ms {
            return Err(ProtocolError::LeaseExpired);
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > 16 * 1024 * 1024 {
            return Err(ProtocolError::FrameTooLarge);
        }
        if self.max_script_bytes == 0
            || self.max_script_bytes > capability.max_script_bytes
            || script_bytes > self.max_script_bytes
        {
            return Err(ProtocolError::ScriptTooLarge);
        }
        if !is_dedicated_task_space(&self.default_task_space) {
            return Err(ProtocolError::InvalidInner("permit default task space"));
        }
        if self.allowlist_revision != capability.allowlist_revision
            || self.learning_bundle_digest != capability.learning_bundle_digest
        {
            return Err(ProtocolError::CapabilityMismatch("permit capability"));
        }
        if !capability
            .supported_concurrency
            .contains(&self.concurrency_mode)
        {
            return Err(ProtocolError::CapabilityMismatch("permit concurrency"));
        }
        let expected = crate::scheduler::RequestScope::normalized(
            Some(self.concurrency_mode),
            self.task_space_scope.as_deref(),
            self.tab_scope.as_deref(),
        );
        if expected.mode != self.concurrency_mode
            || expected.task_space.as_deref() != self.task_space_scope.as_deref()
            || expected.tab.as_deref() != self.tab_scope.as_deref()
        {
            return Err(ProtocolError::InvalidInner("permit scope"));
        }
        if self.concurrency_mode != ConcurrencyMode::Binding
            && self.task_space_scope.as_deref() != Some(self.default_task_space.as_str())
        {
            return Err(ProtocolError::InvalidInner(
                "permit dedicated task space scope",
            ));
        }
        Ok(())
    }
}

/// Errors shared by protocol consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidOuter(&'static str),
    InvalidInner(&'static str),
    CapabilityMismatch(&'static str),
    FrameTooLarge,
    ScriptTooLarge,
    DuplicateJsonKey(String),
    InvalidJson(String),
    InvalidEncoding,
    AuthenticationFailed,
    Replay,
    LeaseExpired,
    LeaseRenewalRequired,
    BindingRevoked,
    ConcurrencyConflict,
    LimitExceeded(&'static str),
    Io(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOuter(reason) => write!(f, "invalid outer envelope: {reason}"),
            Self::InvalidInner(reason) => write!(f, "invalid inner payload: {reason}"),
            Self::CapabilityMismatch(reason) => write!(f, "capability mismatch: {reason}"),
            Self::FrameTooLarge => f.write_str("wire frame is too large"),
            Self::ScriptTooLarge => f.write_str("script is too large"),
            Self::DuplicateJsonKey(key) => write!(f, "duplicate JSON key: {key}"),
            Self::InvalidJson(reason) => write!(f, "invalid JSON: {reason}"),
            Self::InvalidEncoding => f.write_str("invalid base64 encoding"),
            Self::AuthenticationFailed => f.write_str("payload authentication failed"),
            Self::Replay => f.write_str("replayed request"),
            Self::LeaseExpired => f.write_str("lease expired"),
            Self::LeaseRenewalRequired => f.write_str("lease renewal required"),
            Self::BindingRevoked => f.write_str("binding revoked"),
            Self::ConcurrencyConflict => f.write_str("concurrency conflict"),
            Self::LimitExceeded(name) => write!(f, "limit exceeded: {name}"),
            Self::Io(reason) => write!(f, "I/O error: {reason}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

fn decode_b64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let decoded = URL_SAFE_NO_PAD.decode(value)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(base64::DecodeError::InvalidByte(0, b'='));
    }
    Ok(decoded)
}

fn valid_text_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}

/// Return whether a Task Space is the canonical per-tool-session workflow name.
pub fn is_dedicated_task_space(value: &str) -> bool {
    let Some(tool_session_id) = value.strip_prefix("agent-remote:") else {
        return false;
    };
    !tool_session_id.is_empty()
        && value.len() <= 256
        && tool_session_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b':'
        })
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

/// Encode a UUID into a stable opaque identifier.
pub fn opaque_id() -> String {
    Uuid::new_v4().simple().to_string()
}
