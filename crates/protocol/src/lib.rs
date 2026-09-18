//! Shared protocol, validation, scheduling, and local safety primitives.

mod allowlist;
mod artifacts;
mod canonical_json;
mod crypto;
mod framing;
mod learning;
mod lease;
mod pop;
mod runtime;
mod scheduler;
mod state;
mod types;
#[cfg(test)]
mod vectors;

pub use allowlist::{
    Allowlist, AllowlistError, AllowlistLimits, ValidatedInputFile, ValidatedOutputPath,
};
pub use artifacts::{collect_artifacts, Artifact, ArtifactLimits};
pub use canonical_json::{canonical_json, parse_strict_json, StrictJsonError};
pub use crypto::{
    aad_for_outer, decode_b64url, derive_session_key, encode_b64url, key_wrap_transcript,
    unwrap_session_key, wrap_session_key, DetachedCiphertext, SessionCipher,
};
pub use framing::{read_frame, write_frame, FrameError};
pub use learning::{
    verify_learning_bundle, verify_learning_bundle_details, LearningBundleError,
    LearningBundleManifest, LearningFile, VerifiedLearningBundle,
    TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
};
pub use lease::{Admission, LeaseHealth, LeasePolicy, LeaseState, RenewalOutcome};
pub use pop::{device_proof_message, DeviceProofContext, DeviceProofError};
pub use runtime::{parse_runtime_probe, parse_runtime_probe_output, RuntimeProbe};
pub use scheduler::{PermitGuard, RequestScope, Scheduler, SchedulerError};
pub use state::{BindingState, ExecutionState, StateError};
pub use types::*;

/// 当前桥接协议版本。
pub const PROTOCOL_VERSION: &str = "ego-browser-bridge-v1";
/// 当前加密 inner payload 协议版本。
pub const INNER_PROTOCOL_VERSION: &str = "ego-browser-bridge-v1-inner";
/// 远端运行平台。
pub const REMOTE_PLATFORM: &str = "linux";
/// 本地运行平台。
pub const LOCAL_PLATFORM: &str = "macos";
/// Official Skill version installed in the remote runtime.
pub const SUPPORTED_SKILL_VERSION: &str = "2.0.0";
/// Exact local ego-browser runtime version validated for this protocol release.
pub const SUPPORTED_LOCAL_RUNTIME_VERSION: &str = "0.5.0.32";
/// Reviewed upstream commit that supplies the Skill and installer.
pub const EGO_LITE_INSTALLER_COMMIT: &str = "d01be93325c7ea59d41c2ca9f4c59b58b4be4046";
/// Reviewed upstream installer digest.
pub const EGO_LITE_INSTALLER_SHA256: &str =
    "4cbbc9f211aca61244d9ada601c385cabbeba4ec4417b3a8be1819a01cb0221b";
/// Reviewed official Skill tree digest.
pub const SUPPORTED_SKILL_TREE_SHA256: &str =
    "a45cc7fcbea45a6f6222faf83c891b0fd22955193699dd99c9e40b0c0b4a0741";
/// Cargo repository metadata used to derive release URLs.
pub const RELEASE_REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");
/// Project self-signed release profile.
pub const COMMUNITY_PROFILE_ID: &str = "community-local-trust";
/// Fixed community signer trust root.
pub const TRUSTED_COMMUNITY_SIGNER_CERTIFICATE_SHA256: &str =
    "1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5";
/// Previous profile replaced by this source candidate.
pub const REPLACED_COMMUNITY_PROFILE: &str = "community-local-trust@0.1.12";
/// Server policy required by the signed release profile.
pub const ADMISSION_POLICY_REF: &str = "server-policy:ego-browser-v1";
/// Placeholder resolved to the user's authenticated control-plane origin.
pub const ACTIVE_LOGIN_ORIGIN: &str = "$active_login_origin";
/// 默认并发请求数。
pub const DEFAULT_MAX_PARALLEL_REQUESTS: usize = 4;
/// heredoc 脚本最大字节数。
pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
/// stdout 最大字节数。
pub const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
/// stderr 最大字节数。
pub const MAX_STDERR_BYTES: usize = 1024 * 1024;
/// 单个截图最大字节数。
pub const MAX_ARTIFACT_BYTES: usize = 12 * 1024 * 1024;
/// 单个截图最大像素数。
pub const MAX_ARTIFACT_PIXELS: u64 = 4_000_000;
/// 单次执行最大时长。
pub const MAX_EXECUTE_TIMEOUT_MS: u64 = 120_000;
/// Fixed binary size of a wrapped per-request session key.
pub const KEY_WRAP_BYTES: usize = 32 + 12 + 32 + 16;
/// 默认租约时长。
pub const DEFAULT_LEASE_SECONDS: u64 = 60;
/// 自动续租间隔。
pub const LEASE_RENEW_INTERVAL_SECONDS: u64 = 20;
/// 续租失败宽限。
pub const LEASE_RENEW_FAILURE_GRACE_SECONDS: u64 = 10;
/// admission 所需最小剩余租约。
pub const LEASE_ADMISSION_MIN_REMAINING_SECONDS: u64 = 20;
/// binding 绝对 TTL。
pub const ABSOLUTE_BINDING_TTL_SECONDS: u64 = 28_800;
/// helper 单文件上限。
pub const MAX_ALLOWLISTED_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// helper 单请求总文件上限。
pub const MAX_ALLOWLISTED_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// helper 单请求文件数上限。
pub const MAX_ALLOWLISTED_FILE_COUNT: usize = 32;
