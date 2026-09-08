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
pub use runtime::{parse_runtime_probe, RuntimeProbe};
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
pub const SUPPORTED_SKILL_VERSION: &str = "1.2.3";
/// Exact local ego-browser runtime version validated for this protocol release.
pub const SUPPORTED_LOCAL_RUNTIME_VERSION: &str = "0.4.7.4";
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
