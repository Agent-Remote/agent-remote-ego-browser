use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json;

/// Immutable context authenticated by one Device Client PoP signature.
#[derive(Clone, Debug)]
pub struct DeviceProofContext<'a> {
    pub operation: &'a str,
    pub device_id: &'a str,
    pub device_generation: u64,
    pub operation_generation: u64,
    pub binding_id: Option<&'a str>,
    pub release_profile: &'a str,
    pub credential_profile: &'a str,
    pub server_host: &'a str,
}

/// Errors returned while building an unambiguous device PoP transcript.
#[derive(Debug, Error)]
pub enum DeviceProofError {
    #[error("invalid device proof context")]
    InvalidContext,
    #[error("device proof payload is not canonicalizable")]
    InvalidPayload,
}

/// Build the v2 payload-bound Device Client proof transcript.
pub fn device_proof_message(
    context: &DeviceProofContext<'_>,
    challenge: &[u8],
    payload: &serde_json::Value,
) -> Result<Vec<u8>, DeviceProofError> {
    let object = payload
        .as_object()
        .ok_or(DeviceProofError::InvalidPayload)?;
    if context.operation.is_empty()
        || context.device_id.is_empty()
        || context.device_generation == 0
        || context.operation_generation == 0
        || context.release_profile.is_empty()
        || context.credential_profile.is_empty()
        || context.server_host.is_empty()
        || challenge.len() != 32
        || object.contains_key("proof_challenge")
        || object.contains_key("proof_signature")
    {
        return Err(DeviceProofError::InvalidContext);
    }

    let payload = canonical_json(payload).map_err(|_| DeviceProofError::InvalidPayload)?;
    let mut message = Vec::new();
    message.extend_from_slice(b"agent-remote/ego-browser/pop/v2\0");
    for value in [context.operation, context.device_id] {
        append_field(&mut message, value)?;
    }
    message.extend_from_slice(&context.device_generation.to_be_bytes());
    message.extend_from_slice(&context.operation_generation.to_be_bytes());
    for value in [
        context.binding_id.unwrap_or(""),
        context.release_profile,
        context.credential_profile,
        context.server_host,
    ] {
        append_field(&mut message, value)?;
    }
    message.extend_from_slice(challenge);
    message.extend_from_slice(&Sha256::digest(payload));
    Ok(message)
}

fn append_field(message: &mut Vec<u8>, value: &str) -> Result<(), DeviceProofError> {
    let encoded = value.as_bytes();
    let length = u32::try_from(encoded.len()).map_err(|_| DeviceProofError::InvalidContext)?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(encoded);
    Ok(())
}
