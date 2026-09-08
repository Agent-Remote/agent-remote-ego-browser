use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{canonical_json, OuterEnvelope, ProtocolError, KEY_WRAP_BYTES};

/// Detached AEAD output in nonce, ciphertext, authentication-tag order.
pub type DetachedCiphertext = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Session-scoped AEAD cipher. The key must be held only by the two endpoints.
#[derive(Clone)]
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
}

impl SessionCipher {
    /// Construct a cipher from a 32-byte session key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Generate a cryptographically random session key.
    pub fn random() -> ([u8; 32], Self) {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        (key, Self::new(&key))
    }

    /// Seal plaintext and return nonce, ciphertext, and detached tag.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<DetachedCiphertext, ProtocolError> {
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let encrypted = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ProtocolError::AuthenticationFailed)?;
        if encrypted.len() < 16 {
            return Err(ProtocolError::AuthenticationFailed);
        }
        let split = encrypted.len() - 16;
        Ok((
            nonce_bytes.to_vec(),
            encrypted[..split].to_vec(),
            encrypted[split..].to_vec(),
        ))
    }

    /// Open a detached-tag ciphertext.
    pub fn open(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        auth_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if nonce.len() != 12 || auth_tag.len() != 16 {
            return Err(ProtocolError::InvalidEncoding);
        }
        let mut combined = Vec::with_capacity(ciphertext.len() + auth_tag.len());
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(auth_tag);
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &combined,
                    aad,
                },
            )
            .map_err(|_| ProtocolError::AuthenticationFailed)
    }
}

/// Create authenticated associated data from outer routing fields.
pub fn aad_for_outer(envelope: &OuterEnvelope) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::json!({
        "protocol": &envelope.protocol,
        "channel": &envelope.channel,
        "relay_binding_kind": &envelope.relay_binding_kind,
        "type": envelope.message_type,
        "request_id": &envelope.request_id,
        "binding_id": &envelope.binding_id,
        "generation": envelope.generation,
        "sequence": envelope.sequence,
        "direction": envelope.direction,
        "payload_bytes": envelope.payload_bytes,
    });
    canonical_json(&value).map_err(|_| ProtocolError::InvalidOuter("aad serialization"))
}

/// Encode bytes as unpadded base64url.
pub fn encode_b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url bytes.
pub fn decode_b64url(value: &str) -> Result<Vec<u8>, ProtocolError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProtocolError::InvalidEncoding)
}

/// Derive a session key from short-lived handshake material and transcript data.
pub fn derive_session_key(secret: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"agent-remote/ego-browser/session-key/v1\0");
    digest.update(secret);
    digest.update(transcript);
    digest.finalize().into()
}

/// Unwrap a broker-delivered request key using the Bridge's X25519 secret.
///
/// The wire value is a fixed binary tuple: ephemeral public key, ChaCha nonce,
/// ciphertext, and detached authentication tag, encoded as base64url. The
/// transcript binds the wrapped key to one binding generation and request.
pub fn unwrap_session_key(
    encoded: &str,
    recipient_secret: &[u8; 32],
    binding_id: &str,
    generation: u64,
    request_id: &str,
    sequence: u64,
) -> Result<[u8; 32], ProtocolError> {
    let wrapped = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&wrapped) != encoded || wrapped.len() != KEY_WRAP_BYTES {
        return Err(ProtocolError::InvalidEncoding);
    }
    let peer_bytes: [u8; 32] = wrapped[..32]
        .try_into()
        .map_err(|_| ProtocolError::InvalidEncoding)?;
    let peer = X25519PublicKey::from(peer_bytes);
    let secret = StaticSecret::from(*recipient_secret);
    let shared = secret.diffie_hellman(&peer);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let aad = key_wrap_transcript(binding_id, generation, request_id, sequence);
    let wrap_key = derive_wrap_key(shared.as_bytes(), &aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let nonce = Nonce::from_slice(&wrapped[32..44]);
    let ciphertext = &wrapped[44..76];
    let tag = &wrapped[76..92];
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::AuthenticationFailed)?;
    plaintext
        .try_into()
        .map_err(|_| ProtocolError::AuthenticationFailed)
}

/// Wrap a per-request session key to the Bridge's X25519 public key.
///
/// The returned value is the fixed binary tuple documented by the bridge
/// protocol, encoded as canonical unpadded base64url:
/// `ephemeral_public || nonce || ciphertext || tag`.
pub fn wrap_session_key(
    session_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
    binding_id: &str,
    generation: u64,
    request_id: &str,
    sequence: u64,
) -> Result<String, ProtocolError> {
    let recipient = X25519PublicKey::from(*recipient_public_key);
    let ephemeral = StaticSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let aad = key_wrap_transcript(binding_id, generation, request_id, sequence);
    let wrap_key = derive_wrap_key(shared.as_bytes(), &aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrap_key));
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: session_key,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::AuthenticationFailed)?;
    if encrypted.len() != 32 + 16 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let mut wrapped = Vec::with_capacity(KEY_WRAP_BYTES);
    wrapped.extend_from_slice(ephemeral_public.as_bytes());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.extend_from_slice(&encrypted[..32]);
    wrapped.extend_from_slice(&encrypted[32..]);
    Ok(URL_SAFE_NO_PAD.encode(wrapped))
}

/// Build the unambiguous transcript used by both Go and Rust key-wrap code.
pub fn key_wrap_transcript(
    binding_id: &str,
    generation: u64,
    request_id: &str,
    sequence: u64,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(64 + binding_id.len() + request_id.len());
    transcript.extend_from_slice(b"agent-remote/ego-browser/key-wrap/v1\0");
    transcript.extend_from_slice(binding_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&generation.to_be_bytes());
    transcript.extend_from_slice(&sequence.to_be_bytes());
    transcript.extend_from_slice(request_id.as_bytes());
    transcript
}

fn derive_wrap_key(shared: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"agent-remote/ego-browser/key-wrap-key/v1\0");
    digest.update(shared);
    digest.update(transcript);
    digest.finalize().into()
}

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod tests;
