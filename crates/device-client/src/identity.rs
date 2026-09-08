//! Device proof and encryption identity operations.

use super::*;

impl DeviceIdentity {
    /// Generate a new independent ego-browser device key.
    pub fn generate(
        release_profile: impl Into<String>,
        credential_profile: impl Into<String>,
    ) -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            signing_key: SigningKey::generate(&mut OsRng),
            encryption_key: StaticSecret::random(),
            generation: 1,
            release_profile: release_profile.into(),
            credential_profile: credential_profile.into(),
            legacy_encryption_key: false,
        }
    }

    /// Return the public key in URL-safe base64 form.
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Return the independent X25519 encryption public key in URL-safe base64 form.
    pub fn encryption_public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&self.encryption_key).to_bytes())
    }

    /// Return whether this identity was loaded from the pre-encryption key format.
    pub fn needs_encryption_key_rotation(&self) -> bool {
        self.legacy_encryption_key
    }

    /// Sign a payload-bound proof-of-possession transcript.
    ///
    /// Device key generation and binding generation are independent counters:
    /// rotating the device key changes the former, while pause/resume and
    /// lifecycle transitions advance the latter.  The server verifies the
    /// operation's generation in the transcript, so callers must be able to
    /// sign a current binding generation without changing the stored device
    /// generation.
    pub fn sign_request(
        &self,
        operation: &str,
        operation_generation: u64,
        binding_id: Option<&str>,
        challenge: &[u8],
        server_host: &str,
        payload: &serde_json::Value,
    ) -> Result<String, CredentialError> {
        let context = DeviceProofContext {
            operation,
            device_id: &self.device_id,
            device_generation: self.generation,
            operation_generation,
            binding_id,
            release_profile: &self.release_profile,
            credential_profile: &self.credential_profile,
            server_host,
        };
        let message = device_proof_message(&context, challenge, payload)
            .map_err(|_| CredentialError::Malformed)?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing_key.sign(&message).to_bytes()))
    }

    /// Verify a payload-bound proof signature using a registered public key.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_request(
        operation: &str,
        device_id: &str,
        device_generation: u64,
        operation_generation: u64,
        binding_id: Option<&str>,
        release_profile: &str,
        credential_profile: &str,
        server_host: &str,
        challenge: &[u8],
        payload: &serde_json::Value,
        public_key_b64: &str,
        signature_b64: &str,
    ) -> bool {
        let key_bytes = match URL_SAFE_NO_PAD.decode(public_key_b64) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let key_bytes: [u8; 32] = match key_bytes.try_into() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let key = match VerifyingKey::from_bytes(&key_bytes) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let signature = match URL_SAFE_NO_PAD.decode(signature_b64) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let signature = match ed25519_dalek::Signature::from_slice(&signature) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let context = DeviceProofContext {
            operation,
            device_id,
            device_generation,
            operation_generation,
            binding_id,
            release_profile,
            credential_profile,
            server_host,
        };
        let message = match device_proof_message(&context, challenge, payload) {
            Ok(value) => value,
            Err(_) => return false,
        };
        key.verify_strict(&message, &signature).is_ok()
    }
}
