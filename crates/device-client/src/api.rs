//! Browser binding control-plane client operations.

use super::*;

impl DeviceApiClient {
    /// Create an API client from validated credential data.
    pub fn new(credential: &CommunityCredential) -> Result<Self, CredentialError> {
        let base_url = canonical_server_url(&credential.server_url)?;
        if base_url != credential.server_url {
            return Err(CredentialError::Malformed);
        }
        Ok(Self {
            http: control_api_client()?,
            base_url,
            token: credential.token.clone(),
            identity: None,
        })
    }

    /// Create an API client that signs device proof-of-possession requests.
    pub fn with_identity(
        credential: &CommunityCredential,
        identity: DeviceIdentity,
    ) -> Result<Self, CredentialError> {
        let mut client = Self::new(credential)?;
        if identity.device_id != credential.device_id
            || identity.credential_profile != credential.credential_profile
        {
            return Err(CredentialError::Malformed);
        }
        client.identity = Some(identity);
        Ok(client)
    }

    /// Create a client for initial registration or explicit same-device key
    /// rotation. The bearer token must be a fresh user credential; it is never
    /// persisted by this client.
    pub fn with_user_token(
        server_url: &str,
        user_token: &str,
        identity: DeviceIdentity,
    ) -> Result<Self, CredentialError> {
        let base_url = canonical_server_url(server_url)?;
        if base_url != server_url
            || user_token.is_empty()
            || user_token.len() > TOKEN_MAX_BYTES
            || !user_token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        {
            return Err(CredentialError::Malformed);
        }
        Ok(Self {
            http: control_api_client()?,
            base_url,
            token: user_token.to_owned(),
            identity: Some(identity),
        })
    }

    /// Return the validated control-plane base URL.
    pub fn server_url(&self) -> &str {
        &self.base_url
    }

    /// Return the locally held device identity, when configured.
    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }

    /// Register the exact locally held public keys, or rotate an existing
    /// device to their newer generation, using proof signed by those new keys.
    pub async fn register_device(
        &self,
        mut payload: serde_json::Value,
    ) -> Result<serde_json::Value, CredentialError> {
        let identity = self.identity.as_ref().ok_or(CredentialError::Malformed)?;
        let public_key = identity.public_key_b64();
        let encryption_public_key = identity.encryption_public_key_b64();
        let object = payload.as_object().ok_or(CredentialError::Malformed)?;
        let matches_identity = object.get("device_id").and_then(serde_json::Value::as_str)
            == Some(identity.device_id.as_str())
            && object.get("public_key").and_then(serde_json::Value::as_str)
                == Some(public_key.as_str())
            && object
                .get("encryption_public_key")
                .and_then(serde_json::Value::as_str)
                == Some(encryption_public_key.as_str())
            && object.get("generation").and_then(serde_json::Value::as_u64)
                == Some(identity.generation)
            && object
                .get("release_profile")
                .and_then(serde_json::Value::as_str)
                == Some(identity.release_profile.as_str())
            && object
                .get("credential_profile")
                .and_then(serde_json::Value::as_str)
                == Some(identity.credential_profile.as_str())
            && !object.contains_key("proof_challenge")
            && !object.contains_key("proof_signature");
        if !matches_identity {
            return Err(CredentialError::Malformed);
        }
        self.add_proof_for_generation(&mut payload, identity.generation, "register_device", None)
            .await?;
        self.post("/api/v1/ego-browser/devices/register", payload)
            .await
    }

    /// Fetch user-visible remote fclaude session candidates.
    pub async fn candidates(&self) -> Result<serde_json::Value, CredentialError> {
        self.get("/api/v1/ego-browser/bindings/candidates").await
    }

    /// Claim one explicitly selected remote tool session.
    pub async fn claim(
        &self,
        mut payload: serde_json::Value,
    ) -> Result<serde_json::Value, CredentialError> {
        let identity = self.identity.as_ref().ok_or(CredentialError::Malformed)?;
        let object = payload.as_object_mut().ok_or(CredentialError::Malformed)?;
        object.insert(
            "encryption_public_key".into(),
            serde_json::Value::String(identity.encryption_public_key_b64()),
        );
        self.add_proof(&mut payload, "claim_binding", None).await?;
        self.post("/api/v1/ego-browser/bindings/claim", payload)
            .await
    }

    /// Read a binding status.
    pub async fn status(&self, binding_id: &str) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        self.get(&format!("/api/v1/ego-browser/bindings/{binding_id}"))
            .await
    }

    /// Report local Bridge capability metadata and activate a binding.
    pub async fn connected(
        &self,
        binding_id: &str,
        generation: u64,
        mut payload: serde_json::Value,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let object = payload.as_object_mut().ok_or(CredentialError::Malformed)?;
        object.insert("generation".into(), serde_json::json!(generation));
        self.add_proof_for_generation(
            &mut payload,
            generation,
            "connect_binding",
            Some(binding_id),
        )
        .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/connected"),
            payload,
        )
        .await
    }

    /// Obtain a one-time relay ticket for the local Bridge role.
    pub async fn bridge_relay_ticket(
        &self,
        binding_id: &str,
        generation: u64,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let identity = self.identity.as_ref().ok_or(CredentialError::Malformed)?;
        let mut payload = serde_json::json!({
            "generation": generation,
            "role": "bridge",
            "ego_browser_device_id": identity.device_id,
        });
        self.add_proof_for_generation(
            &mut payload,
            generation,
            "issue_relay_ticket",
            Some(binding_id),
        )
        .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/relay-ticket"),
            payload,
        )
        .await
    }

    /// Renew a binding lease using the current local capability revisions.
    pub async fn renew_binding(
        &self,
        binding_id: &str,
        generation: u64,
        allowlist_revision: u64,
        learning_bundle_digest: Option<String>,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let mut payload = serde_json::json!({
            "generation": generation,
            "allowlist_revision": allowlist_revision,
            "learning_bundle_digest": learning_bundle_digest,
        });
        self.add_proof_for_generation(&mut payload, generation, "renew_binding", Some(binding_id))
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/renew"),
            payload,
        )
        .await
    }

    /// Stop a binding using its expected generation.
    pub async fn stop(
        &self,
        binding_id: &str,
        generation: u64,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let mut payload = serde_json::json!({"generation": generation});
        self.add_proof_for_generation(&mut payload, generation, "stop_binding", Some(binding_id))
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/stop"),
            payload,
        )
        .await
    }

    /// Revoke a binding permanently.
    pub async fn revoke(
        &self,
        binding_id: &str,
        generation: u64,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let mut payload = serde_json::json!({"generation": generation});
        self.add_proof_for_generation(&mut payload, generation, "revoke_binding", Some(binding_id))
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/revoke"),
            payload,
        )
        .await
    }

    /// Pause a binding pending an explicit user resume.
    pub async fn pause(
        &self,
        binding_id: &str,
        generation: u64,
    ) -> Result<serde_json::Value, CredentialError> {
        self.pause_with_reason(binding_id, generation, "user_pause")
            .await
    }

    /// Permanently revoke this independently authenticated ego-browser device.
    pub async fn revoke_device(&self) -> Result<serde_json::Value, CredentialError> {
        let identity = self.identity.as_ref().ok_or(CredentialError::Malformed)?;
        validate_api_id(&identity.device_id)?;
        let device_id = identity.device_id.clone();
        let generation = identity.generation;
        let mut payload = serde_json::json!({
            "generation": generation,
            "reason": "device_revoked",
        });
        self.add_proof_for_generation(&mut payload, generation, "revoke_device", None)
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/devices/{device_id}/revoke"),
            payload,
        )
        .await
    }

    /// Pause a binding with a finite content-free lifecycle reason.
    pub async fn pause_with_reason(
        &self,
        binding_id: &str,
        generation: u64,
        reason: &str,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        if !is_content_free_pause_reason(reason) {
            return Err(CredentialError::Malformed);
        }
        let mut payload = serde_json::json!({
            "generation": generation,
            "reason": reason,
        });
        self.add_proof_for_generation(&mut payload, generation, "pause_binding", Some(binding_id))
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/pause"),
            payload,
        )
        .await
    }

    /// Resume a paused binding with a fresh generation authorization.
    pub async fn resume(
        &self,
        binding_id: &str,
        generation: u64,
        allowlist_revision: u64,
        learning_bundle_digest: Option<String>,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let mut payload = serde_json::json!({
            "generation": generation,
            "user_confirmation": true,
            "allowlist_revision": allowlist_revision,
            "learning_bundle_digest": learning_bundle_digest,
        });
        self.add_proof_for_generation(&mut payload, generation, "resume_binding", Some(binding_id))
            .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/resume"),
            payload,
        )
        .await
    }

    /// Confirm a new local helper allowlist and invalidate old permits.
    pub async fn confirm_allowlist(
        &self,
        binding_id: &str,
        generation: u64,
        expected_revision: u64,
        roots_digest: &str,
    ) -> Result<serde_json::Value, CredentialError> {
        validate_api_id(binding_id)?;
        let mut payload = serde_json::json!({
            "generation": generation,
            "expected_revision": expected_revision,
            "roots_digest": roots_digest,
            "user_confirmation": true,
        });
        self.add_proof_for_generation(
            &mut payload,
            generation,
            "confirm_allowlist",
            Some(binding_id),
        )
        .await?;
        self.post(
            &format!("/api/v1/ego-browser/bindings/{binding_id}/allowlist/confirm"),
            payload,
        )
        .await
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value, CredentialError> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| CredentialError::Network)?;
        decode_response(response).await
    }

    async fn post(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, CredentialError> {
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|_| CredentialError::Network)?;
        decode_response(response).await
    }

    async fn add_proof(
        &self,
        payload: &mut serde_json::Value,
        operation: &str,
        binding_id: Option<&str>,
    ) -> Result<(), CredentialError> {
        let generation = self
            .identity
            .as_ref()
            .map(|identity| identity.generation)
            .unwrap_or(1);
        self.add_proof_for_generation(payload, generation, operation, binding_id)
            .await
    }

    async fn add_proof_for_generation(
        &self,
        payload: &mut serde_json::Value,
        generation: u64,
        operation: &str,
        binding_id: Option<&str>,
    ) -> Result<(), CredentialError> {
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
        if generation == 0 {
            return Err(CredentialError::Malformed);
        }
        let device_id = identity.device_id.clone();
        let challenge_response = self
            .post(
                "/api/v1/ego-browser/proof-challenges",
                serde_json::json!({
                    "operation": operation,
                    "ego_browser_device_id": device_id,
                    "generation": generation,
                    "binding_id": binding_id,
                }),
            )
            .await?;
        let challenge_text = challenge_response
            .pointer("/data/challenge")
            .and_then(serde_json::Value::as_str)
            .ok_or(CredentialError::Malformed)?;
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge_text)
            .map_err(|_| CredentialError::Malformed)?;
        if challenge.len() != 32 {
            return Err(CredentialError::Malformed);
        }
        let host = reqwest::Url::parse(&self.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or(CredentialError::Malformed)?;
        let signature = identity.sign_request(
            operation, generation, binding_id, &challenge, &host, payload,
        )?;
        let object = payload.as_object_mut().ok_or(CredentialError::Malformed)?;
        object.insert(
            "proof_challenge".into(),
            serde_json::Value::String(challenge_text.to_owned()),
        );
        object.insert(
            "proof_signature".into(),
            serde_json::Value::String(signature),
        );
        Ok(())
    }
}
