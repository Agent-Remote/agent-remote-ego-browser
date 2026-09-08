//! Owner-only credential, policy, and binding storage operations.

use super::*;

impl CredentialStore {
    /// Create a store under a canonical user-selected directory.
    pub fn new(directory: PathBuf) -> Result<Self, CredentialError> {
        if !directory.is_absolute() {
            return Err(CredentialError::InvalidPath);
        }
        let existed = directory.exists();
        fs::create_dir_all(&directory).map_err(CredentialError::Io)?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(CredentialError::Io)?;
        }
        let metadata = fs::symlink_metadata(&directory).map_err(CredentialError::Io)?;
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
        Ok(Self {
            credential_path: directory.join("ego-browser-credential.json"),
            key_path: directory.join("ego-browser-device-key.bin"),
            pending_key_rotation_path: directory.join("ego-browser-device-key.pending.bin"),
            policy_path: directory.join("ego-browser-policy.json"),
            policy_lock_path: directory.join(".ego-browser-policy.lock"),
            active_binding_path: directory.join("ego-browser-active-binding.json"),
            directory,
        })
    }

    /// Return the private Unix socket used to prove that the launchd Device
    /// Client peer is alive. The socket carries no credentials or browser data.
    pub fn device_service_socket_path(&self) -> PathBuf {
        self.directory.join("device-service.sock")
    }

    /// Load and strictly verify the owner-only local policy.
    pub fn load_policy(
        &self,
        expected_skill_version: Option<&str>,
        expected_runtime_version: Option<&str>,
    ) -> Result<(LocalPolicy, VerifiedLocalPolicy), CredentialError> {
        let policy = self.load_policy_document()?;
        let verified = policy.verify(expected_skill_version, expected_runtime_version)?;
        Ok((policy, verified))
    }

    /// Start one fail-fast cross-process policy update transaction.
    pub fn begin_policy_update(&self) -> Result<PolicyUpdateTransaction<'_>, CredentialError> {
        Ok(PolicyUpdateTransaction {
            store: self,
            _lock: self.lock_policy(true)?,
        })
    }

    /// Prepare a monotonic allowlist update without changing local state.
    pub fn prepare_allowlist_update(
        &self,
        roots: Vec<PathBuf>,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        self.prepare_allowlist_update_unlocked(roots)
    }

    pub(super) fn prepare_allowlist_update_unlocked(
        &self,
        roots: Vec<PathBuf>,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        let previous = self.load_policy_document()?;
        previous.verify(None, None)?;
        let next = previous.with_allowlist_roots(roots)?;
        next.verify(None, None)?;
        Ok(PreparedPolicyUpdate { previous, next })
    }

    /// Prepare a signed learning-bundle path update without changing local state.
    pub fn prepare_learning_bundle_update(
        &self,
        root: PathBuf,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        self.prepare_learning_bundle_update_unlocked(root)
    }

    pub(super) fn prepare_learning_bundle_update_unlocked(
        &self,
        root: PathBuf,
    ) -> Result<PreparedPolicyUpdate, CredentialError> {
        let previous = self.load_policy_document()?;
        previous.verify(None, None)?;
        let next = previous.with_learning_bundle_root(root)?;
        next.verify(None, None)?;
        Ok(PreparedPolicyUpdate { previous, next })
    }

    /// Commit a prepared policy only if its exact predecessor remains current.
    pub fn commit_policy_update(
        &self,
        update: &PreparedPolicyUpdate,
    ) -> Result<(), CredentialError> {
        let _lock = self.lock_policy(false)?;
        self.commit_policy_update_unlocked(update)
    }

    pub(super) fn commit_policy_update_unlocked(
        &self,
        update: &PreparedPolicyUpdate,
    ) -> Result<(), CredentialError> {
        let current = self.load_policy_document()?;
        if current != update.previous
            || update.next.policy_revision
                != current
                    .policy_revision
                    .checked_add(1)
                    .ok_or(CredentialError::PolicyInvalid)?
        {
            return Err(CredentialError::PolicyConflict);
        }
        update.next.verify(None, None)?;
        let bytes = serde_json::to_vec(&update.next).map_err(|_| CredentialError::PolicyInvalid)?;
        atomic_owner_write(&self.directory, &self.policy_path, &bytes, "policy")
    }

    pub(crate) fn load_policy_document(&self) -> Result<LocalPolicy, CredentialError> {
        let bytes = match read_owner_file(&self.policy_path) {
            Ok(bytes) => bytes,
            Err(CredentialError::Missing) => return Ok(LocalPolicy::default()),
            Err(error) => return Err(error),
        };
        parse_strict_json(&bytes).map_err(|_| CredentialError::PolicyInvalid)
    }

    fn lock_policy(&self, fail_if_locked: bool) -> Result<File, CredentialError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(&self.policy_lock_path)
            .map_err(CredentialError::Io)?;
        validate_owner_file_metadata(&file.metadata().map_err(CredentialError::Io)?)?;
        #[cfg(unix)]
        {
            let operation = libc::LOCK_EX | if fail_if_locked { libc::LOCK_NB } else { 0 };
            if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
                let error = std::io::Error::last_os_error();
                if fail_if_locked && error.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(CredentialError::PolicyConflict);
                }
                return Err(CredentialError::Io(error));
            }
        }
        Ok(file)
    }

    /// Read and strictly validate the short-lived control credential.
    pub fn load(&self, now_unix: u64) -> Result<CommunityCredential, CredentialError> {
        self.load_credential(Some(now_unix))
    }

    /// Load a credential for an explicitly user-authenticated recovery or key
    /// rotation. The caller supplies fresh user authentication, so expiry is
    /// not used to hide the device ID or its canonical Server origin.
    pub fn load_for_rotation(&self) -> Result<CommunityCredential, CredentialError> {
        self.load_credential(None)
    }

    fn load_credential(
        &self,
        now_unix: Option<u64>,
    ) -> Result<CommunityCredential, CredentialError> {
        let bytes = read_owner_file(&self.credential_path)?;
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::TooLarge);
        }
        let credential: CommunityCredential =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        if !valid_community_credential(&credential, now_unix) {
            return Err(CredentialError::Malformed);
        }
        Ok(credential)
    }

    /// Atomically write a short-lived credential with owner-only permissions.
    pub fn save(&self, credential: &CommunityCredential) -> Result<(), CredentialError> {
        if !valid_community_credential(credential, None) {
            return Err(CredentialError::Malformed);
        }
        let bytes = serde_json::to_vec(credential).map_err(|_| CredentialError::Malformed)?;
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::TooLarge);
        }
        atomic_owner_write(&self.directory, &self.credential_path, &bytes, "credential")
    }

    /// Persist the exact binding selected and confirmed by this Device Client.
    pub fn save_active_binding(&self, binding: &ActiveBinding) -> Result<(), CredentialError> {
        validate_active_binding(binding)?;
        let bytes = serde_json::to_vec(binding).map_err(|_| CredentialError::Malformed)?;
        atomic_owner_write(
            &self.directory,
            &self.active_binding_path,
            &bytes,
            "active binding",
        )
    }

    /// Load the explicitly selected active binding for a specific device.
    pub fn load_active_binding(&self, device_id: &str) -> Result<ActiveBinding, CredentialError> {
        let bytes = read_owner_file(&self.active_binding_path)?;
        let binding: ActiveBinding =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        if binding.device_id != device_id {
            return Err(CredentialError::Malformed);
        }
        validate_active_binding(&binding)?;
        Ok(binding)
    }

    /// Remove only the reconnect handoff after pause termination or revoke.
    pub fn clear_active_binding(&self) -> Result<(), CredentialError> {
        remove_owner_file_if_present(&self.active_binding_path)
    }

    /// Store a private Ed25519 key separately from the relay credential.
    pub fn save_identity(&self, identity: &DeviceIdentity) -> Result<(), CredentialError> {
        let bytes = encode_identity(identity);
        atomic_owner_write(&self.directory, &self.key_path, &bytes, "device key")
    }

    /// Load a private key and bind it to a previously stored device ID.
    pub fn load_identity(
        &self,
        device_id: String,
        release_profile: String,
        credential_profile: String,
    ) -> Result<DeviceIdentity, CredentialError> {
        load_identity_file(
            &self.key_path,
            device_id,
            release_profile,
            credential_profile,
        )
    }

    /// Create or recover the next same-device identity rotation. The pending
    /// key is persisted before any network request so a lost Server response
    /// can be retried with exactly the same generation and public keys.
    pub fn prepare_identity_rotation(
        &self,
        current: &DeviceIdentity,
    ) -> Result<DeviceIdentity, CredentialError> {
        match load_identity_file(
            &self.pending_key_rotation_path,
            current.device_id.clone(),
            current.release_profile.clone(),
            current.credential_profile.clone(),
        ) {
            Ok(pending) => {
                let current_public = current.public_key_b64();
                let current_encryption = current.encryption_public_key_b64();
                let pending_matches_committed = pending.generation == current.generation
                    && pending.public_key_b64() == current_public
                    && pending.encryption_public_key_b64() == current_encryption;
                let pending_is_next = current
                    .generation
                    .checked_add(1)
                    .is_some_and(|generation| pending.generation == generation);
                if !pending_matches_committed && !pending_is_next {
                    return Err(CredentialError::RotationConflict);
                }
                Ok(pending)
            }
            Err(CredentialError::Missing) => {
                let generation = current
                    .generation
                    .checked_add(1)
                    .ok_or(CredentialError::RotationConflict)?;
                let pending = DeviceIdentity {
                    device_id: current.device_id.clone(),
                    signing_key: SigningKey::generate(&mut OsRng),
                    encryption_key: StaticSecret::random(),
                    generation,
                    release_profile: current.release_profile.clone(),
                    credential_profile: current.credential_profile.clone(),
                    legacy_encryption_key: false,
                };
                let bytes = encode_identity(&pending);
                atomic_owner_write(
                    &self.directory,
                    &self.pending_key_rotation_path,
                    &bytes,
                    "pending device key rotation",
                )?;
                Ok(pending)
            }
            Err(error) => Err(error),
        }
    }

    /// Commit a Server-confirmed identity and credential rotation, then remove
    /// the old binding handoff. A leftover pending file is deliberately kept on
    /// any partial failure so the operation remains safely retryable.
    pub fn commit_identity_rotation(
        &self,
        identity: &DeviceIdentity,
        credential: &CommunityCredential,
    ) -> Result<(), CredentialError> {
        let pending = load_identity_file(
            &self.pending_key_rotation_path,
            identity.device_id.clone(),
            identity.release_profile.clone(),
            identity.credential_profile.clone(),
        )?;
        if pending.generation != identity.generation
            || pending.public_key_b64() != identity.public_key_b64()
            || pending.encryption_public_key_b64() != identity.encryption_public_key_b64()
            || credential.device_id != identity.device_id
            || credential.credential_profile != identity.credential_profile
        {
            return Err(CredentialError::RotationConflict);
        }
        self.save_identity(identity)?;
        self.save(credential)?;
        self.clear_active_binding()?;
        remove_owner_file_if_present(&self.pending_key_rotation_path)
    }

    /// Discard a locally prepared rotation only when it has not been submitted.
    pub fn discard_identity_rotation(&self) -> Result<(), CredentialError> {
        remove_owner_file_if_present(&self.pending_key_rotation_path)
    }

    fn decode_identity(
        bytes: &[u8],
        device_id: String,
        release_profile: String,
        credential_profile: String,
    ) -> Result<DeviceIdentity, CredentialError> {
        if bytes.len() != 8 + 8 + 32 + 32 && bytes.len() != 8 + 8 + 32 {
            return Err(CredentialError::Malformed);
        }
        let format = &bytes[..8];
        if format != b"EGBKEY2\0" && format != b"EGBKEY1\0" {
            return Err(CredentialError::Malformed);
        }
        let generation = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        );
        if generation == 0 {
            return Err(CredentialError::Malformed);
        }
        let key: [u8; 32] = bytes[16..]
            .get(..32)
            .ok_or(CredentialError::Malformed)?
            .try_into()
            .map_err(|_| CredentialError::Malformed)?;
        let (encryption_key, legacy_encryption_key) = if format == b"EGBKEY2\0" {
            let encryption: [u8; 32] = bytes[48..]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?;
            (StaticSecret::from(encryption), false)
        } else {
            // A legacy identity has no independent encryption key.  Generate one
            // so callers can inspect/status the identity, but require a fresh
            // registration before it is accepted for relay execution.
            (StaticSecret::random(), true)
        };
        Ok(DeviceIdentity {
            device_id,
            signing_key: SigningKey::from_bytes(&key),
            encryption_key,
            generation,
            release_profile,
            credential_profile,
            legacy_encryption_key,
        })
    }

    /// Remove credentials after explicit revoke/unenroll.
    pub fn clear(&self) -> Result<(), CredentialError> {
        let paths = [
            &self.credential_path,
            &self.key_path,
            &self.pending_key_rotation_path,
            &self.policy_path,
            &self.policy_lock_path,
            &self.active_binding_path,
        ];
        for path in paths {
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(CredentialError::InvalidPath)
                }
                Ok(metadata) if !metadata.is_file() => return Err(CredentialError::InvalidPath),
                Ok(metadata) => validate_owner_file_metadata(&metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(CredentialError::Io(error)),
            }
        }
        for path in paths {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(CredentialError::Io(error)),
            }
        }
        Ok(())
    }
}

fn encode_identity(identity: &DeviceIdentity) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 8 + 32 + 32);
    bytes.extend_from_slice(b"EGBKEY2\0");
    bytes.extend_from_slice(&identity.generation.to_be_bytes());
    bytes.extend_from_slice(identity.signing_key.as_bytes());
    bytes.extend_from_slice(&identity.encryption_key.to_bytes());
    bytes
}

fn load_identity_file(
    path: &Path,
    device_id: String,
    release_profile: String,
    credential_profile: String,
) -> Result<DeviceIdentity, CredentialError> {
    let bytes = read_owner_file(path)?;
    CredentialStore::decode_identity(&bytes, device_id, release_profile, credential_profile)
}

fn remove_owner_file_if_present(path: &Path) -> Result<(), CredentialError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CredentialError::InvalidPath)
        }
        Ok(metadata) => {
            validate_owner_file_metadata(&metadata)?;
            fs::remove_file(path).map_err(CredentialError::Io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CredentialError::Io(error)),
    }
}

fn validate_active_binding(binding: &ActiveBinding) -> Result<(), CredentialError> {
    if binding.version != 1
        || validate_api_id(&binding.binding_id).is_err()
        || validate_api_id(&binding.device_id).is_err()
        || binding.generation == 0
        || !is_dedicated_task_space(&binding.task_space_label)
        || binding.authorization_mode != "ego_browser_script_full_trust"
        || !binding.user_confirmation
    {
        return Err(CredentialError::Malformed);
    }
    Ok(())
}
