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
            identity_metadata_path: directory.join("ego-browser-device-metadata.json"),
            pending_key_rotation_path: directory.join("ego-browser-device-key.pending.bin"),
            pending_rotation_metadata_path: directory.join("ego-browser-pending-rotation.json"),
            pending_registration_path: directory.join("ego-browser-pending-registration.json"),
            registration_lock_path: directory.join(".ego-browser-registration.lock"),
            policy_path: directory.join("ego-browser-policy.json"),
            policy_lock_path: directory.join(".ego-browser-policy.lock"),
            active_binding_path: directory.join("ego-browser-active-binding.json"),
            local_admission_path: directory.join(LOCAL_ADMISSION_FILE_NAME),
            directory,
        })
    }

    pub fn device_service_socket_path(&self) -> PathBuf {
        self.directory.join("device-service.sock")
    }

    /// Acquires the registration lock without waiting.
    pub fn lock_registration(&self) -> Result<RegistrationLock, CredentialError> {
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
            .open(&self.registration_lock_path)
            .map_err(CredentialError::Io)?;
        validate_owner_file_metadata(&file.metadata().map_err(CredentialError::Io)?)?;
        #[cfg(unix)]
        {
            let operation = libc::LOCK_EX | libc::LOCK_NB;
            if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(CredentialError::LocalLockBusy);
                }
                return Err(CredentialError::Io(error));
            }
        }
        Ok(RegistrationLock { _file: file })
    }

    pub fn load_pending_registration(&self) -> Result<PendingRegistration, CredentialError> {
        let pending = self.read_pending_registration()?;
        if pending.is_expired(unix_now()) {
            return Err(CredentialError::PendingExpired);
        }
        Ok(pending)
    }

    /// Reads pending state without expiry so diagnostics preserve recovery evidence.
    fn read_pending_registration(&self) -> Result<PendingRegistration, CredentialError> {
        let bytes = read_owner_file(&self.pending_registration_path)?;
        let pending: PendingRegistration =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        if pending.version != 1
            || validate_api_id(&pending.device_id).is_err()
            || canonical_server_url(&pending.server_url).is_err()
            || !matches!(
                pending.enrollment_mode.as_str(),
                "initial" | "ensure" | "re_enroll" | "rotate"
            )
            || pending.device_generation == 0
            || pending.created_at_unix == 0
            || pending.idempotency_key.len() < 22
            || pending.idempotency_key.len() > 256
            || pending
                .idempotency_key
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b'"' || byte == b'\\')
            || pending.signing_public_key_sha256.len() != 64
            || pending.encryption_public_key_sha256.len() != 64
            || !pending
                .signing_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !pending
                .encryption_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CredentialError::Malformed);
        }
        Ok(pending)
    }

    /// Persists recovery state atomically with owner-only permissions.
    pub fn save_pending_registration(
        &self,
        pending: &PendingRegistration,
    ) -> Result<(), CredentialError> {
        if pending.version != 1
            || pending.device_generation == 0
            || pending.created_at_unix == 0
            || validate_api_id(&pending.device_id).is_err()
            || canonical_server_url(&pending.server_url).is_err()
            || !matches!(
                pending.enrollment_mode.as_str(),
                "initial" | "ensure" | "re_enroll" | "rotate"
            )
            || pending.idempotency_key.len() < 22
            || pending.idempotency_key.len() > 256
        {
            return Err(CredentialError::Malformed);
        }
        let bytes = serde_json::to_vec(pending).map_err(|_| CredentialError::Malformed)?;
        atomic_owner_write(
            &self.directory,
            &self.pending_registration_path,
            &bytes,
            "pending registration",
        )
    }

    /// Updates only the bounded error attached to pending state.
    pub fn record_pending_registration_error(
        &self,
        code: Option<&str>,
    ) -> Result<(), CredentialError> {
        let Ok(mut pending) = self.read_pending_registration() else {
            return Ok(());
        };
        pending.last_error_code = code.map(str::to_owned);
        self.save_pending_registration(&pending)
    }

    /// Clears pending state only after identity and credential persistence.
    pub fn clear_pending_registration(&self) -> Result<(), CredentialError> {
        remove_owner_file_if_present(&self.pending_registration_path)
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

    pub(super) fn prepare_managed_learning_bundle_update_unlocked(
        &self,
        current_release: &Path,
        expected_skill_version: &str,
        expected_runtime_version: &str,
        learning_key: &[u8; 32],
    ) -> Result<(VerifiedLocalPolicy, Option<PreparedPolicyUpdate>), CredentialError> {
        let previous = self.load_policy_document()?;
        match previous.verify_with_key(
            Some(expected_skill_version),
            Some(expected_runtime_version),
            learning_key,
        ) {
            Ok(verified) => return Ok((verified, None)),
            Err(CredentialError::LearningBundleInvalid) => {}
            Err(error) => return Err(error),
        }

        let mut policy_without_learning = previous.clone();
        policy_without_learning.learning_bundle_root = None;
        policy_without_learning.verify_with_key(None, None, learning_key)?;

        let canonical_current_release = current_release
            .canonicalize()
            .map_err(|_| CredentialError::LearningBundleInvalid)?;
        if canonical_current_release != current_release
            || canonical_current_release
                .file_name()
                .and_then(|value| value.to_str())
                != Some(env!("CARGO_PKG_VERSION"))
        {
            return Err(CredentialError::LearningBundleInvalid);
        }
        let current_release = canonical_current_release;
        let releases = current_release
            .parent()
            .filter(|path| path.file_name().and_then(|value| value.to_str()) == Some("releases"))
            .ok_or(CredentialError::LearningBundleInvalid)?;
        let previous_root = PathBuf::from(
            previous
                .learning_bundle_root
                .as_deref()
                .ok_or(CredentialError::LearningBundleInvalid)?,
        );
        let previous_release = previous_root
            .parent()
            .filter(|_| {
                previous_root.file_name().and_then(|value| value.to_str())
                    == Some("learning-bundle")
            })
            .ok_or(CredentialError::LearningBundleInvalid)?;
        if previous_release.parent() != Some(releases)
            || previous_release == current_release.as_path()
            || !is_stable_release_version(previous_release.file_name())
            || previous_root
                .canonicalize()
                .map_err(|_| CredentialError::LearningBundleInvalid)?
                != previous_root
        {
            return Err(CredentialError::LearningBundleInvalid);
        }

        let next = previous.with_learning_bundle_root(current_release.join("learning-bundle"))?;
        let verified = next.verify_with_key(
            Some(expected_skill_version),
            Some(expected_runtime_version),
            learning_key,
        )?;
        Ok((verified, Some(PreparedPolicyUpdate { previous, next })))
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
        self.commit_policy_update_unlocked_with_key(update, &TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY)
    }

    pub(super) fn commit_policy_update_unlocked_with_key(
        &self,
        update: &PreparedPolicyUpdate,
        learning_key: &[u8; 32],
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
        update.next.verify_with_key(None, None, learning_key)?;
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

    /// Loads expired credential metadata only for fresh user-authenticated recovery.
    pub fn load_for_rotation(&self) -> Result<CommunityCredential, CredentialError> {
        self.load_credential(None)
    }

    /// Reads exact identity metadata, including for expired-credential recovery.
    pub fn local_metadata(&self) -> Result<LocalDeviceMetadata, CredentialError> {
        match self.load_for_rotation() {
            Ok(credential) => {
                let identity = self.load_identity(
                    credential.device_id.clone(),
                    credential.release_profile.clone(),
                    credential.credential_profile.clone(),
                )?;
                // Backfill legacy metadata only after validating both credential and key.
                self.save_identity_metadata(&identity, &credential.server_url)?;
                Ok(LocalDeviceMetadata {
                    device_id: identity.device_id,
                    device_generation: identity.generation,
                    server_url: credential.server_url,
                    release_profile: identity.release_profile,
                    credential_profile: identity.credential_profile,
                    credential_revision: credential.revision,
                    credential_expires_at_unix: credential.expires_at_unix,
                })
            }
            Err(CredentialError::Missing) => {
                let metadata = self.load_identity_metadata()?;
                let identity = self.load_identity(
                    metadata.device_id.clone(),
                    metadata.release_profile.clone(),
                    metadata.credential_profile.clone(),
                )?;
                Ok(LocalDeviceMetadata {
                    device_id: identity.device_id,
                    device_generation: identity.generation,
                    server_url: metadata.server_url,
                    release_profile: identity.release_profile,
                    credential_profile: identity.credential_profile,
                    credential_revision: 0,
                    credential_expires_at_unix: 0,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn save_identity_metadata(
        &self,
        identity: &DeviceIdentity,
        server_url: &str,
    ) -> Result<(), CredentialError> {
        let metadata = StoredIdentityMetadata {
            version: 1,
            device_id: identity.device_id.clone(),
            server_url: canonical_server_url(server_url)?,
            release_profile: identity.release_profile.clone(),
            credential_profile: identity.credential_profile.clone(),
        };
        if !valid_stored_identity_metadata(&metadata) {
            return Err(CredentialError::Malformed);
        }
        let bytes = serde_json::to_vec(&metadata).map_err(|_| CredentialError::Malformed)?;
        atomic_owner_write(
            &self.directory,
            &self.identity_metadata_path,
            &bytes,
            "device metadata",
        )
    }

    pub fn load_identity_metadata(&self) -> Result<StoredIdentityMetadata, CredentialError> {
        let bytes = read_owner_file(&self.identity_metadata_path)?;
        let metadata: StoredIdentityMetadata =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        if !valid_stored_identity_metadata(&metadata) {
            return Err(CredentialError::Malformed);
        }
        Ok(metadata)
    }

    /// Reports identity presence while rejecting an unsafe key path.
    pub fn identity_exists(&self) -> Result<bool, CredentialError> {
        match fs::symlink_metadata(&self.key_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(CredentialError::InvalidPath);
                }
                validate_owner_file_metadata(&metadata)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(CredentialError::Io(error)),
        }
    }

    /// Removes short-lived runtime state while retaining identity and verified policy.
    pub fn retire_runtime_state(&self) -> Result<(), CredentialError> {
        // Preserve origin before deleting the only record carrying it on legacy installs.
        match self.load_for_rotation() {
            Ok(credential) => {
                let identity = self.load_identity(
                    credential.device_id.clone(),
                    credential.release_profile.clone(),
                    credential.credential_profile.clone(),
                )?;
                self.save_identity_metadata(&identity, &credential.server_url)?;
            }
            Err(CredentialError::Missing) => {}
            Err(error) => return Err(error),
        }
        remove_owner_file_if_present(&self.credential_path)?;
        remove_owner_file_if_present(&self.active_binding_path)
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

    pub fn local_admission_path(&self) -> PathBuf {
        self.local_admission_path.clone()
    }

    /// Reads the gate while preserving missing or corrupt states for diagnostics.
    pub fn load_local_admission(&self) -> Result<LocalAdmissionRecord, CredentialError> {
        let bytes = read_owner_file(&self.local_admission_path)?;
        if bytes.len() > 16 * 1024 {
            return Err(CredentialError::TooLarge);
        }
        let record: LocalAdmissionRecord =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        validate_local_admission_record(&record)?;
        Ok(record)
    }

    /// Returns whether an exact active binding has a valid local admission record.
    pub fn local_admission_is_open(
        &self,
        device_id: &str,
        binding: &ActiveBinding,
    ) -> Result<bool, CredentialError> {
        let record = match self.load_local_admission() {
            Ok(record) => record,
            Err(CredentialError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(record.state == LOCAL_ADMISSION_OPEN
            && record.device_id.as_deref() == Some(device_id)
            && record.binding_id.as_deref() == Some(binding.binding_id.as_str())
            && record.binding_generation == Some(binding.generation))
    }

    /// Opens admission only for a validated active binding.
    pub fn open_local_admission(&self, binding: &ActiveBinding) -> Result<(), CredentialError> {
        validate_active_binding(binding)?;
        let identity = self
            .load_for_rotation()
            .ok()
            .filter(|credential| credential.device_id == binding.device_id)
            .and_then(|credential| {
                self.load_identity(
                    credential.device_id.clone(),
                    credential.release_profile.clone(),
                    credential.credential_profile.clone(),
                )
                .ok()
            })
            .ok_or(CredentialError::Malformed)?;
        let record = LocalAdmissionRecord {
            version: 1,
            state: LOCAL_ADMISSION_OPEN.to_owned(),
            device_id: Some(identity.device_id),
            device_generation: Some(identity.generation),
            binding_id: Some(binding.binding_id.clone()),
            binding_generation: Some(binding.generation),
            updated_at_unix: unix_now(),
        };
        self.write_local_admission(&record)
    }

    /// Closes admission idempotently while retaining identity metadata for setup.
    pub fn close_local_admission(&self) -> Result<(), CredentialError> {
        self.write_local_admission(&self.local_admission_record(LOCAL_ADMISSION_CLOSED))
    }

    /// Marks the supervisor reusable but not executable after setup or repair.
    pub fn ready_local_admission(&self) -> Result<(), CredentialError> {
        self.write_local_admission(&self.local_admission_record(LOCAL_ADMISSION_READY))
    }

    fn local_admission_record(&self, state: &str) -> LocalAdmissionRecord {
        let (device_id, device_generation) = self.local_identity_reference();
        LocalAdmissionRecord {
            version: 1,
            state: state.to_owned(),
            device_id,
            device_generation,
            binding_id: None,
            binding_generation: None,
            updated_at_unix: unix_now(),
        }
    }

    fn local_identity_reference(&self) -> (Option<String>, Option<u64>) {
        if let Ok(credential) = self.load_for_rotation() {
            if let Ok(identity) = self.load_identity(
                credential.device_id.clone(),
                credential.release_profile,
                credential.credential_profile,
            ) {
                return (Some(identity.device_id), Some(identity.generation));
            }
        }
        if let Ok(metadata) = self.load_identity_metadata() {
            if let Ok(identity) = self.load_identity(
                metadata.device_id.clone(),
                metadata.release_profile,
                metadata.credential_profile,
            ) {
                return (Some(identity.device_id), Some(identity.generation));
            }
        }
        (None, None)
    }

    fn write_local_admission(&self, record: &LocalAdmissionRecord) -> Result<(), CredentialError> {
        validate_local_admission_record(record)?;
        let bytes = serde_json::to_vec(record).map_err(|_| CredentialError::Malformed)?;
        atomic_owner_write(
            &self.directory,
            &self.local_admission_path,
            &bytes,
            "local-admission",
        )
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

    /// Creates or recovers a rotation, persisting its key before any request.
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

    pub fn load_pending_identity_rotation(
        &self,
        identity: &DeviceIdentity,
    ) -> Result<Option<DeviceIdentity>, CredentialError> {
        match load_identity_file(
            &self.pending_key_rotation_path,
            identity.device_id.clone(),
            identity.release_profile.clone(),
            identity.credential_profile.clone(),
        ) {
            Ok(pending) => Ok(Some(pending)),
            Err(CredentialError::Missing) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Loads or creates rotation recovery state under the pre-request registration lock.
    pub fn load_or_create_pending_rotation(
        &self,
        current: &DeviceIdentity,
        next: &DeviceIdentity,
        current_credential_revision: u64,
        idempotency_key: Option<&str>,
    ) -> Result<PendingRotation, CredentialError> {
        if current_credential_revision == 0 {
            return Err(CredentialError::RotationConflict);
        }
        let same_identity_scope = current.device_id == next.device_id
            && current.release_profile == next.release_profile
            && current.credential_profile == next.credential_profile;
        let current_is_source = next.generation == current.generation.saturating_add(1);
        let current_is_target = next.generation == current.generation
            && next.public_key_b64() == current.public_key_b64()
            && next.encryption_public_key_b64() == current.encryption_public_key_b64();
        if !same_identity_scope || (!current_is_source && !current_is_target) {
            return Err(CredentialError::RotationConflict);
        }
        match self.read_pending_rotation()? {
            Some(existing) if pending_rotation_matches(&existing, current, next) => {
                if current_credential_revision < existing.previous_credential_revision {
                    return Err(CredentialError::RotationConflict);
                }
                if let Some(key) = idempotency_key {
                    if key != existing.idempotency_key {
                        return Err(CredentialError::RotationConflict);
                    }
                }
                Ok(existing)
            }
            Some(_) => Err(CredentialError::RotationConflict),
            None if current_is_source => {
                let key = idempotency_key.map(str::to_owned).unwrap_or_else(|| {
                    let mut bytes = [0_u8; 32];
                    getrandom_bytes(&mut bytes);
                    URL_SAFE_NO_PAD.encode(bytes)
                });
                if key.len() < 22
                    || key.len() > 256
                    || key
                        .bytes()
                        .any(|byte| !byte.is_ascii_graphic() || byte == b'"' || byte == b'\\')
                {
                    return Err(CredentialError::Malformed);
                }
                let metadata = PendingRotation {
                    version: 1,
                    device_id: current.device_id.clone(),
                    current_generation: current.generation,
                    target_generation: next.generation,
                    previous_credential_revision: current_credential_revision,
                    old_signing_public_key_sha256: public_value_sha256(&current.public_key_b64()),
                    old_encryption_public_key_sha256: public_value_sha256(
                        &current.encryption_public_key_b64(),
                    ),
                    target_signing_public_key_sha256: public_value_sha256(&next.public_key_b64()),
                    target_encryption_public_key_sha256: public_value_sha256(
                        &next.encryption_public_key_b64(),
                    ),
                    idempotency_key: key,
                    created_at_unix: unix_now(),
                };
                let bytes =
                    serde_json::to_vec(&metadata).map_err(|_| CredentialError::Malformed)?;
                atomic_owner_write(
                    &self.directory,
                    &self.pending_rotation_metadata_path,
                    &bytes,
                    "pending rotation metadata",
                )?;
                Ok(metadata)
            }
            None => Err(CredentialError::RotationConflict),
        }
    }

    pub fn load_pending_rotation(&self) -> Result<Option<PendingRotation>, CredentialError> {
        self.read_pending_rotation()
    }

    fn read_pending_rotation(&self) -> Result<Option<PendingRotation>, CredentialError> {
        let bytes = match read_owner_file(&self.pending_rotation_metadata_path) {
            Ok(bytes) => bytes,
            Err(CredentialError::Missing) => return Ok(None),
            Err(error) => return Err(error),
        };
        let value: PendingRotation =
            parse_strict_json(&bytes).map_err(|_| CredentialError::Malformed)?;
        if value.version != 1
            || validate_api_id(&value.device_id).is_err()
            || value.current_generation == 0
            || value.target_generation != value.current_generation.saturating_add(1)
            || value.previous_credential_revision == 0
            || value.created_at_unix == 0
            || value.idempotency_key.len() < 22
            || value.idempotency_key.len() > 256
            || value
                .idempotency_key
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b'"' || byte == b'\\')
            || value.old_signing_public_key_sha256.len() != 64
            || value.old_encryption_public_key_sha256.len() != 64
            || value.target_signing_public_key_sha256.len() != 64
            || value.target_encryption_public_key_sha256.len() != 64
            || !value
                .old_signing_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !value
                .old_encryption_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !value
                .target_signing_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !value
                .target_encryption_public_key_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CredentialError::Malformed);
        }
        Ok(Some(value))
    }

    /// Finalizes committed rotation only after validating all recovery state.
    pub fn finish_interrupted_identity_rotation(
        &self,
        identity: &DeviceIdentity,
        credential: &CommunityCredential,
    ) -> Result<bool, CredentialError> {
        let Some(rotation) = self.read_pending_rotation()? else {
            return Ok(false);
        };
        if self.load_pending_identity_rotation(identity)?.is_some()
            || rotation.device_id != identity.device_id
            || rotation.target_generation != identity.generation
            || rotation.target_signing_public_key_sha256
                != public_value_sha256(&identity.public_key_b64())
            || rotation.target_encryption_public_key_sha256
                != public_value_sha256(&identity.encryption_public_key_b64())
            || credential.device_id != identity.device_id
            || credential.release_profile != identity.release_profile
            || credential.credential_profile != identity.credential_profile
            || credential.revision <= rotation.previous_credential_revision
        {
            return Ok(false);
        }
        let metadata = self.load_identity_metadata()?;
        if metadata.device_id != identity.device_id
            || metadata.server_url != credential.server_url
            || metadata.release_profile != identity.release_profile
            || metadata.credential_profile != identity.credential_profile
        {
            return Err(CredentialError::RotationConflict);
        }
        match self.load_active_binding(&identity.device_id) {
            Ok(_) => return Err(CredentialError::RotationConflict),
            Err(CredentialError::Missing) => {}
            Err(error) => return Err(error),
        }
        self.clear_pending_rotation_metadata()?;
        Ok(true)
    }

    /// Clears rotation metadata only after the new identity is committed.
    pub fn clear_pending_rotation_metadata(&self) -> Result<(), CredentialError> {
        remove_owner_file_if_present(&self.pending_rotation_metadata_path)
    }

    /// Commits Server-confirmed rotation while retaining pending state on partial failure.
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
        self.save_identity_metadata(identity, &credential.server_url)?;
        self.save(credential)?;
        self.clear_active_binding()?;
        remove_owner_file_if_present(&self.pending_key_rotation_path)?;
        self.clear_pending_rotation_metadata()
    }

    /// Discard a locally prepared rotation only when it has not been submitted.
    pub fn discard_identity_rotation(&self) -> Result<(), CredentialError> {
        remove_owner_file_if_present(&self.pending_key_rotation_path)?;
        self.clear_pending_rotation_metadata()
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
            // A generated legacy encryption key permits inspection, not relay execution.
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
        // Retain the lock inode while clearing identity so concurrent ensure cannot bypass it.
        self.close_local_admission()?;
        let paths = [
            &self.credential_path,
            &self.key_path,
            &self.identity_metadata_path,
            &self.pending_key_rotation_path,
            &self.pending_rotation_metadata_path,
            &self.pending_registration_path,
            &self.policy_path,
            &self.policy_lock_path,
            &self.active_binding_path,
            &self.local_admission_path,
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

fn is_stable_release_version(value: Option<&std::ffi::OsStr>) -> bool {
    let Some(value) = value.and_then(|value| value.to_str()) else {
        return false;
    };
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

fn pending_rotation_matches(
    existing: &PendingRotation,
    current: &DeviceIdentity,
    next: &DeviceIdentity,
) -> bool {
    let target_matches = existing.device_id == current.device_id
        && existing.target_generation == next.generation
        && existing.target_signing_public_key_sha256 == public_value_sha256(&next.public_key_b64())
        && existing.target_encryption_public_key_sha256
            == public_value_sha256(&next.encryption_public_key_b64());
    let source_matches = existing.current_generation == current.generation
        && existing.old_signing_public_key_sha256 == public_value_sha256(&current.public_key_b64())
        && existing.old_encryption_public_key_sha256
            == public_value_sha256(&current.encryption_public_key_b64());
    let installed_target_matches = existing.target_generation == current.generation
        && existing.target_signing_public_key_sha256
            == public_value_sha256(&current.public_key_b64())
        && existing.target_encryption_public_key_sha256
            == public_value_sha256(&current.encryption_public_key_b64());
    target_matches && (source_matches || installed_target_matches)
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

fn validate_local_admission_record(record: &LocalAdmissionRecord) -> Result<(), CredentialError> {
    if record.version != 1
        || !matches!(
            record.state.as_str(),
            LOCAL_ADMISSION_CLOSED | LOCAL_ADMISSION_READY | LOCAL_ADMISSION_OPEN
        )
        || record.updated_at_unix == 0
    {
        return Err(CredentialError::Malformed);
    }
    if let Some(device_id) = record.device_id.as_deref() {
        validate_api_id(device_id)?;
    }
    if let Some(binding_id) = record.binding_id.as_deref() {
        validate_api_id(binding_id)?;
    }
    if record.device_generation == Some(0) || record.binding_generation == Some(0) {
        return Err(CredentialError::Malformed);
    }
    match record.state.as_str() {
        LOCAL_ADMISSION_OPEN => {
            if record.device_id.is_none()
                || record.device_generation.is_none()
                || record.binding_id.is_none()
                || record.binding_generation.is_none()
            {
                return Err(CredentialError::Malformed);
            }
        }
        LOCAL_ADMISSION_CLOSED | LOCAL_ADMISSION_READY => {
            if record.binding_id.is_some() || record.binding_generation.is_some() {
                return Err(CredentialError::Malformed);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn valid_stored_identity_metadata(metadata: &StoredIdentityMetadata) -> bool {
    metadata.version == 1
        && validate_api_id(&metadata.device_id).is_ok()
        && canonical_server_url(&metadata.server_url)
            .is_ok_and(|value| value == metadata.server_url)
        && !metadata.release_profile.is_empty()
        && metadata.release_profile.len() <= 128
        && metadata
            .release_profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        && metadata.credential_profile == "community_file"
}
