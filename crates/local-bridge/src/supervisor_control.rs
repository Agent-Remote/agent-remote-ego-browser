//! Local bridge supervisor control internals.

use super::*;

impl BridgeSupervisor {
    /// Create a supervisor with a fresh lease and bounded scheduler.
    pub fn new(config: BridgeConfig) -> Result<Arc<Self>, BridgeError> {
        if !is_dedicated_task_space(&config.default_task_space) {
            return Err(BridgeError::ProtocolMessage(
                "invalid default task space".into(),
            ));
        }
        prepare_private_root(&config.work_root)?;
        let instance_lock = acquire_instance_lock(&config.work_root)?;
        let remote_sequence_path = config.work_root.join("remote-sequence-v1.json");
        let highest_remote_sequence = load_remote_sequence(&remote_sequence_path)?;
        let scheduler = Scheduler::new(config.max_parallel_requests)
            .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
        let (cancel_tx, _) = watch::channel(false);
        Ok(Arc::new(Self {
            lease: Mutex::new(LeaseState::new(
                config.generation,
                now_seconds(),
                LeasePolicy::default(),
            )),
            _instance_lock: instance_lock,
            remote_sequence_path,
            config,
            scheduler,
            next_sequence: Mutex::new(0),
            issued_permits: Mutex::new(HashMap::new()),
            consumed_sequences: Mutex::new(HashSet::new()),
            highest_remote_sequence: Mutex::new(highest_remote_sequence),
            active_remote_requests: Mutex::new(HashMap::new()),
            cancel_tx,
        }))
    }

    /// Return current capability metadata.
    pub fn capability(&self) -> BridgeCapability {
        self.config.capability()
    }

    /// Return the hard process parallelism limit for this binding.
    pub fn max_parallel_requests(&self) -> usize {
        self.config.max_parallel_requests
    }

    /// Return the number of executions that still hold supervisor locks.
    pub fn active_execution_count(&self) -> usize {
        self.scheduler.active_count()
    }

    /// Return the binding identity this supervisor was configured to serve.
    pub fn binding_id(&self) -> &str {
        &self.config.binding_id
    }

    /// Validate the startup nonce used only by the local fake-broker adapter.
    pub fn development_broker_nonce_matches(&self, supplied: Option<&str>) -> bool {
        match self.config.broker_startup_nonce.as_deref() {
            Some(expected) => constant_time_text_eq(expected, supplied.unwrap_or_default()),
            None => supplied.is_none(),
        }
    }

    /// Return the currently authorized binding generation.
    pub fn generation(&self) -> Result<u64, BridgeError> {
        self.lease
            .lock()
            .map(|lease| lease.generation)
            .map_err(|_| BridgeError::Unavailable)
    }

    /// Mark the binding revoked and cancel all supervised executions.
    pub fn revoke(&self) {
        if let Ok(mut lease) = self.lease.lock() {
            lease.revoke();
        }
        self.clear_permits();
        self.cancel_tx.send_replace(true);
    }

    /// Request cancellation of the current generation's executions.
    pub fn cancel(&self) {
        self.cancel_tx.send_replace(true);
    }

    /// Re-enable request admission after a transient relay reconnect.
    ///
    /// A revoked or expired lease can only be revived through an explicit
    /// generation activation; reconnecting a socket must never bypass that
    /// state transition.
    pub fn resume_after_reconnect(&self) -> Result<(), BridgeError> {
        let lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
        match lease.admit(now_seconds(), LeasePolicy::default()) {
            ego_browser_bridge_protocol::Admission::Allowed => {}
            ego_browser_bridge_protocol::Admission::RenewalRequired => {
                return Err(BridgeError::LeaseRenewalRequired)
            }
            ego_browser_bridge_protocol::Admission::Expired => {
                return Err(BridgeError::LeaseExpired)
            }
            ego_browser_bridge_protocol::Admission::BindingRevoked => {
                return Err(BridgeError::Revoked)
            }
        }
        drop(lease);
        self.cancel_tx.send_replace(false);
        Ok(())
    }

    /// Reset the cancellation signal after a new explicitly authorized generation.
    pub fn activate_generation(&self, generation: u64) -> Result<(), BridgeError> {
        if generation == 0 {
            return Err(BridgeError::ProtocolMessage("invalid generation".into()));
        }
        let mut lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
        if generation <= lease.generation {
            return Err(BridgeError::ProtocolMessage(
                "generation must increase".into(),
            ));
        }
        *lease = LeaseState::new(generation, now_seconds(), LeasePolicy::default());
        self.clear_permits();
        self.cancel_tx.send_replace(false);
        Ok(())
    }

    /// Issue a one-time permit for a wrapper request.
    pub fn issue_permit(
        &self,
        request: &PermitRequest,
    ) -> Result<([u8; 32], RequestPermit), BridgeError> {
        if request.protocol != PROTOCOL_VERSION || request.message_type != "permit_request" {
            return Err(BridgeError::ProtocolMessage(
                "invalid permit request".into(),
            ));
        }
        if let Some(expected) = self.config.broker_startup_nonce.as_deref() {
            let supplied = request.startup_nonce.as_deref().unwrap_or_default();
            if !constant_time_text_eq(expected, supplied) {
                return Err(BridgeError::ProtocolMessage(
                    "broker startup nonce is invalid".into(),
                ));
            }
        } else if request.startup_nonce.is_some() {
            return Err(BridgeError::ProtocolMessage(
                "broker startup nonce was not configured".into(),
            ));
        }
        if request.script_bytes == 0 || request.script_bytes > MAX_SCRIPT_BYTES {
            return Err(BridgeError::ProtocolMessage("script exceeds limit".into()));
        }
        if request.timeout_ms == 0 || request.timeout_ms > MAX_EXECUTE_TIMEOUT_MS {
            return Err(BridgeError::ProtocolMessage("timeout exceeds limit".into()));
        }
        if request.cwd_label.is_empty()
            || request.cwd_label.len() > 128
            || request.cwd_label.contains("..")
        {
            return Err(BridgeError::ProtocolMessage("invalid cwd label".into()));
        }
        if self.is_cancelled() {
            return Err(BridgeError::Revoked);
        }
        let lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
        match lease.admit(now_seconds(), LeasePolicy::default()) {
            ego_browser_bridge_protocol::Admission::Allowed => {}
            ego_browser_bridge_protocol::Admission::RenewalRequired => {
                return Err(BridgeError::LeaseRenewalRequired)
            }
            ego_browser_bridge_protocol::Admission::Expired => {
                return Err(BridgeError::LeaseExpired)
            }
            ego_browser_bridge_protocol::Admission::BindingRevoked => {
                return Err(BridgeError::Revoked)
            }
        }
        let sequence = self.next_sequence()?;
        let request_id = ego_browser_bridge_protocol::opaque_id();
        let scope = RequestScope::normalized(
            Some(request.concurrency_mode),
            request.task_space_scope.as_deref(),
            request.tab_scope.as_deref(),
        );
        if scope.mode != ConcurrencyMode::Binding
            && scope.task_space.as_deref() != Some(self.config.default_task_space.as_str())
        {
            return Err(BridgeError::ProtocolMessage(
                "task space scope is not dedicated to the tool session".into(),
            ));
        }
        // Keep the permit scope normalized so a malformed/wildcard request cannot widen itself later.
        let permit = RequestPermit {
            binding_id: self.config.binding_id.clone(),
            generation: lease.generation,
            request_id,
            sequence,
            expires_at_unix_ms: now_millis().saturating_add(20_000),
            max_payload_bytes: 16 * 1024 * 1024,
            max_script_bytes: MAX_SCRIPT_BYTES,
            default_task_space: self.config.default_task_space.clone(),
            allowlist_revision: self.config.allowlist_revision,
            learning_bundle_digest: self.config.learning_bundle_digest.clone(),
            concurrency_mode: scope.mode,
            task_space_scope: scope.task_space,
            tab_scope: scope.tab,
        };
        let (key, _) = SessionCipher::random();
        let mut permits = self
            .issued_permits
            .lock()
            .map_err(|_| BridgeError::Unavailable)?;
        permits.insert(
            sequence,
            IssuedPermit {
                permit: permit.clone(),
                key,
            },
        );
        Ok((key, permit))
    }

    pub(super) fn next_sequence(&self) -> Result<u64, BridgeError> {
        let mut next = self
            .next_sequence
            .lock()
            .map_err(|_| BridgeError::Unavailable)?;
        if *next == u64::MAX {
            return Err(BridgeError::ProtocolMessage("sequence exhausted".into()));
        }
        *next += 1;
        Ok(*next)
    }

    pub(super) fn clear_permits(&self) {
        if let Ok(mut permits) = self.issued_permits.lock() {
            permits.clear();
        }
        if let Ok(mut consumed) = self.consumed_sequences.lock() {
            consumed.clear();
        }
    }

    pub(crate) fn reserve_remote_sequence(&self, sequence: u64) -> Result<(), BridgeError> {
        let mut highest = self
            .highest_remote_sequence
            .lock()
            .map_err(|_| BridgeError::Unavailable)?;
        if sequence <= *highest {
            return Err(BridgeError::Replay);
        }
        persist_remote_sequence(&self.remote_sequence_path, sequence)?;
        *highest = sequence;
        Ok(())
    }

    pub(super) fn is_cancelled(&self) -> bool {
        *self.cancel_tx.borrow()
    }
}
