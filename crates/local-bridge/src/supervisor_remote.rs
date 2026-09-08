//! Local bridge supervisor remote internals.

use super::*;

impl BridgeSupervisor {
    /// Validate and prepare a request received from the authenticated outbound relay.
    ///
    /// Unlike the local development adapter, a relay request does not carry a
    /// locally issued permit.  The broker binds the per-request session key in
    /// ``key_wrap``. Sequence reservation and scheduler admission happen before
    /// this method returns, preserving wire order while the returned process
    /// futures are free to complete out of order.
    pub fn prepare_remote_execution(
        self: &Arc<Self>,
        envelope: OuterEnvelope,
        encryption_secret: [u8; 32],
    ) -> Result<RemoteExecution, BridgeError> {
        envelope
            .validate(16 * 1024 * 1024)
            .map_err(BridgeError::Protocol)?;
        envelope
            .validate_key_wrap()
            .map_err(BridgeError::Protocol)?;
        if envelope.message_type != OuterMessageType::Execute
            || envelope.direction != Direction::Request
        {
            return Err(BridgeError::ProtocolMessage(
                "invalid remote execute envelope".into(),
            ));
        }
        if self.is_cancelled() {
            return Err(BridgeError::Revoked);
        }
        if envelope.binding_id != self.config.binding_id {
            return Err(BridgeError::ProtocolMessage(
                "remote envelope binding does not match bridge configuration".into(),
            ));
        }
        {
            let lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
            if envelope.generation != lease.generation || lease.revoked {
                return Err(BridgeError::Revoked);
            }
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
        }
        // Reserve the sequence before doing any decryption or process work so
        // two concurrent relay deliveries cannot execute the same request.
        self.reserve_remote_sequence(envelope.sequence)?;
        let key = unwrap_session_key(
            &envelope.key_wrap,
            &encryption_secret,
            &envelope.binding_id,
            envelope.generation,
            &envelope.request_id,
            envelope.sequence,
        )
        .map_err(BridgeError::Protocol)?;
        let (ciphertext, nonce, tag) = envelope.decoded_payload().map_err(BridgeError::Protocol)?;
        let aad = aad_for_outer(&envelope).map_err(BridgeError::Protocol)?;
        let cipher = SessionCipher::new(&key);
        let plaintext = cipher
            .open(&nonce, &ciphertext, &tag, &aad)
            .map_err(BridgeError::Protocol)?;
        let request: InnerExecuteRequest = match parse_strict_json(&plaintext) {
            Ok(request) => request,
            Err(_) => {
                let response = self.seal_status_response(
                    ExecutionStatus::ProtocolError,
                    envelope,
                    &cipher,
                    0,
                )?;
                return Ok(Box::pin(async move { Ok(response) }));
            }
        };
        let capability = self.capability();
        if request.validate(&capability).is_err()
            || envelope.payload_bytes > 16 * 1024 * 1024
            || request.script.len() > MAX_SCRIPT_BYTES
            || request.default_task_space != self.config.default_task_space
        {
            let response =
                self.seal_status_response(ExecutionStatus::ProtocolError, envelope, &cipher, 0)?;
            return Ok(Box::pin(async move { Ok(response) }));
        }
        let scope = RequestScope::normalized(
            Some(request.concurrency_mode),
            request.task_space_scope.as_deref(),
            request.tab_scope.as_deref(),
        );
        let guard = match self.scheduler.try_acquire(
            envelope.generation,
            envelope.request_id.clone(),
            scope,
        ) {
            Ok(guard) => guard,
            Err(
                ego_browser_bridge_protocol::SchedulerError::Conflict
                | ego_browser_bridge_protocol::SchedulerError::LimitReached,
            ) => {
                let response = self.seal_status_response(
                    ExecutionStatus::ConcurrencyConflict,
                    envelope,
                    &cipher,
                    0,
                )?;
                return Ok(Box::pin(async move { Ok(response) }));
            }
            Err(_) => {
                let response = self.seal_status_response(
                    ExecutionStatus::BridgeUnavailable,
                    envelope,
                    &cipher,
                    0,
                )?;
                return Ok(Box::pin(async move { Ok(response) }));
            }
        };
        if self.is_cancelled() {
            drop(guard);
            let response =
                self.seal_status_response(ExecutionStatus::BindingRevoked, envelope, &cipher, 0)?;
            return Ok(Box::pin(async move { Ok(response) }));
        }
        let (request_cancel_tx, request_cancel_rx) = watch::channel(false);
        let request_key = RemoteRequestKey::from_envelope(&envelope);
        {
            let mut active = self
                .active_remote_requests
                .lock()
                .map_err(|_| BridgeError::Unavailable)?;
            if active.contains_key(&request_key) {
                return Err(BridgeError::Replay);
            }
            active.insert(
                request_key,
                ActiveRemoteRequest {
                    cancel_tx: request_cancel_tx,
                    session_key: key,
                },
            );
        }
        let supervisor = Arc::clone(self);
        Ok(Box::pin(async move {
            let started = Instant::now();
            let response = supervisor
                .run_process(
                    &request,
                    &envelope.request_id,
                    envelope.sequence,
                    request_cancel_rx,
                )
                .await;
            drop(guard);
            let (status, exit_code, stdout, stderr, artifacts) = response;
            let inner = InnerExecuteResponse {
                protocol: "ego-browser-bridge-v1-inner".into(),
                message_type: InnerMessageType::ExecuteResult,
                request_id: envelope.request_id.clone(),
                sequence: envelope.sequence,
                status,
                exit_code,
                stdout,
                stderr,
                artifacts,
                duration_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            };
            supervisor.seal_response(inner, envelope, &cipher)
        }))
    }

    /// Update the local lease snapshot after a control-plane activation or
    /// renewal.  Timestamps are Unix seconds, matching the shared protocol's
    /// monotonic lease representation.
    pub fn update_lease(
        &self,
        generation: u64,
        lease_until: u64,
        absolute_ttl_until: u64,
        healthy: bool,
    ) -> Result<(), BridgeError> {
        if generation == 0 || lease_until == 0 || absolute_ttl_until < lease_until {
            return Err(BridgeError::ProtocolMessage(
                "invalid lease metadata".into(),
            ));
        }
        let mut lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
        if generation != lease.generation {
            return Err(BridgeError::Revoked);
        }
        lease.lease_until = lease_until;
        lease.absolute_ttl_until = absolute_ttl_until;
        lease.health = if healthy {
            ego_browser_bridge_protocol::LeaseHealth::Healthy
        } else {
            ego_browser_bridge_protocol::LeaseHealth::RenewalGrace
        };
        if healthy {
            lease.grace_until = None;
        }
        Ok(())
    }

    /// Mark a failed renewal while preserving the first grace deadline.
    pub fn mark_renewal_failed(&self, failure_grace_seconds: u64) -> Result<(), BridgeError> {
        if failure_grace_seconds == 0 {
            return Err(BridgeError::ProtocolMessage(
                "invalid renewal failure grace".into(),
            ));
        }
        let mut lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
        if lease.revoked {
            return Err(BridgeError::Revoked);
        }
        let now = now_seconds();
        if now >= lease.absolute_ttl_until {
            lease.revoke();
            self.cancel_tx.send_replace(true);
            return Err(BridgeError::LeaseExpired);
        }
        if lease.health != ego_browser_bridge_protocol::LeaseHealth::RenewalGrace {
            lease.health = ego_browser_bridge_protocol::LeaseHealth::RenewalGrace;
            lease.grace_until = Some(now.saturating_add(failure_grace_seconds));
        }
        if lease.grace_until.is_some_and(|deadline| now >= deadline) {
            lease.revoke();
            self.cancel_tx.send_replace(true);
            return Err(BridgeError::LeaseExpired);
        }
        Ok(())
    }

    /// Expose a cancellation receiver for the relay loop.
    pub fn cancellation_receiver(&self) -> watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }

    /// Authenticate and cancel exactly one active relay request.
    pub fn cancel_remote_request(&self, envelope: &OuterEnvelope) -> Result<bool, BridgeError> {
        envelope
            .validate(16 * 1024 * 1024)
            .map_err(BridgeError::Protocol)?;
        if envelope.message_type != OuterMessageType::Cancel
            || envelope.direction != Direction::Request
            || !envelope.key_wrap.is_empty()
            || envelope.binding_id != self.config.binding_id
        {
            return Err(BridgeError::ProtocolMessage(
                "invalid remote cancel envelope".into(),
            ));
        }
        {
            let lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
            if envelope.generation != lease.generation || lease.revoked {
                return Err(BridgeError::Revoked);
            }
        }
        let key = RemoteRequestKey::from_envelope(envelope);
        let active = self
            .active_remote_requests
            .lock()
            .map_err(|_| BridgeError::Unavailable)?
            .get(&key)
            .cloned();
        let Some(active) = active else {
            // A cancellation can cross an already sealed terminal response. It
            // has no executable target and must not tear down unrelated work.
            return Ok(false);
        };
        let (ciphertext, nonce, tag) = envelope.decoded_payload().map_err(BridgeError::Protocol)?;
        let aad = aad_for_outer(envelope).map_err(BridgeError::Protocol)?;
        let plaintext = SessionCipher::new(&active.session_key)
            .open(&nonce, &ciphertext, &tag, &aad)
            .map_err(BridgeError::Protocol)?;
        let cancel: InnerCancelRequest = parse_strict_json(&plaintext)
            .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
        cancel.validate().map_err(BridgeError::Protocol)?;
        if cancel.request_id != envelope.request_id || cancel.sequence != envelope.sequence {
            return Err(BridgeError::ProtocolMessage(
                "cancel inner identity mismatch".into(),
            ));
        }
        active.cancel_tx.send_replace(true);
        Ok(true)
    }

    /// Forget request-level cancellation material after its response is sent.
    pub fn finish_remote_request(&self, envelope: &OuterEnvelope) {
        let key = RemoteRequestKey::from_envelope(envelope);
        if let Ok(mut active) = self.active_remote_requests.lock() {
            if let Some(mut removed) = active.remove(&key) {
                removed.session_key.fill(0);
            }
        }
    }

    /// Clear all request-level keys once generation-wide cancellation is reaped.
    pub fn clear_remote_requests(&self) {
        if let Ok(mut active) = self.active_remote_requests.lock() {
            for request in active.values_mut() {
                request.session_key.fill(0);
            }
            active.clear();
        }
    }
}
