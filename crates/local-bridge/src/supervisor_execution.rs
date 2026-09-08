//! Local bridge supervisor execution internals.

use super::*;

impl BridgeSupervisor {
    /// Execute an authenticated request and produce a response envelope.
    pub async fn execute(
        self: &Arc<Self>,
        envelope: OuterEnvelope,
        key: [u8; 32],
    ) -> Result<OuterEnvelope, BridgeError> {
        envelope
            .validate(16 * 1024 * 1024)
            .map_err(BridgeError::Protocol)?;
        if envelope.message_type != OuterMessageType::Execute
            || envelope.direction != Direction::Request
        {
            return Err(BridgeError::ProtocolMessage(
                "invalid execute envelope".into(),
            ));
        }
        if self.is_cancelled() {
            return Err(BridgeError::Revoked);
        }
        {
            let lease = self.lease.lock().map_err(|_| BridgeError::Unavailable)?;
            if envelope.generation != lease.generation || lease.revoked {
                return Err(BridgeError::Revoked);
            }
        }
        // Consume the permit only after every unencrypted identity check succeeds. This
        // makes retries/replays fail closed while a bad session key cannot burn a permit.
        let issued = {
            let mut permits = self
                .issued_permits
                .lock()
                .map_err(|_| BridgeError::Unavailable)?;
            let issued = permits
                .get(&envelope.sequence)
                .ok_or_else(|| {
                    if self
                        .consumed_sequences
                        .lock()
                        .map(|values| values.contains(&envelope.sequence))
                        .unwrap_or(false)
                    {
                        BridgeError::Replay
                    } else {
                        BridgeError::Revoked
                    }
                })?
                .clone();
            if issued.permit.binding_id != envelope.binding_id
                || issued.permit.generation != envelope.generation
                || issued.permit.request_id != envelope.request_id
                || issued.permit.sequence != envelope.sequence
            {
                return Err(BridgeError::ProtocolMessage(
                    "permit and request identity mismatch".into(),
                ));
            }
            if issued.key != key {
                return Err(BridgeError::ProtocolMessage("invalid session key".into()));
            }
            if envelope.payload_bytes > issued.permit.max_payload_bytes {
                return Err(BridgeError::Protocol(ProtocolError::FrameTooLarge));
            }
            if issued.permit.expires_at_unix_ms <= now_millis() {
                permits.remove(&envelope.sequence);
                return Err(BridgeError::LeaseExpired);
            }
            permits.remove(&envelope.sequence);
            issued
        };
        if self.is_cancelled() {
            return Err(BridgeError::Revoked);
        }
        if let Ok(mut consumed) = self.consumed_sequences.lock() {
            consumed.insert(envelope.sequence);
        }
        let (ciphertext, nonce, tag) = envelope.decoded_payload().map_err(BridgeError::Protocol)?;
        let aad = aad_for_outer(&envelope).map_err(BridgeError::Protocol)?;
        let cipher = SessionCipher::new(&key);
        let plaintext = cipher
            .open(&nonce, &ciphertext, &tag, &aad)
            .map_err(BridgeError::Protocol)?;
        let request: InnerExecuteRequest = parse_strict_json(&plaintext)
            .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
        request
            .validate(&self.capability())
            .map_err(BridgeError::Protocol)?;
        if request.default_task_space != self.config.default_task_space {
            return Err(BridgeError::ProtocolMessage(
                "request Task Space does not match the binding".into(),
            ));
        }
        issued
            .permit
            .validate(&self.capability(), now_millis(), request.script.len())
            .map_err(BridgeError::Protocol)?;
        if request.script.len() > MAX_SCRIPT_BYTES
            || request.script.len() > issued.permit.max_script_bytes
        {
            return Err(BridgeError::ProtocolMessage("script exceeds limit".into()));
        }
        let scope = RequestScope::normalized(
            Some(request.concurrency_mode),
            request.task_space_scope.as_deref(),
            request.tab_scope.as_deref(),
        );
        if request.concurrency_mode != issued.permit.concurrency_mode
            || scope.task_space.as_deref() != issued.permit.task_space_scope.as_deref()
            || scope.tab.as_deref() != issued.permit.tab_scope.as_deref()
        {
            return Err(BridgeError::ProtocolMessage(
                "request scope does not match permit".into(),
            ));
        }
        let guard = self
            .scheduler
            .try_acquire(envelope.generation, envelope.request_id.clone(), scope)
            .map_err(|error| match error {
                ego_browser_bridge_protocol::SchedulerError::Conflict
                | ego_browser_bridge_protocol::SchedulerError::LimitReached => {
                    BridgeError::Concurrency
                }
                _ => BridgeError::Unavailable,
            })?;
        if let Ok(mut consumed) = self.consumed_sequences.lock() {
            consumed.insert(envelope.sequence);
        }
        let (_request_cancel_tx, request_cancel_rx) = watch::channel(false);
        let started = Instant::now();
        let response = self
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
        self.seal_response(inner, envelope, &cipher)
    }

    pub(crate) async fn run_process(
        &self,
        request: &InnerExecuteRequest,
        _request_id: &str,
        sequence: u64,
        mut request_cancellation: watch::Receiver<bool>,
    ) -> (
        ExecutionStatus,
        Option<i32>,
        String,
        String,
        Vec<ego_browser_bridge_protocol::ArtifactDescriptor>,
    ) {
        let mut cancellation = self.cancel_tx.subscribe();
        if *cancellation.borrow() {
            return (
                ExecutionStatus::BindingRevoked,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        if *request_cancellation.borrow() {
            return (
                ExecutionStatus::Cancelled,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        let temp = match tempfile::Builder::new()
            .prefix("ego-browser-request-")
            .tempdir_in(&self.config.work_root)
        {
            Ok(value) => value,
            Err(_) => {
                return (
                    ExecutionStatus::BridgeUnavailable,
                    None,
                    String::new(),
                    String::new(),
                    Vec::new(),
                )
            }
        };
        let artifact_dir = temp.path().join("artifacts");
        if tokio::fs::create_dir(&artifact_dir).await.is_err()
            || set_private_permissions(&artifact_dir).is_err()
        {
            return (
                ExecutionStatus::ArtifactError,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        let file_guard = match self.config.allowlist.clone() {
            Some(allowlist) => match FileGuardHandle::start(
                &self.config.work_root,
                temp.path(),
                sequence,
                allowlist,
            )
            .await
            {
                Ok(handle) => Some(handle),
                Err(_) => {
                    return (
                        ExecutionStatus::ArtifactError,
                        None,
                        String::new(),
                        String::new(),
                        Vec::new(),
                    )
                }
            },
            None => None,
        };
        let guarded_script = match helper_guard_script(
            file_guard.as_ref().map(|guard| guard.socket_path.as_path()),
            &request.default_task_space,
            &request.script,
        ) {
            Ok(script) => script,
            Err(_) => {
                if let Some(guard) = file_guard {
                    guard.stop().await;
                }
                return (
                    ExecutionStatus::ProtocolError,
                    None,
                    String::new(),
                    String::new(),
                    Vec::new(),
                );
            }
        };
        // Logic-test uses a directly launched fake. Every deployable profile
        // routes execution through the independent peer-loss supervisor.
        let independently_supervised = self.config.release_profile != ReleaseProfile::LogicTest;
        let command_executable = if independently_supervised {
            match env::current_exe() {
                Ok(value) => value,
                Err(_) => {
                    if let Some(guard) = file_guard {
                        guard.stop().await;
                    }
                    return (
                        ExecutionStatus::BridgeUnavailable,
                        None,
                        String::new(),
                        String::new(),
                        Vec::new(),
                    );
                }
            }
        } else {
            self.config.executable.clone()
        };
        let mut command = Command::new(command_executable);
        command.env_clear();
        if independently_supervised {
            command
                .arg("--execution-supervisor")
                .env("EGO_BROWSER_SUPERVISED_EXECUTABLE", &self.config.executable)
                .env("EGO_BROWSER_ARTIFACT_DIR", &artifact_dir)
                .env(
                    "EGO_BROWSER_DEFAULT_TASK_SPACE",
                    &request.default_task_space,
                );
        } else {
            command
                .arg("nodejs")
                .env("EGO_BROWSER_ARTIFACT_DIR", &artifact_dir)
                .env("TMPDIR", &artifact_dir)
                .env(
                    "EGO_BROWSER_DEFAULT_TASK_SPACE",
                    &request.default_task_space,
                );
        }
        command
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(root) = &self.config.learning_bundle_root {
            command.env(
                if independently_supervised {
                    "EGO_BROWSER_SUPERVISED_AGENT_WORKSPACE"
                } else {
                    "EGO_BROWSER_AGENT_WORKSPACE"
                },
                root,
            );
        }
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = match command.spawn() {
            Ok(value) => value,
            Err(_) => {
                if let Some(guard) = file_guard {
                    guard.stop().await;
                }
                return (
                    ExecutionStatus::EgoRuntimeUnavailable,
                    None,
                    String::new(),
                    String::new(),
                    Vec::new(),
                );
            }
        };
        if *cancellation.borrow() {
            terminate_child(&mut child).await;
            return (
                ExecutionStatus::BindingRevoked,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        if *request_cancellation.borrow() {
            terminate_child(&mut child).await;
            return (
                ExecutionStatus::Cancelled,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        let mut supervisor_stdin = child.stdin.take();
        let script = guarded_script.into_bytes();
        let script_length = u64::try_from(script.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes();
        let script_written = if let Some(stdin) = supervisor_stdin.as_mut() {
            (!independently_supervised || stdin.write_all(&script_length).await.is_ok())
                && stdin.write_all(&script).await.is_ok()
                && (independently_supervised || stdin.shutdown().await.is_ok())
        } else {
            false
        };
        if !independently_supervised {
            drop(supervisor_stdin.take());
        }
        if !script_written {
            terminate_execution(&mut child, &mut supervisor_stdin, independently_supervised).await;
            if let Some(guard) = file_guard {
                guard.stop().await;
            }
            return (
                ExecutionStatus::BridgeUnavailable,
                None,
                String::new(),
                String::new(),
                Vec::new(),
            );
        }
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let stdout_task = child.stdout.take().map(|stream| {
            let sender = event_tx.clone();
            tokio::spawn(read_bounded(stream, MAX_STDOUT_BYTES, sender))
        });
        let stderr_task = child.stderr.take().map(|stream| {
            let sender = event_tx.clone();
            tokio::spawn(read_bounded(stream, MAX_STDERR_BYTES, sender))
        });
        drop(event_tx);
        let timeout = Duration::from_millis(request.timeout_ms.min(MAX_EXECUTE_TIMEOUT_MS));
        let deadline = tokio::time::Instant::now() + timeout;
        let mut status = None;
        let mut child_exited = false;
        let mut overflow_channel_open = true;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    child_exited = true;
                    break;
                }
                Ok(None) => {}
                Err(_) => {
                    terminate_execution(
                        &mut child,
                        &mut supervisor_stdin,
                        independently_supervised,
                    )
                    .await;
                    status = Some(ExecutionStatus::BridgeUnavailable);
                    break;
                }
            }
            tokio::select! {
                event = event_rx.recv(), if overflow_channel_open => {
                    if let Some(event) = event {
                        terminate_execution(
                            &mut child,
                            &mut supervisor_stdin,
                            independently_supervised,
                        )
                        .await;
                        status = Some(match event {
                            ReaderEvent::Overflow => ExecutionStatus::ProtocolError,
                            ReaderEvent::Failed => ExecutionStatus::BridgeUnavailable,
                        });
                        break;
                    }
                    overflow_channel_open = false;
                }
                changed = cancellation.changed() => {
                    if changed.is_ok() && *cancellation.borrow() {
                        terminate_execution(
                            &mut child,
                            &mut supervisor_stdin,
                            independently_supervised,
                        )
                        .await;
                        status = Some(ExecutionStatus::BindingRevoked);
                        break;
                    }
                    if changed.is_err() {
                        terminate_execution(
                            &mut child,
                            &mut supervisor_stdin,
                            independently_supervised,
                        )
                        .await;
                        status = Some(ExecutionStatus::Cancelled);
                        break;
                    }
                }
                changed = request_cancellation.changed() => {
                    if changed.is_err() || *request_cancellation.borrow() {
                        terminate_execution(
                            &mut child,
                            &mut supervisor_stdin,
                            independently_supervised,
                        )
                        .await;
                        status = Some(ExecutionStatus::Cancelled);
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    terminate_execution(
                        &mut child,
                        &mut supervisor_stdin,
                        independently_supervised,
                    )
                    .await;
                    status = Some(ExecutionStatus::Timeout);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        if !child_exited && status.is_none() {
            let _ = child.wait().await;
        }
        drop(supervisor_stdin);
        let stdout_capture = join_capture(stdout_task).await;
        let stderr_capture = join_capture(stderr_task).await;
        if let Some(guard) = file_guard {
            guard.stop().await;
        }
        // A cancellation can race with a naturally exiting child.  Re-check the
        // watch value after the process has been reaped so revocation wins over
        // an otherwise successful exit.
        if status.is_none() && *cancellation.borrow() {
            status = Some(ExecutionStatus::BindingRevoked);
        } else if status.is_none() && *request_cancellation.borrow() {
            status = Some(ExecutionStatus::Cancelled);
        }
        if status.is_none()
            && (stdout_capture.exceeded
                || stderr_capture.exceeded
                || stdout_capture.failed
                || stderr_capture.failed)
        {
            status = Some(if stdout_capture.failed || stderr_capture.failed {
                ExecutionStatus::BridgeUnavailable
            } else {
                ExecutionStatus::ProtocolError
            });
        }
        let stdout = String::from_utf8_lossy(&stdout_capture.bytes).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_capture.bytes).into_owned();
        if let Some(status) = status {
            return (status, None, stdout, stderr, Vec::new());
        }
        let exit_code = child
            .try_wait()
            .ok()
            .flatten()
            .and_then(|value| value.code());
        let artifacts = match collect_artifacts(
            &artifact_dir,
            ArtifactLimits {
                max_bytes: MAX_ARTIFACT_BYTES,
                max_pixels: MAX_ARTIFACT_PIXELS,
                max_count: 32,
                max_total_bytes: MAX_ARTIFACT_BYTES,
            },
        ) {
            Ok(values) => values.into_iter().map(|value| value.descriptor).collect(),
            Err(_) => {
                return (
                    ExecutionStatus::ArtifactError,
                    exit_code,
                    stdout,
                    stderr,
                    Vec::new(),
                )
            }
        };
        let status = if exit_code == Some(0) {
            ExecutionStatus::Completed
        } else {
            ExecutionStatus::ScriptError
        };
        (status, exit_code, stdout, stderr, artifacts)
    }

    pub(super) fn seal_response(
        &self,
        inner: InnerExecuteResponse,
        request: OuterEnvelope,
        cipher: &SessionCipher,
    ) -> Result<OuterEnvelope, BridgeError> {
        let request_payload_bytes = request.payload_bytes;
        let plaintext = canonical_json(&inner)
            .map_err(|error| BridgeError::ProtocolMessage(error.to_string()))?;
        let mut envelope = OuterEnvelope {
            protocol: PROTOCOL_VERSION.into(),
            channel: "ego_browser_bridge".into(),
            relay_binding_kind: "ego_browser".into(),
            message_type: OuterMessageType::ExecuteResult,
            request_id: request.request_id,
            binding_id: request.binding_id,
            generation: request.generation,
            sequence: request.sequence,
            direction: Direction::Response,
            payload_bytes: plaintext.len(),
            nonce: String::new(),
            ciphertext: String::new(),
            auth_tag: String::new(),
            key_wrap: String::new(),
        };
        let aad = aad_for_outer(&envelope).map_err(BridgeError::Protocol)?;
        let (nonce, ciphertext, tag) = cipher
            .seal(&plaintext, &aad)
            .map_err(BridgeError::Protocol)?;
        envelope.payload_bytes = ciphertext.len();
        envelope.nonce = encode_b64url(&nonce);
        envelope.ciphertext = encode_b64url(&ciphertext);
        envelope.auth_tag = encode_b64url(&tag);
        for event in execution_metric_events(
            inner.status,
            inner.duration_ms,
            request_payload_bytes,
            envelope.payload_bytes,
            &inner.artifacts,
        ) {
            eprintln!("{event}");
        }
        Ok(envelope)
    }

    pub(super) fn seal_status_response(
        &self,
        status: ExecutionStatus,
        request: OuterEnvelope,
        cipher: &SessionCipher,
        duration_ms: u64,
    ) -> Result<OuterEnvelope, BridgeError> {
        let inner = InnerExecuteResponse {
            protocol: "ego-browser-bridge-v1-inner".into(),
            message_type: InnerMessageType::ExecuteResult,
            request_id: request.request_id.clone(),
            sequence: request.sequence,
            status,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            artifacts: Vec::new(),
            duration_ms,
        };
        self.seal_response(inner, request, cipher)
    }
}
