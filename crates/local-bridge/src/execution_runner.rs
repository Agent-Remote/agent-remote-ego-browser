//! Local bridge execution runner internals.

use super::*;

pub(crate) fn execution_metric_events(
    status: ExecutionStatus,
    duration_ms: u64,
    request_bytes: usize,
    response_bytes: usize,
    artifacts: &[ego_browser_bridge_protocol::ArtifactDescriptor],
) -> Vec<String> {
    let status = execution_status_label(status);
    let mut events = vec![
        serde_json::json!({
            "event": "metric",
            "metric": "ego_browser_execute_total",
            "status": status,
            "unit": "executions",
            "value": 1,
        })
        .to_string(),
        serde_json::json!({
            "event": "metric",
            "metric": "ego_browser_execute_duration_seconds",
            "status": status,
            "unit": "seconds",
            "value": duration_ms as f64 / 1000.0,
        })
        .to_string(),
        serde_json::json!({
            "direction": "request",
            "event": "metric",
            "metric": "ego_browser_bytes_total",
            "status": status,
            "unit": "bytes",
            "value": request_bytes,
        })
        .to_string(),
        serde_json::json!({
            "direction": "response",
            "event": "metric",
            "metric": "ego_browser_bytes_total",
            "status": status,
            "unit": "bytes",
            "value": response_bytes,
        })
        .to_string(),
    ];
    let mut artifact_counts = BTreeMap::new();
    for artifact in artifacts {
        let media_type = match artifact.media_type.as_str() {
            "image/jpeg" => "image/jpeg",
            "image/png" => "image/png",
            _ => "other",
        };
        *artifact_counts.entry(media_type).or_insert(0_u64) += 1;
    }
    for (media_type, count) in artifact_counts {
        events.push(
            serde_json::json!({
                "event": "metric",
                "media_type": media_type,
                "metric": "ego_browser_artifacts_total",
                "status": status,
                "unit": "artifacts",
                "value": count,
            })
            .to_string(),
        );
    }
    events
}

fn execution_status_label(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::ScriptError => "script_error",
        ExecutionStatus::Timeout => "timeout",
        ExecutionStatus::Cancelled => "cancelled",
        ExecutionStatus::BridgeUnavailable => "bridge_unavailable",
        ExecutionStatus::EgoRuntimeUnavailable => "ego_runtime_unavailable",
        ExecutionStatus::LeaseExpired => "lease_expired",
        ExecutionStatus::BindingRevoked => "binding_revoked",
        ExecutionStatus::ProtocolError => "protocol_error",
        ExecutionStatus::ArtifactError => "artifact_error",
        ExecutionStatus::ConcurrencyConflict => "concurrency_conflict",
        ExecutionStatus::LeaseRenewalRequired => "lease_renewal_required",
        ExecutionStatus::UnknownResult => "unknown_result",
    }
}

/// Run the independent process that owns one local runtime execution.
///
/// The Bridge writes a bounded length-prefixed script and deliberately keeps
/// stdin open. EOF means the Bridge died or cancelled the request, at which
/// point this process terminates and reaps the runtime's entire process group.
pub async fn run_execution_supervisor() -> Result<i32, BridgeError> {
    if env::args().len() != 2 {
        return Err(BridgeError::ProtocolMessage(
            "invalid execution supervisor arguments".into(),
        ));
    }
    let executable = env::var_os("EGO_BROWSER_SUPERVISED_EXECUTABLE")
        .map(PathBuf::from)
        .ok_or_else(|| BridgeError::ProtocolMessage("supervised executable is missing".into()))?;
    let artifact_dir = env::var_os("EGO_BROWSER_ARTIFACT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| BridgeError::ProtocolMessage("artifact directory is missing".into()))?;
    if !executable.is_absolute() || !artifact_dir.is_absolute() {
        return Err(BridgeError::ProtocolMessage(
            "execution supervisor paths must be absolute".into(),
        ));
    }

    let mut control = tokio::io::stdin();
    let mut length_bytes = [0_u8; 8];
    control
        .read_exact(&mut length_bytes)
        .await
        .map_err(BridgeError::Io)?;
    let length = usize::try_from(u64::from_be_bytes(length_bytes))
        .map_err(|_| BridgeError::ProtocolMessage("supervised script length is invalid".into()))?;
    if length == 0 || length > MAX_SCRIPT_BYTES.saturating_add(64 * 1024) {
        return Err(BridgeError::ProtocolMessage(
            "supervised script exceeds limit".into(),
        ));
    }
    let mut script = vec![0_u8; length];
    control
        .read_exact(&mut script)
        .await
        .map_err(BridgeError::Io)?;

    let mut command = Command::new(executable);
    command
        .arg("nodejs")
        .env_clear()
        .env("EGO_BROWSER_ARTIFACT_DIR", &artifact_dir)
        // The official captureScreenshot() default uses os.tmpdir().
        .env("TMPDIR", &artifact_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(task_space) = env::var_os("EGO_BROWSER_DEFAULT_TASK_SPACE") {
        command.env("EGO_BROWSER_DEFAULT_TASK_SPACE", task_space);
    }
    if let Some(root) = env::var_os("EGO_BROWSER_SUPERVISED_AGENT_WORKSPACE") {
        command.env("EGO_BROWSER_AGENT_WORKSPACE", root);
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
    let mut runtime = command.spawn().map_err(BridgeError::Io)?;
    let mut runtime_stdin = match runtime.stdin.take() {
        Some(stdin) => stdin,
        None => {
            terminate_child(&mut runtime).await;
            return Err(BridgeError::ProtocolMessage(
                "runtime stdin is unavailable".into(),
            ));
        }
    };
    if let Err(error) = runtime_stdin.write_all(&script).await {
        terminate_child(&mut runtime).await;
        return Err(BridgeError::Io(error));
    }
    if let Err(error) = runtime_stdin.shutdown().await {
        terminate_child(&mut runtime).await;
        return Err(BridgeError::Io(error));
    }
    drop(runtime_stdin);
    script.fill(0);

    let mut peer_probe = [0_u8; 1];
    tokio::select! {
        status = runtime.wait() => {
            match status {
                Ok(status) => Ok(status.code().unwrap_or(1)),
                Err(error) => {
                    terminate_child(&mut runtime).await;
                    Err(BridgeError::Io(error))
                }
            }
        }
        peer = control.read(&mut peer_probe) => {
            let _ = peer;
            terminate_child(&mut runtime).await;
            Ok(125)
        }
    }
}

pub(super) fn constant_time_text_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
