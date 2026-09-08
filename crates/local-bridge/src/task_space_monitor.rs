//! Local bridge task space monitor internals.

use super::*;

pub(super) fn task_space_monitor_script(task_space: &str) -> Result<Vec<u8>, BridgeError> {
    if !is_dedicated_task_space(task_space) {
        return Err(BridgeError::ProtocolMessage(
            "invalid Task Space monitor target".into(),
        ));
    }
    let task_space = serde_json::to_string(task_space)
        .map_err(|_| BridgeError::ProtocolMessage("invalid Task Space monitor target".into()))?;
    Ok(format!(
        r#"// agent-remote-task-space-ownership-monitor-v1
const agentRemoteTaskSpace = {task_space};
let agentControlObserved = false;
for (;;) {{
  const spaces = await listTaskSpaces();
  const matches = spaces.filter(space =>
    space && (space.name === agentRemoteTaskSpace || space.taskId === agentRemoteTaskSpace)
  );
  if (matches.length > 1) process.exit(74);
  if (matches.length === 1) {{
    const ownership = matches[0].ownership;
    if (ownership === 'agent') {{
      agentControlObserved = true;
    }} else if (
      agentControlObserved &&
      (ownership === 'agentDelegatedToUser' || ownership === 'user')
    ) {{
      process.exit({TASK_SPACE_MONITOR_TAKEOVER_EXIT_CODE});
    }} else if (
      ownership !== 'agentDelegatedToUser' && ownership !== 'user'
    ) {{
      process.exit(74);
    }}
  }}
  await new Promise(resolve => setTimeout(resolve, {TASK_SPACE_MONITOR_POLL_INTERVAL_MS}));
}}
"#
    )
    .into_bytes())
}

pub(super) async fn run_task_space_monitor(
    executable: PathBuf,
    work_root: PathBuf,
    task_space: String,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> TaskSpaceMonitorOutcome {
    if !executable.is_absolute() || !work_root.is_absolute() {
        return TaskSpaceMonitorOutcome::Unavailable;
    }
    let script = match task_space_monitor_script(&task_space) {
        Ok(script) => script,
        Err(_) => return TaskSpaceMonitorOutcome::Unavailable,
    };
    let supervisor_executable = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return TaskSpaceMonitorOutcome::Unavailable,
    };
    let mut command = tokio::process::Command::new(supervisor_executable);
    command
        .arg("--execution-supervisor")
        .env_clear()
        .env("EGO_BROWSER_SUPERVISED_EXECUTABLE", executable)
        .env("EGO_BROWSER_ARTIFACT_DIR", &work_root)
        .env("EGO_BROWSER_DEFAULT_TASK_SPACE", &task_space)
        .current_dir(work_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
        Ok(child) => child,
        Err(_) => return TaskSpaceMonitorOutcome::Unavailable,
    };
    let mut control = match child.stdin.take() {
        Some(control) => Some(control),
        None => {
            terminate_task_space_monitor(&mut child, None).await;
            return TaskSpaceMonitorOutcome::Unavailable;
        }
    };
    let length = u64::try_from(script.len())
        .unwrap_or(u64::MAX)
        .to_be_bytes();
    let written = if let Some(stdin) = control.as_mut() {
        stdin.write_all(&length).await.is_ok() && stdin.write_all(&script).await.is_ok()
    } else {
        false
    };
    if !written {
        terminate_task_space_monitor(&mut child, control.take()).await;
        return TaskSpaceMonitorOutcome::Unavailable;
    }

    loop {
        tokio::select! {
            status = child.wait() => {
                drop(control.take());
                return match status.ok().and_then(|status| status.code()) {
                    Some(TASK_SPACE_MONITOR_TAKEOVER_EXIT_CODE) => {
                        TaskSpaceMonitorOutcome::TakenOver
                    }
                    _ => TaskSpaceMonitorOutcome::Unavailable,
                };
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    terminate_task_space_monitor(&mut child, control.take()).await;
                    return TaskSpaceMonitorOutcome::Stopped;
                }
            }
        }
    }
}

async fn terminate_task_space_monitor(
    child: &mut Child,
    control: Option<tokio::process::ChildStdin>,
) {
    drop(control);
    if tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .is_ok()
    {
        return;
    }
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(super) async fn fail_closed_task_space_monitor<Pause, PauseFuture>(
    outcome: TaskSpaceMonitorOutcome,
    supervisor: &BridgeSupervisor,
    pause_binding: Pause,
) -> BridgeError
where
    Pause: FnOnce(&'static str) -> PauseFuture,
    PauseFuture: Future<Output = ()>,
{
    let (reason, message) = match outcome {
        TaskSpaceMonitorOutcome::TakenOver => (
            "task_space_takeover",
            "Task Space control was taken over; explicit binding resume is required",
        ),
        TaskSpaceMonitorOutcome::Stopped | TaskSpaceMonitorOutcome::Unavailable => (
            "task_space_monitor_unavailable",
            "Task Space ownership monitor is unavailable; explicit binding resume is required",
        ),
    };
    supervisor.revoke();
    let deadline = tokio::time::Instant::now() + TASK_SPACE_EXECUTION_SHUTDOWN_TIMEOUT;
    while supervisor.active_execution_count() != 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pause_binding(reason).await;
    BridgeError::ProtocolMessage(message.into())
}

pub(super) async fn pause_binding_after_task_space_event(
    api: DeviceApiClient,
    binding_id: String,
    generation: u64,
    reason: &'static str,
) {
    match tokio::time::timeout(
        TASK_SPACE_MONITOR_PAUSE_TIMEOUT,
        api.pause_with_reason(&binding_id, generation, reason),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            eprintln!("ego-browser-bridge could not confirm binding pause after Task Space control change");
        }
        Err(_) => {
            eprintln!("ego-browser-bridge binding pause timed out after Task Space control change");
        }
    }
}

pub(super) async fn stop_task_space_monitor(
    stop: tokio::sync::watch::Sender<bool>,
    mut task: tokio::task::JoinHandle<TaskSpaceMonitorOutcome>,
) {
    stop.send_replace(true);
    if tokio::time::timeout(Duration::from_secs(4), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}
