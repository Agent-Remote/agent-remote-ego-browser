//! Local bridge file guard internals.

use super::*;

const MAX_FILE_GUARD_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGuardRequest {
    operation: String,
    path: String,
    token: Option<String>,
}

#[derive(Serialize)]
struct FileGuardResponse {
    ok: bool,
    path: Option<String>,
    token: Option<String>,
    error: Option<&'static str>,
}

#[derive(Default)]
struct FileGuardBudget {
    total_bytes: u64,
    file_count: usize,
}

struct PreparedDownload {
    staging_path: PathBuf,
    destination: ValidatedOutputPath,
}

#[derive(Default)]
struct FileGuardState {
    budget: FileGuardBudget,
    downloads: HashMap<String, PreparedDownload>,
}

pub(crate) struct FileGuardHandle {
    pub(crate) socket_path: PathBuf,
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl FileGuardHandle {
    pub(crate) async fn start(
        socket_root: &Path,
        request_root: &Path,
        sequence: u64,
        allowlist: Allowlist,
    ) -> Result<Self, BridgeError> {
        let staging_root = request_root.join("helper-files");
        tokio::fs::create_dir(&staging_root)
            .await
            .map_err(BridgeError::Io)?;
        set_private_permissions(&staging_root).map_err(BridgeError::Io)?;
        let socket_path = socket_root.join(format!("guard-{}-{sequence}.sock", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            if socket_path.as_os_str().as_bytes().len() > 96 {
                return Err(BridgeError::ProtocolMessage(
                    "helper guard socket path is too long".into(),
                ));
            }
        }
        let listener = UnixListener::bind(&socket_path).map_err(BridgeError::Io)?;
        set_private_permissions(&socket_path).map_err(BridgeError::Io)?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_file_guard(listener, allowlist, staging_root, stop_rx));
        Ok(Self {
            socket_path,
            stop_tx,
            task,
        })
    }

    pub(crate) async fn stop(self) {
        self.stop_tx.send_replace(true);
        let _ = self.task.await;
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn run_file_guard(
    listener: UnixListener,
    allowlist: Allowlist,
    staging_root: PathBuf,
    mut stop_rx: watch::Receiver<bool>,
) {
    let state = Arc::new(Mutex::new(FileGuardState::default()));
    loop {
        let stream = tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(_) => break,
            }
        };
        let result = tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
                continue;
            }
            value = handle_file_guard_connection(
                stream,
                allowlist.clone(),
                staging_root.clone(),
                Arc::clone(&state),
            ) => value,
        };
        if result.is_err() {
            continue;
        }
    }
    let pending = state
        .lock()
        .map(|mut state| std::mem::take(&mut state.downloads))
        .unwrap_or_default();
    for (token, download) in pending {
        let _ = download.destination.remove_staging(&token);
    }
}

async fn handle_file_guard_connection(
    mut stream: UnixStream,
    allowlist: Allowlist,
    staging_root: PathBuf,
    state: Arc<Mutex<FileGuardState>>,
) -> Result<(), BridgeError> {
    let bytes = read_file_guard_message(&mut stream).await?;
    let request: FileGuardRequest = parse_strict_json(&bytes)
        .map_err(|_| BridgeError::ProtocolMessage("invalid helper guard request".into()))?;
    let operation = request.operation;
    let path = request.path;
    let token = request.token;
    let result = if path.is_empty() || path.len() > 4096 {
        None
    } else {
        tokio::task::spawn_blocking(move || match operation.as_str() {
            "upload" => {
                stage_allowlisted_input(&allowlist, &staging_root, &state, Path::new(&path))
                    .map(|path| (path, None))
            }
            "prepare_download" if token.is_none() => {
                prepare_allowlisted_output(&allowlist, &state, Path::new(&path))
            }
            "commit_download" => commit_allowlisted_output(
                &allowlist,
                &state,
                Path::new(&path),
                token.as_deref().unwrap_or_default(),
            )
            .map(|path| (path, None)),
            _ => Err(BridgeError::ProtocolMessage(
                "helper file operation rejected".into(),
            )),
        })
        .await
        .ok()
        .and_then(Result::ok)
    };
    let response = match result {
        Some((path, token)) => FileGuardResponse {
            ok: true,
            path: Some(path),
            token,
            error: None,
        },
        None => FileGuardResponse {
            ok: false,
            path: None,
            token: None,
            error: Some("artifact_error: helper file path rejected"),
        },
    };
    let mut encoded = canonical_json(&response)
        .map_err(|_| BridgeError::ProtocolMessage("helper guard response failed".into()))?;
    encoded.push(b'\n');
    stream.write_all(&encoded).await.map_err(BridgeError::Io)?;
    stream.shutdown().await.map_err(BridgeError::Io)
}

async fn read_file_guard_message(stream: &mut UnixStream) -> Result<Vec<u8>, BridgeError> {
    let mut value = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await.map_err(BridgeError::Io)?;
        if count == 0 {
            return Err(BridgeError::ProtocolMessage(
                "truncated helper guard request".into(),
            ));
        }
        if let Some(index) = chunk[..count].iter().position(|byte| *byte == b'\n') {
            if index + 1 != count {
                return Err(BridgeError::ProtocolMessage(
                    "trailing helper guard request data".into(),
                ));
            }
            value.extend_from_slice(&chunk[..index]);
            break;
        }
        value.extend_from_slice(&chunk[..count]);
        if value.len() > MAX_FILE_GUARD_MESSAGE_BYTES {
            return Err(BridgeError::ProtocolMessage(
                "helper guard request exceeds limit".into(),
            ));
        }
    }
    if value.is_empty() || value.len() > MAX_FILE_GUARD_MESSAGE_BYTES {
        return Err(BridgeError::ProtocolMessage(
            "helper guard request is invalid".into(),
        ));
    }
    Ok(value)
}

fn stage_allowlisted_input(
    allowlist: &Allowlist,
    staging_root: &Path,
    state: &Mutex<FileGuardState>,
    requested_path: &Path,
) -> Result<String, BridgeError> {
    let mut state = state.lock().map_err(|_| BridgeError::Unavailable)?;
    let input = allowlist
        .open_input(
            requested_path,
            state.budget.total_bytes,
            state.budget.file_count,
        )
        .map_err(|_| BridgeError::ProtocolMessage("helper file path rejected".into()))?;
    let input_size = input.size_bytes;
    let file_name = input
        .path
        .file_name()
        .ok_or_else(|| BridgeError::ProtocolMessage("helper file name is invalid".into()))?
        .to_owned();
    let bytes = input
        .read_to_end()
        .map_err(|_| BridgeError::ProtocolMessage("helper file read failed".into()))?;
    let directory = staging_root.join(format!("upload-{}", state.budget.file_count + 1));
    std::fs::create_dir(&directory).map_err(BridgeError::Io)?;
    set_private_permissions(&directory).map_err(BridgeError::Io)?;
    let destination = directory.join(file_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut output = options.open(&destination).map_err(BridgeError::Io)?;
    output.write_all(&bytes).map_err(BridgeError::Io)?;
    output.sync_all().map_err(BridgeError::Io)?;
    state.budget.total_bytes = state.budget.total_bytes.saturating_add(input_size);
    state.budget.file_count = state.budget.file_count.saturating_add(1);
    destination
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| BridgeError::ProtocolMessage("helper staging path is invalid".into()))
}

fn prepare_allowlisted_output(
    allowlist: &Allowlist,
    state: &Mutex<FileGuardState>,
    requested_path: &Path,
) -> Result<(String, Option<String>), BridgeError> {
    let mut state = state.lock().map_err(|_| BridgeError::Unavailable)?;
    let operation_count = state
        .budget
        .file_count
        .checked_add(state.downloads.len())
        .ok_or_else(|| BridgeError::ProtocolMessage("helper output count rejected".into()))?;
    let destination = allowlist
        .validate_output(requested_path, state.budget.total_bytes, operation_count, 0)
        .map_err(|_| BridgeError::ProtocolMessage("helper output path rejected".into()))?;
    let token = loop {
        let candidate = opaque_id();
        if !state.downloads.contains_key(&candidate) {
            break candidate;
        }
    };
    let staging_path = destination
        .staging_path(&token)
        .map_err(|_| BridgeError::ProtocolMessage("helper staging path is invalid".into()))?;
    state.downloads.insert(
        token.clone(),
        PreparedDownload {
            staging_path: staging_path.clone(),
            destination,
        },
    );
    let path = staging_path
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| BridgeError::ProtocolMessage("helper staging path is invalid".into()))?;
    Ok((path, Some(token)))
}

fn commit_allowlisted_output(
    allowlist: &Allowlist,
    state: &Mutex<FileGuardState>,
    staged_path: &Path,
    token: &str,
) -> Result<String, BridgeError> {
    let mut state = state.lock().map_err(|_| BridgeError::Unavailable)?;
    let prepared = state
        .downloads
        .remove(token)
        .ok_or_else(|| BridgeError::ProtocolMessage("helper output token rejected".into()))?;
    if prepared.staging_path != staged_path {
        return Err(BridgeError::ProtocolMessage(
            "helper staging path rejected".into(),
        ));
    }
    let destination = prepared.destination;
    let result: Result<(), BridgeError> = (|| {
        let input = allowlist
            .open_input(
                staged_path,
                state.budget.total_bytes,
                state.budget.file_count,
            )
            .map_err(|_| BridgeError::ProtocolMessage("helper output limit rejected".into()))?;
        let size = input.size_bytes;
        let bytes = input
            .read_to_end()
            .map_err(|_| BridgeError::ProtocolMessage("helper output changed".into()))?;
        destination
            .replace_atomically(&bytes, token)
            .map_err(|_| BridgeError::ProtocolMessage("helper output changed".into()))?;
        state.budget.total_bytes = state.budget.total_bytes.saturating_add(size);
        state.budget.file_count = state.budget.file_count.saturating_add(1);
        Ok(())
    })();
    let _ = destination.remove_staging(token);
    result?;
    destination
        .path
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| BridgeError::ProtocolMessage("helper output path is invalid".into()))
}

pub(crate) fn helper_guard_script(
    socket_path: Option<&Path>,
    default_task_space: &str,
    script: &str,
) -> Result<String, BridgeError> {
    if !is_dedicated_task_space(default_task_space) {
        return Err(BridgeError::ProtocolMessage(
            "invalid default task space".into(),
        ));
    }
    let wrapper = if let Some(socket_path) = socket_path {
        let socket = socket_path
            .to_str()
            .ok_or_else(|| BridgeError::ProtocolMessage("helper guard path is invalid".into()))?;
        let socket = serde_json::to_string(socket)
            .map_err(|_| BridgeError::ProtocolMessage("helper guard path is invalid".into()))?;
        format!(
            r#"{{
const originalUploadFile = globalThis.uploadFile;
const originalSetInputFiles = globalThis.setInputFiles;
const originalDownloadSaveAs = globalThis.download && globalThis.download.saveAs;
const guardSocketPath = {socket};
const guardFilePath = async (operation, filePath, token) => {{
  if (typeof filePath !== 'string' || filePath.length === 0) throw new Error('artifact_error: helper file path rejected');
  const net = await import('node:net');
  return await new Promise((resolve, reject) => {{
    const client = net.createConnection({{ path: guardSocketPath }});
    let response = '';
    client.setEncoding('utf8');
    client.on('connect', () => client.end(JSON.stringify({{ operation, path: filePath, token }}) + '\n'));
    client.on('data', (chunk) => {{
      response += chunk;
      if (Buffer.byteLength(response, 'utf8') > 16384) client.destroy(new Error('artifact_error: helper guard response exceeds limit'));
    }});
    client.on('error', () => reject(new Error('artifact_error: helper file validation unavailable')));
    client.on('end', () => {{
      try {{
        const parsed = JSON.parse(response);
        if (!parsed.ok || typeof parsed.path !== 'string') throw new Error('rejected');
        resolve(parsed);
      }} catch (_) {{
        reject(new Error('artifact_error: helper file path rejected'));
      }}
    }});
  }});
}};
const validateUploadPaths = async (filePath) => {{
  if (Array.isArray(filePath)) {{
    const staged = [];
    for (const value of filePath) staged.push((await guardFilePath('upload', value, null)).path);
    return staged;
  }}
  return (await guardFilePath('upload', filePath, null)).path;
}};
globalThis.uploadFile = async function(target, filePath, ...rest) {{
  if (typeof originalUploadFile !== 'function') throw new Error('artifact_error: uploadFile helper unavailable');
  const stagedPath = await validateUploadPaths(filePath);
  return await originalUploadFile.call(this, target, stagedPath, ...rest);
}};
globalThis.setInputFiles = async function(target, filePath, ...rest) {{
  if (typeof originalSetInputFiles !== 'function') throw new Error('artifact_error: setInputFiles helper unavailable');
  const stagedPath = await validateUploadPaths(filePath);
  return await originalSetInputFiles.call(this, target, stagedPath, ...rest);
}};
if (globalThis.download && typeof globalThis.download === 'object') {{
  globalThis.download.saveAs = async function(filePath, ...rest) {{
    if (typeof originalDownloadSaveAs !== 'function') throw new Error('artifact_error: download.saveAs helper unavailable');
    const prepared = await guardFilePath('prepare_download', filePath, null);
    const result = await originalDownloadSaveAs.call(this, prepared.path, ...rest);
    await guardFilePath('commit_download', prepared.path, prepared.token);
    return result;
  }};
}}
}}
"#
        )
    } else {
        r#"{
const rejectHelperFile = async function() {
  throw new Error('artifact_error: helper file allowlist is not configured');
};
globalThis.uploadFile = rejectHelperFile;
globalThis.setInputFiles = rejectHelperFile;
if (globalThis.download && typeof globalThis.download === 'object') {
  globalThis.download.saveAs = rejectHelperFile;
}
}
"#
        .to_owned()
    };
    let task_space = serde_json::to_string(default_task_space)
        .map_err(|_| BridgeError::ProtocolMessage("invalid default task space".into()))?;
    // Redirect normal Skill selection lazily. Eager selection would fail before
    // an explicitly confirmed takeOverTaskSpace/claimTaskSpace recovery can run.
    let task_space_wrapper = format!(
        r#"{{
const agentRemoteDefaultTaskSpace = {task_space};
const agentRemoteUseOrCreateTaskSpace = globalThis.useOrCreateTaskSpace;
if (typeof agentRemoteUseOrCreateTaskSpace !== 'function') {{
  throw new Error('ego_runtime_unavailable: useOrCreateTaskSpace helper unavailable');
}}
globalThis.useOrCreateTaskSpace = async function(_nameOrId, ...rest) {{
  return await agentRemoteUseOrCreateTaskSpace.call(globalThis, agentRemoteDefaultTaskSpace, ...rest);
}};
}}
"#
    );
    Ok(format!("{wrapper}{task_space_wrapper}{script}"))
}
