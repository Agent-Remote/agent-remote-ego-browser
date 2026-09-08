//! Local bridge state store internals.

use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteSequenceState {
    version: u32,
    highest_sequence: u64,
}

pub(super) fn acquire_instance_lock(root: &Path) -> Result<std::fs::File, BridgeError> {
    let path = root.join("bridge-instance.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(&path).map_err(BridgeError::Io)?;
    validate_private_file(&path)?;
    #[cfg(unix)]
    if unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } != 0
    {
        return Err(BridgeError::ProtocolMessage(
            "another Bridge instance owns the work root".into(),
        ));
    }
    Ok(file)
}

pub(super) fn load_remote_sequence(path: &Path) -> Result<u64, BridgeError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_private_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(BridgeError::Io(error)),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(BridgeError::Io)?;
    let mut bytes = Vec::new();
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(BridgeError::Io)?;
    if bytes.len() > 256 {
        return Err(BridgeError::ProtocolMessage(
            "remote sequence ledger is too large".into(),
        ));
    }
    let state: RemoteSequenceState = parse_strict_json(&bytes)
        .map_err(|_| BridgeError::ProtocolMessage("remote sequence ledger is malformed".into()))?;
    if state.version != 1 {
        return Err(BridgeError::ProtocolMessage(
            "remote sequence ledger version is unsupported".into(),
        ));
    }
    Ok(state.highest_sequence)
}

pub(super) fn persist_remote_sequence(path: &Path, sequence: u64) -> Result<(), BridgeError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_private_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(BridgeError::Io(error)),
    }
    let parent = path.parent().ok_or_else(|| {
        BridgeError::ProtocolMessage("remote sequence ledger path is invalid".into())
    })?;
    let state = RemoteSequenceState {
        version: 1,
        highest_sequence: sequence,
    };
    let bytes = canonical_json(&state)
        .map_err(|_| BridgeError::ProtocolMessage("remote sequence ledger failed".into()))?;
    for _ in 0..8 {
        let temporary = parent.join(format!(
            ".remote-sequence-{}.tmp",
            ego_browser_bridge_protocol::opaque_id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BridgeError::Io(error)),
        };
        let result = (|| -> Result<(), BridgeError> {
            file.write_all(&bytes).map_err(BridgeError::Io)?;
            file.sync_all().map_err(BridgeError::Io)?;
            drop(file);
            std::fs::rename(&temporary, path).map_err(BridgeError::Io)?;
            validate_private_file(path)?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(BridgeError::Io)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        return result;
    }
    Err(BridgeError::ProtocolMessage(
        "remote sequence ledger temporary path collision".into(),
    ))
}

fn validate_private_file(path: &Path) -> Result<(), BridgeError> {
    let metadata = std::fs::symlink_metadata(path).map_err(BridgeError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BridgeError::ProtocolMessage(
            "Bridge state path is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.permissions().mode() & 0o600 != 0o600
        {
            return Err(BridgeError::ProtocolMessage(
                "Bridge state file permissions are unsafe".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn prepare_private_root(path: &Path) -> Result<(), BridgeError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(BridgeError::ProtocolMessage(
            "work root must be an absolute canonical path".into(),
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = std::fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(BridgeError::ProtocolMessage(
                    "work root contains a symlink".into(),
                ));
            }
        }
    }
    let missing = std::fs::symlink_metadata(path).is_err();
    if missing {
        std::fs::create_dir_all(path).map_err(BridgeError::Io)?;
        set_private_permissions(path).map_err(BridgeError::Io)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(BridgeError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BridgeError::ProtocolMessage(
            "work root is not a directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(BridgeError::ProtocolMessage(
                "work root permissions are unsafe".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
