//! Bounded artifact output and retention handling.

use super::*;

pub(super) async fn emit_response(response: InnerExecuteResponse) -> Result<(), WrapperError> {
    if response.stdout.len() > MAX_STDOUT_BYTES || response.stderr.len() > MAX_STDERR_BYTES {
        return Err(WrapperError::Protocol(
            "response output exceeds limit".into(),
        ));
    }
    if response.status != ego_browser_bridge_protocol::ExecutionStatus::Completed {
        return Err(WrapperError::Status(format!("{:?}", response.status)));
    }
    if response.exit_code.is_some_and(|code| code != 0) {
        return Err(WrapperError::Exit(response.exit_code.unwrap_or_default()));
    }
    // Default artifact paths remain readable after this process exits. Later
    // invocations prune the private cache using a bounded TTL and count.
    let directory = if response.artifacts.is_empty() {
        None
    } else {
        Some(artifact_directory()?)
    };
    let mut artifacts = Vec::new();
    let mut total_bytes = 0_usize;
    if response.artifacts.len() > MAX_ARTIFACT_COUNT {
        return Err(WrapperError::Protocol("too many artifacts".into()));
    }
    for artifact in &response.artifacts {
        let bytes = decode_canonical_b64(&artifact.content_b64)?;
        if artifact.media_type != "image/png" && artifact.media_type != "image/jpeg" {
            return Err(WrapperError::Protocol(
                "unsupported artifact media type".into(),
            ));
        }
        if artifact.artifact_id.is_empty()
            || artifact.artifact_id.len() > 128
            || !artifact
                .artifact_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(WrapperError::Protocol("invalid artifact id".into()));
        }
        if bytes.len() > MAX_ARTIFACT_BYTES
            || bytes.len() as u64 != artifact.size_bytes
            || total_bytes.saturating_add(bytes.len()) > MAX_ARTIFACT_BYTES
        {
            return Err(WrapperError::Protocol(
                "artifact size limit exceeded".into(),
            ));
        }
        let (media_type, width, height) = image_dimensions(&bytes)
            .ok_or_else(|| WrapperError::Protocol("invalid artifact image".into()))?;
        if media_type != artifact.media_type
            || width != artifact.width
            || height != artifact.height
            || width == 0
            || height == 0
            || (width as u64).saturating_mul(height as u64) > MAX_ARTIFACT_PIXELS
        {
            return Err(WrapperError::Protocol("artifact metadata mismatch".into()));
        }
        total_bytes = total_bytes.saturating_add(bytes.len());
        let extension = if media_type == "image/png" {
            "png"
        } else {
            "jpg"
        };
        let directory_path = directory
            .as_ref()
            .map(|value| value.path.as_path())
            .ok_or_else(|| WrapperError::Protocol("artifact directory unavailable".into()))?;
        let path = directory_path.join(format!("{}.{}", artifact.artifact_id, extension));
        if !path.starts_with(directory_path) {
            return Err(WrapperError::Protocol(
                "artifact path escaped directory".into(),
            ));
        }
        artifacts.push((path, bytes));
    }

    let mut out = stdout();
    if !response.stdout.is_empty() {
        tokio::io::AsyncWriteExt::write_all(&mut out, response.stdout.as_bytes())
            .await
            .map_err(|error| WrapperError::Io(error.to_string()))?;
    }
    if !response.stderr.is_empty() {
        eprint!("{}", response.stderr);
    }
    for (path, bytes) in artifacts {
        write_artifact(&path, &bytes)?;
        eprintln!("artifact: {}", path.display());
    }
    out.flush()
        .await
        .map_err(|error| WrapperError::Io(error.to_string()))?;
    Ok(())
}

struct ArtifactDirectory {
    path: PathBuf,
}

fn artifact_directory() -> Result<ArtifactDirectory, WrapperError> {
    let requested = match env::var_os("EGO_BROWSER_ARTIFACT_DIR") {
        Some(value) => PathBuf::from(value),
        None => default_artifact_directory()?,
    };
    validate_path_components(&requested)?;
    if !requested.is_absolute() {
        return Err(WrapperError::Protocol(
            "artifact directory must be absolute".into(),
        ));
    }
    let was_missing = fs::symlink_metadata(&requested).is_err();
    if was_missing {
        fs::create_dir_all(&requested).map_err(|error| WrapperError::Io(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&requested, fs::Permissions::from_mode(0o700))
                .map_err(|error| WrapperError::Io(error.to_string()))?;
        }
    }
    let metadata =
        fs::symlink_metadata(&requested).map_err(|error| WrapperError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WrapperError::Protocol(
            "artifact directory is invalid".into(),
        ));
    }
    validate_owner_only_directory(&metadata)?;
    let canonical =
        fs::canonicalize(&requested).map_err(|error| WrapperError::Io(error.to_string()))?;
    Ok(ArtifactDirectory { path: canonical })
}

fn default_artifact_directory() -> Result<PathBuf, WrapperError> {
    let root = env::temp_dir().join("agent-remote-ego-browser-artifacts");
    validate_path_components(&root)?;
    if fs::symlink_metadata(&root).is_err() {
        fs::create_dir(&root).map_err(|error| WrapperError::Io(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|error| WrapperError::Io(error.to_string()))?;
        }
    }
    let metadata =
        fs::symlink_metadata(&root).map_err(|error| WrapperError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WrapperError::Protocol(
            "artifact cache root is invalid".into(),
        ));
    }
    validate_owner_only_directory(&metadata)?;
    prune_default_artifact_directories(&root)?;
    let request = root.join(format!(
        "request-{}-{}-{}",
        std::process::id(),
        now_millis(),
        ego_browser_bridge_protocol::opaque_id()
    ));
    fs::create_dir(&request).map_err(|error| WrapperError::Io(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&request, fs::Permissions::from_mode(0o700))
            .map_err(|error| WrapperError::Io(error.to_string()))?;
    }
    Ok(request)
}

fn prune_default_artifact_directories(root: &Path) -> Result<(), WrapperError> {
    let now = SystemTime::now();
    let mut directories = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| WrapperError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| WrapperError::Io(error.to_string()))?;
        if !entry.file_name().to_string_lossy().starts_with("request-") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| WrapperError::Io(error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        validate_owner_only_directory(&metadata)?;
        directories.push((metadata.modified().unwrap_or(UNIX_EPOCH), entry.path()));
    }
    directories.sort_by_key(|(modified, _)| *modified);
    let excess = directories
        .len()
        .saturating_sub(DEFAULT_ARTIFACT_REQUEST_DIRECTORIES);
    for (index, (modified, path)) in directories.into_iter().enumerate() {
        let expired = now
            .duration_since(modified)
            .map(|age| age.as_secs() >= DEFAULT_ARTIFACT_RETENTION_SECONDS)
            .unwrap_or(false);
        if expired || index < excess {
            fs::remove_dir_all(path).map_err(|error| WrapperError::Io(error.to_string()))?;
        }
    }
    Ok(())
}

fn validate_path_components(path: &Path) -> Result<(), WrapperError> {
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(WrapperError::Protocol("artifact path traversal".into()));
        }
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(WrapperError::Protocol("artifact symlink path".into()));
            }
        }
    }
    Ok(())
}

fn validate_owner_only_directory(metadata: &fs::Metadata) -> Result<(), WrapperError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(WrapperError::Protocol(
                "artifact directory permissions".into(),
            ));
        }
    }
    Ok(())
}

fn write_artifact(path: &Path, bytes: &[u8]) -> Result<(), WrapperError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            WrapperError::Protocol("artifact already exists".into())
        } else {
            WrapperError::Io(error.to_string())
        }
    })?;
    file.write_all(bytes)
        .map_err(|error| WrapperError::Io(error.to_string()))?;
    file.flush()
        .map_err(|error| WrapperError::Io(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| WrapperError::Io(error.to_string()))?;
    if !metadata.is_file() {
        return Err(WrapperError::Protocol(
            "artifact destination is not regular".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(WrapperError::Protocol(
                "artifact destination identity".into(),
            ));
        }
    }
    Ok(())
}

fn decode_canonical_b64(value: &str) -> Result<Vec<u8>, WrapperError> {
    let bytes = decode_b64url(value)
        .map_err(|_| WrapperError::Protocol("invalid artifact encoding".into()))?;
    if encode_b64url(&bytes) != value {
        return Err(WrapperError::Protocol(
            "non-canonical artifact encoding".into(),
        ));
    }
    Ok(bytes)
}

fn image_dimensions(bytes: &[u8]) -> Option<(&'static str, u32, u32)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        return (width != 0 && height != 0).then_some(("image/png", width, height));
    }
    if bytes.starts_with(&[0xff, 0xd8]) {
        let (width, height) = jpeg_dimensions(bytes)?;
        return (width != 0 && height != 0).then_some(("image/jpeg", width, height));
    }
    None
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let mut index = 2;
    while index + 9 < bytes.len() {
        if bytes[index] != 0xff {
            index += 1;
            continue;
        }
        while index < bytes.len() && bytes[index] == 0xff {
            index += 1;
        }
        let marker = *bytes.get(index)?;
        index += 1;
        if marker == 0xd9 || marker == 0xda || index + 2 > bytes.len() {
            return None;
        }
        let length = u16::from_be_bytes(bytes[index..index + 2].try_into().ok()?) as usize;
        if length < 2 || index + length > bytes.len() {
            return None;
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) && length >= 7 {
            let height = u16::from_be_bytes(bytes[index + 3..index + 5].try_into().ok()?) as u32;
            let width = u16::from_be_bytes(bytes[index + 5..index + 7].try_into().ok()?) as u32;
            return Some((width, height));
        }
        index += length;
    }
    None
}

pub(super) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
