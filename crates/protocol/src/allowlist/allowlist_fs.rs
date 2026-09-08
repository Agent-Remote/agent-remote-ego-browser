//! Race-resistant allowlist filesystem operations.

use super::*;

pub(super) fn canonical_existing_directory(path: &Path) -> Result<PathBuf, AllowlistError> {
    reject_path_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AllowlistError::ParentMissing
        } else {
            AllowlistError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(if metadata.file_type().is_symlink() {
            AllowlistError::Symlink
        } else {
            AllowlistError::NonRegular
        });
    }
    fs::canonicalize(path).map_err(AllowlistError::Io)
}

pub(super) fn reject_path_components(path: &Path) -> Result<(), AllowlistError> {
    if !path.is_absolute() {
        return Err(AllowlistError::InvalidPath);
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(AllowlistError::InvalidPath);
        }
    }
    // Check every existing component using lstat so a symlink cannot hide in a parent.
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(AllowlistError::Symlink);
            }
        }
    }
    Ok(())
}

pub(super) fn staging_name(token: &str) -> Result<OsString, AllowlistError> {
    validate_operation_token(token)?;
    Ok(format!(".agent-remote-download-{token}.incoming").into())
}

pub(super) fn commit_name(token: &str) -> Result<OsString, AllowlistError> {
    validate_operation_token(token)?;
    Ok(format!(".agent-remote-download-{token}-{}.commit", Uuid::new_v4()).into())
}

pub(super) fn validate_operation_token(token: &str) -> Result<(), AllowlistError> {
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AllowlistError::InvalidPath);
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn path_component(value: &OsStr) -> Result<CString, AllowlistError> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(value.as_bytes()).map_err(|_| AllowlistError::InvalidPath)
}

#[cfg(unix)]
pub(super) fn open_root_directory(
    root: &Path,
    expected_identity: FileIdentity,
) -> Result<File, AllowlistError> {
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(root).map_err(map_open_error)?;
    let metadata = directory.metadata().map_err(AllowlistError::Io)?;
    if !metadata.is_dir() || file_identity(&metadata) != expected_identity {
        return Err(AllowlistError::ChangedDuringOpen);
    }
    Ok(directory)
}

#[cfg(unix)]
pub(super) fn open_at_raw(
    parent: &File,
    name: &OsStr,
    flags: libc::c_int,
) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = path_component(name).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
pub(super) fn map_open_error(error: std::io::Error) -> AllowlistError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        AllowlistError::Symlink
    } else {
        AllowlistError::Io(error)
    }
}

#[cfg(unix)]
pub(super) fn open_directory_at(parent: &File, name: &OsStr) -> Result<File, AllowlistError> {
    let directory = open_at_raw(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(map_open_error)?;
    if !directory.metadata().map_err(AllowlistError::Io)?.is_dir() {
        return Err(AllowlistError::NonRegular);
    }
    Ok(directory)
}

#[cfg(unix)]
pub(super) fn open_beneath_directory(
    root: &Path,
    root_identity: FileIdentity,
    relative: &Path,
) -> Result<File, AllowlistError> {
    let mut directory = open_root_directory(root, root_identity)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(AllowlistError::InvalidPath);
        };
        directory = open_directory_at(&directory, name)?;
    }
    Ok(directory)
}

#[cfg(not(unix))]
pub(super) fn open_beneath_directory(
    root: &Path,
    _root_identity: FileIdentity,
    relative: &Path,
) -> Result<File, AllowlistError> {
    File::open(root.join(relative)).map_err(AllowlistError::Io)
}

#[cfg(unix)]
pub(super) fn open_beneath(
    root: &Path,
    root_identity: FileIdentity,
    relative: &Path,
    write: bool,
    create_new: bool,
) -> Result<File, AllowlistError> {
    let parent = open_beneath_directory(
        root,
        root_identity,
        relative.parent().unwrap_or_else(|| Path::new("")),
    )?;
    let name = relative.file_name().ok_or(AllowlistError::InvalidPath)?;
    let mut flags = if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    } | libc::O_NOFOLLOW
        | libc::O_CLOEXEC;
    if create_new {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    open_at_raw(&parent, name, flags).map_err(map_open_error)
}

#[cfg(not(unix))]
pub(super) fn open_beneath(
    root: &Path,
    _root_identity: FileIdentity,
    relative: &Path,
    write: bool,
    create_new: bool,
) -> Result<File, AllowlistError> {
    let mut options = OpenOptions::new();
    options.read(!write).write(write).create_new(create_new);
    options
        .open(root.join(relative))
        .map_err(AllowlistError::Io)
}

#[cfg(unix)]
pub(super) fn open_output_at(
    parent: &File,
    name: &OsStr,
    create_new: bool,
) -> Result<File, AllowlistError> {
    let mut flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if create_new {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    open_at_raw(parent, name, flags).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            AllowlistError::ChangedDuringOpen
        } else {
            map_open_error(error)
        }
    })
}

#[cfg(not(unix))]
pub(super) fn open_output_at(
    _parent: &File,
    _name: &OsStr,
    _create_new: bool,
) -> Result<File, AllowlistError> {
    Err(AllowlistError::InvalidPath)
}

#[cfg(unix)]
pub(super) fn inspect_output_at(
    parent: &File,
    name: &OsStr,
) -> Result<Option<fs::Metadata>, AllowlistError> {
    match open_at_raw(
        parent,
        name,
        libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(file) => file.metadata().map(Some).map_err(AllowlistError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_open_error(error)),
    }
}

#[cfg(not(unix))]
pub(super) fn inspect_output_at(
    _parent: &File,
    _name: &OsStr,
) -> Result<Option<fs::Metadata>, AllowlistError> {
    Err(AllowlistError::InvalidPath)
}

#[cfg(unix)]
pub(super) fn rename_at(
    parent: &File,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), AllowlistError> {
    use std::os::fd::AsRawFd;

    let source = path_component(source)?;
    let destination = path_component(destination)?;
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
        )
    } != 0
    {
        return Err(AllowlistError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn rename_at(
    _parent: &File,
    _source: &OsStr,
    _destination: &OsStr,
) -> Result<(), AllowlistError> {
    Err(AllowlistError::InvalidPath)
}

#[cfg(unix)]
pub(super) fn unlink_at(parent: &File, name: &OsStr) -> Result<(), AllowlistError> {
    use std::os::fd::AsRawFd;

    let name = path_component(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(AllowlistError::Io(error));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn unlink_at(_parent: &File, _name: &OsStr) -> Result<(), AllowlistError> {
    Err(AllowlistError::InvalidPath)
}

pub(super) fn validate_regular_file(metadata: &fs::Metadata) -> Result<(), AllowlistError> {
    if !metadata.is_file() {
        return Err(AllowlistError::NonRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if link_count(metadata) != 1 {
            return Err(AllowlistError::HardLink);
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(AllowlistError::NonRegular);
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
pub(super) type FileIdentity = (u64, u64);

#[cfg(not(unix))]
pub(super) type FileIdentity = u64;

#[cfg(unix)]
pub(super) fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
pub(super) fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    metadata.len()
}

#[cfg(not(unix))]
pub(super) fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
pub(super) fn link_count(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(unix))]
pub(super) fn link_count(_metadata: &fs::Metadata) -> u64 {
    1
}
