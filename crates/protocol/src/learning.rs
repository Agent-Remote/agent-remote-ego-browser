use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{canonical_json, parse_strict_json};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 4096;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(unix)]
type FileIdentity = (u64, u64);

#[cfg(not(unix))]
type FileIdentity = u64;

struct ReadOnlyFile {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

/// Release trust anchor for bundled Site Learning manifests.
///
/// The matching private key is intentionally not present in this repository.
/// The 2026-09 trust-anchor rotation retired the previous public key; a release
/// that rotates this key must also update its signed release manifest.
pub const TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY: [u8; 32] = [
    0x81, 0x9c, 0xf9, 0xff, 0x15, 0x70, 0x3b, 0xab, 0x7a, 0xb4, 0x27, 0x21, 0xa0, 0x28, 0x42, 0xf8,
    0x2d, 0xe2, 0x91, 0x25, 0xcf, 0x25, 0xf0, 0x06, 0x5f, 0x8b, 0x9a, 0xd8, 0xba, 0xf5, 0x51, 0x00,
];

/// Signed file entry in a Site Learning bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LearningFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Manifest shipped with a Bridge release.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LearningBundleManifest {
    pub bundle_version: String,
    pub skill_version: String,
    pub local_ego_browser_runtime_version: String,
    pub protocol_versions: Vec<String>,
    pub files: Vec<LearningFile>,
    pub signing_key_id: String,
    pub signature: String,
}

impl LearningBundleManifest {
    /// Canonical bytes covered by the Ed25519 signature.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, LearningBundleError> {
        let mut value =
            serde_json::to_value(self).map_err(|_| LearningBundleError::MalformedManifest)?;
        let object = value
            .as_object_mut()
            .ok_or(LearningBundleError::MalformedManifest)?;
        object.remove("signature");
        canonical_json(&value).map_err(|_| LearningBundleError::MalformedManifest)
    }
}

/// Metadata derived from a fully verified Site Learning bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLearningBundle {
    pub root: PathBuf,
    pub digest: String,
    pub bundle_version: String,
    pub skill_version: String,
    pub local_ego_browser_runtime_version: String,
}

/// Verify a fixed, read-only learning bundle and return its digest.
pub fn verify_learning_bundle(
    root: &Path,
    public_key: &[u8; 32],
    expected_skill_version: &str,
    expected_runtime_version: &str,
) -> Result<String, LearningBundleError> {
    let verified = verify_learning_bundle_details(root, public_key)?;
    if verified.skill_version != expected_skill_version
        || verified.local_ego_browser_runtime_version != expected_runtime_version
    {
        return Err(LearningBundleError::VersionMismatch);
    }
    Ok(verified.digest)
}

/// Verify a fixed bundle and return the signed version metadata.
pub fn verify_learning_bundle_details(
    root: &Path,
    public_key: &[u8; 32],
) -> Result<VerifiedLearningBundle, LearningBundleError> {
    if !root.is_absolute() {
        return Err(LearningBundleError::InvalidRoot);
    }
    reject_symlink_components(root)?;
    let metadata = fs::symlink_metadata(root).map_err(LearningBundleError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LearningBundleError::InvalidRoot);
    }
    validate_read_only_directory(&metadata)?;
    let root_identity = file_identity(&metadata);
    let canonical_root = fs::canonicalize(root).map_err(LearningBundleError::Io)?;
    if canonical_root != root {
        return Err(LearningBundleError::InvalidRoot);
    }
    let root_handle = open_root_directory(root, root_identity)?;
    let manifest_relative = Path::new("manifest.json");
    let manifest_file =
        read_read_only_file(root, &root_handle, manifest_relative, MAX_MANIFEST_BYTES)?;
    let manifest: LearningBundleManifest = parse_strict_json(&manifest_file.bytes)
        .map_err(|_| LearningBundleError::MalformedManifest)?;
    if manifest.bundle_version.is_empty()
        || manifest.skill_version.is_empty()
        || manifest.local_ego_browser_runtime_version.is_empty()
        || !manifest
            .protocol_versions
            .iter()
            .any(|value| value == crate::PROTOCOL_VERSION)
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_BUNDLE_FILES
    {
        return Err(LearningBundleError::VersionMismatch);
    }
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| LearningBundleError::InvalidSignature)?;
    let signature_bytes = STANDARD
        .decode(&manifest.signature)
        .map_err(|_| LearningBundleError::InvalidSignature)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| LearningBundleError::InvalidSignature)?;
    key.verify(&manifest.signed_bytes()?, &signature)
        .map_err(|_| LearningBundleError::InvalidSignature)?;

    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(&manifest.signed_bytes()?);
    let mut paths = HashSet::with_capacity(manifest.files.len());
    let mut identities = HashMap::with_capacity(manifest.files.len().saturating_add(1));
    identities.insert(manifest_relative.to_owned(), manifest_file.identity);
    let mut total_bytes = 0_u64;
    for entry in &manifest.files {
        let relative = validate_relative_path(&entry.path)?;
        if !paths.insert(relative.clone()) {
            return Err(LearningBundleError::DuplicatePath(entry.path.clone()));
        }
        total_bytes = total_bytes
            .checked_add(entry.size_bytes)
            .ok_or(LearningBundleError::BundleTooLarge)?;
        if total_bytes > MAX_BUNDLE_BYTES {
            return Err(LearningBundleError::BundleTooLarge);
        }
        let path = root.join(&relative);
        reject_symlink_components(&path)?;
        require_read_only_parents(root, &relative)?;
        let canonical = fs::canonicalize(&path).map_err(LearningBundleError::Io)?;
        if !canonical.starts_with(&canonical_root) {
            return Err(LearningBundleError::InvalidPath);
        }
        let file = read_read_only_file(root, &root_handle, &relative, entry.size_bytes)?;
        if file.bytes.len() as u64 != entry.size_bytes {
            return Err(LearningBundleError::FileMismatch(entry.path.clone()));
        }
        let hash = hex_digest(&file.bytes);
        if !constant_time_eq(hash.as_bytes(), entry.sha256.as_bytes()) {
            return Err(LearningBundleError::FileMismatch(entry.path.clone()));
        }
        identities.insert(relative, file.identity);
        digest_input.extend_from_slice(entry.path.as_bytes());
        digest_input.extend_from_slice(entry.sha256.as_bytes());
        digest_input.extend_from_slice(&entry.size_bytes.to_be_bytes());
    }
    verify_complete_inventory(root, &paths)?;
    verify_snapshot(root, root_identity, &identities)?;
    Ok(VerifiedLearningBundle {
        root: canonical_root,
        digest: format!("sha256:{}", hex_digest(&digest_input)),
        bundle_version: manifest.bundle_version,
        skill_version: manifest.skill_version,
        local_ego_browser_runtime_version: manifest.local_ego_browser_runtime_version,
    })
}

fn verify_complete_inventory(
    root: &Path,
    expected_files: &HashSet<PathBuf>,
) -> Result<(), LearningBundleError> {
    let expected_directories = expected_files
        .iter()
        .flat_map(|path| {
            let mut directories = Vec::new();
            let mut parent = path.parent();
            while let Some(value) = parent {
                if value.as_os_str().is_empty() {
                    break;
                }
                directories.push(value.to_owned());
                parent = value.parent();
            }
            directories
        })
        .collect::<HashSet<_>>();
    let mut directories = vec![root.to_owned()];
    let mut observed = HashSet::with_capacity(expected_files.len());
    let mut observed_directories = HashSet::with_capacity(expected_directories.len());
    while let Some(directory) = directories.pop() {
        let before = fs::symlink_metadata(&directory).map_err(LearningBundleError::Io)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(LearningBundleError::InvalidPath);
        }
        validate_read_only_directory(&before)?;
        let entries = fs::read_dir(&directory).map_err(LearningBundleError::Io)?;
        for entry in entries {
            let entry = entry.map_err(LearningBundleError::Io)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(LearningBundleError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(LearningBundleError::InvalidPath);
            }
            if metadata.is_dir() {
                validate_read_only_directory(&metadata)?;
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| LearningBundleError::InvalidPath)?
                    .to_owned();
                if !expected_directories.contains(&relative) {
                    return Err(LearningBundleError::UnlistedPath(
                        relative.to_string_lossy().into_owned(),
                    ));
                }
                if !observed_directories.insert(relative) {
                    return Err(LearningBundleError::InvalidPath);
                }
                directories.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| LearningBundleError::InvalidPath)?
                .to_owned();
            validate_read_only_file_metadata(&metadata, &relative)?;
            if relative == Path::new("manifest.json") {
                continue;
            }
            if !expected_files.contains(&relative) {
                return Err(LearningBundleError::UnlistedPath(
                    relative.to_string_lossy().into_owned(),
                ));
            }
            observed.insert(relative);
        }
        let after = fs::symlink_metadata(&directory).map_err(LearningBundleError::Io)?;
        validate_read_only_directory(&after)?;
        if !same_file(&before, &after) {
            return Err(LearningBundleError::InvalidPath);
        }
    }
    if observed != *expected_files || observed_directories != expected_directories {
        return Err(LearningBundleError::InvalidPath);
    }
    Ok(())
}

fn read_read_only_file(
    root: &Path,
    root_handle: &File,
    relative: &Path,
    expected_max: u64,
) -> Result<ReadOnlyFile, LearningBundleError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(LearningBundleError::Io)?;
    validate_read_only_file_metadata(&metadata, relative)?;
    if metadata.len() > expected_max {
        return Err(LearningBundleError::FileMismatch(
            relative.to_string_lossy().into_owned(),
        ));
    }
    let file = open_beneath(root, root_handle, relative)?;
    let opened = file.metadata().map_err(LearningBundleError::Io)?;
    validate_read_only_file_metadata(&opened, relative)?;
    if opened.len() != metadata.len() || !same_file(&metadata, &opened) {
        return Err(LearningBundleError::FileMismatch(
            relative.to_string_lossy().into_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len().min(expected_max) as usize);
    (&file)
        .take(expected_max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(LearningBundleError::Io)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > expected_max {
        return Err(LearningBundleError::FileMismatch(
            relative.to_string_lossy().into_owned(),
        ));
    }
    let after_open = file.metadata().map_err(LearningBundleError::Io)?;
    validate_read_only_file_metadata(&after_open, relative)?;
    let after_path = fs::symlink_metadata(&path).map_err(LearningBundleError::Io)?;
    validate_read_only_file_metadata(&after_path, relative)?;
    if after_open.len() != opened.len()
        || !same_file(&opened, &after_open)
        || !same_file(&opened, &after_path)
    {
        return Err(LearningBundleError::FileMismatch(
            relative.to_string_lossy().into_owned(),
        ));
    }
    Ok(ReadOnlyFile {
        bytes,
        identity: file_identity(&opened),
    })
}

fn verify_snapshot(
    root: &Path,
    expected_root: FileIdentity,
    expected_files: &HashMap<PathBuf, FileIdentity>,
) -> Result<(), LearningBundleError> {
    reject_symlink_components(root)?;
    let root_metadata = fs::symlink_metadata(root).map_err(LearningBundleError::Io)?;
    validate_read_only_directory(&root_metadata)?;
    if file_identity(&root_metadata) != expected_root
        || fs::canonicalize(root).map_err(LearningBundleError::Io)? != root
    {
        return Err(LearningBundleError::InvalidRoot);
    }
    let root_handle = open_root_directory(root, expected_root)?;
    for (relative, expected_identity) in expected_files {
        let path = root.join(relative);
        reject_symlink_components(&path)?;
        require_read_only_parents(root, relative)?;
        let file = open_beneath(root, &root_handle, relative)?;
        let opened = file.metadata().map_err(LearningBundleError::Io)?;
        validate_read_only_file_metadata(&opened, relative)?;
        let current = fs::symlink_metadata(&path).map_err(LearningBundleError::Io)?;
        validate_read_only_file_metadata(&current, relative)?;
        if file_identity(&opened) != *expected_identity || !same_file(&opened, &current) {
            return Err(LearningBundleError::FileMismatch(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn path_component(value: &OsStr) -> Result<CString, LearningBundleError> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(value.as_bytes()).map_err(|_| LearningBundleError::InvalidPath)
}

#[cfg(unix)]
fn open_at_raw(parent: &File, name: &OsStr, flags: libc::c_int) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = path_component(name).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_root_directory(
    root: &Path,
    expected_identity: FileIdentity,
) -> Result<File, LearningBundleError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let directory = options.open(root).map_err(LearningBundleError::Io)?;
    let metadata = directory.metadata().map_err(LearningBundleError::Io)?;
    validate_read_only_directory(&metadata)?;
    if file_identity(&metadata) != expected_identity {
        return Err(LearningBundleError::InvalidRoot);
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &OsStr) -> Result<File, LearningBundleError> {
    let directory = open_at_raw(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(LearningBundleError::Io)?;
    validate_read_only_directory(&directory.metadata().map_err(LearningBundleError::Io)?)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_beneath(
    _root: &Path,
    root_handle: &File,
    relative: &Path,
) -> Result<File, LearningBundleError> {
    let mut directory = root_handle.try_clone().map_err(LearningBundleError::Io)?;
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let Component::Normal(name) = component else {
            return Err(LearningBundleError::InvalidPath);
        };
        directory = open_directory_at(&directory, name)?;
    }
    let name = relative
        .file_name()
        .ok_or(LearningBundleError::InvalidPath)?;
    open_at_raw(
        &directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(LearningBundleError::Io)
}

#[cfg(not(unix))]
fn open_beneath(
    root: &Path,
    _root_handle: &File,
    relative: &Path,
) -> Result<File, LearningBundleError> {
    File::open(root.join(relative)).map_err(LearningBundleError::Io)
}

fn reject_symlink_components(path: &Path) -> Result<(), LearningBundleError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(LearningBundleError::InvalidPath);
            }
        }
    }
    Ok(())
}

fn require_read_only_parents(root: &Path, relative: &Path) -> Result<(), LearningBundleError> {
    let mut current = root.to_owned();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(LearningBundleError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LearningBundleError::InvalidPath);
        }
        validate_read_only_directory(&metadata)?;
    }
    Ok(())
}

fn validate_read_only_directory(metadata: &fs::Metadata) -> Result<(), LearningBundleError> {
    if !metadata.is_dir() {
        return Err(LearningBundleError::InvalidPath);
    }
    require_read_only(metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(LearningBundleError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_read_only_file_metadata(
    metadata: &fs::Metadata,
    relative: &Path,
) -> Result<(), LearningBundleError> {
    if !metadata.is_file() {
        return Err(LearningBundleError::FileMismatch(
            relative.to_string_lossy().into_owned(),
        ));
    }
    require_read_only(metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(LearningBundleError::FileMismatch(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    Ok(())
}

fn require_read_only(metadata: &fs::Metadata) -> Result<(), LearningBundleError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 != 0 {
            return Err(LearningBundleError::WritableBundle);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    metadata.len()
}

fn validate_relative_path(value: &str) -> Result<PathBuf, LearningBundleError> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        return Err(LearningBundleError::InvalidPath);
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::CurDir
        ) {
            return Err(LearningBundleError::InvalidPath);
        }
    }
    Ok(path.to_owned())
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Learning bundle verification errors.
#[derive(Debug)]
pub enum LearningBundleError {
    InvalidRoot,
    InvalidPath,
    MalformedManifest,
    InvalidSignature,
    VersionMismatch,
    WritableBundle,
    BundleTooLarge,
    DuplicatePath(String),
    UnlistedPath(String),
    FileMismatch(String),
    Io(std::io::Error),
}

impl std::fmt::Display for LearningBundleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRoot => formatter.write_str("learning bundle root is invalid"),
            Self::InvalidPath => formatter.write_str("learning bundle path is invalid"),
            Self::MalformedManifest => formatter.write_str("learning bundle manifest is malformed"),
            Self::InvalidSignature => formatter.write_str("learning bundle signature is invalid"),
            Self::VersionMismatch => formatter.write_str("learning bundle version is incompatible"),
            Self::WritableBundle => formatter.write_str("learning bundle is writable"),
            Self::BundleTooLarge => formatter.write_str("learning bundle exceeds size limits"),
            Self::DuplicatePath(path) => {
                write!(formatter, "duplicate learning bundle path: {path}")
            }
            Self::UnlistedPath(path) => {
                write!(formatter, "unlisted learning bundle path: {path}")
            }
            Self::FileMismatch(path) => write!(formatter, "learning bundle file mismatch: {path}"),
            Self::Io(error) => write!(formatter, "learning bundle I/O error: {error}"),
        }
    }
}

impl std::error::Error for LearningBundleError {}

#[cfg(all(test, unix))]
#[path = "tests/learning.rs"]
mod tests;
