use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical_json;
use crate::{MAX_ALLOWLISTED_FILE_BYTES, MAX_ALLOWLISTED_FILE_COUNT, MAX_ALLOWLISTED_TOTAL_BYTES};

/// Limits for helper file operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowlistLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_file_count: usize,
}

impl Default for AllowlistLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_ALLOWLISTED_FILE_BYTES,
            max_total_bytes: MAX_ALLOWLISTED_TOTAL_BYTES,
            max_file_count: MAX_ALLOWLISTED_FILE_COUNT,
        }
    }
}

/// Canonical absolute roots explicitly confirmed by the user.
#[derive(Clone, Debug)]
pub struct Allowlist {
    roots: Vec<PathBuf>,
    root_identities: Vec<FileIdentity>,
    revision: u64,
    limits: AllowlistLimits,
}

impl Allowlist {
    /// Build an allowlist after canonicalizing every existing root.
    pub fn new(
        roots: impl IntoIterator<Item = PathBuf>,
        revision: u64,
        limits: AllowlistLimits,
    ) -> Result<Self, AllowlistError> {
        if revision == 0 {
            return Err(AllowlistError::InvalidRevision);
        }
        if limits.max_file_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_file_count == 0
            || limits.max_file_bytes > MAX_ALLOWLISTED_FILE_BYTES
            || limits.max_total_bytes > MAX_ALLOWLISTED_TOTAL_BYTES
            || limits.max_file_count > MAX_ALLOWLISTED_FILE_COUNT
        {
            return Err(AllowlistError::InvalidLimits);
        }
        let mut canonical_roots = Vec::new();
        for root in roots {
            let canonical = canonical_existing_directory(&root)?;
            if !canonical_roots.iter().any(|(path, _)| path == &canonical) {
                let metadata = fs::metadata(&canonical).map_err(AllowlistError::Io)?;
                canonical_roots.push((canonical, file_identity(&metadata)));
            }
        }
        if canonical_roots.is_empty() {
            return Err(AllowlistError::Empty);
        }
        canonical_roots.sort_by(|left, right| left.0.cmp(&right.0));
        let (roots, root_identities) = canonical_roots.into_iter().unzip();
        Ok(Self {
            roots,
            root_identities,
            revision,
            limits,
        })
    }

    /// Return the user-confirmed monotonic revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Return canonical roots for diagnostics (never a secret-bearing payload).
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Return the digest of the canonical, sorted root list.
    pub fn roots_digest(&self) -> Result<String, AllowlistError> {
        let roots = self
            .roots
            .iter()
            .map(|root| {
                root.to_str()
                    .map(|value| Value::String(value.to_owned()))
                    .ok_or(AllowlistError::InvalidPath)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes =
            canonical_json(&Value::Array(roots)).map_err(|_| AllowlistError::InvalidPath)?;
        let digest = Sha256::digest(bytes);
        Ok(format!("sha256:{digest:x}"))
    }

    /// Validate and open a regular input file without following symlinks.
    pub fn open_input(
        &self,
        path: &Path,
        request_total: u64,
        request_count: usize,
    ) -> Result<ValidatedInputFile, AllowlistError> {
        self.check_request_budget(request_total, request_count)?;
        let canonical = self.canonical_target(path, false)?;
        let (root, root_identity, relative) = self.relative_to_root(&canonical)?;
        let file = open_beneath(root, root_identity, relative, false, false)?;
        let metadata = file.metadata().map_err(AllowlistError::Io)?;
        validate_regular_file(&metadata)?;
        if metadata.len() > self.limits.max_file_bytes {
            return Err(AllowlistError::FileTooLarge);
        }
        if request_total.saturating_add(metadata.len()) > self.limits.max_total_bytes {
            return Err(AllowlistError::TotalTooLarge);
        }
        let canonical_metadata = fs::metadata(&canonical).map_err(AllowlistError::Io)?;
        if !same_file(&metadata, &canonical_metadata) {
            return Err(AllowlistError::ChangedDuringOpen);
        }
        // Re-canonicalize after opening to make replacement races fail closed.
        let reopened = fs::canonicalize(path).map_err(AllowlistError::Io)?;
        if reopened != canonical {
            return Err(AllowlistError::ChangedDuringOpen);
        }
        Ok(ValidatedInputFile {
            path: canonical,
            size_bytes: metadata.len(),
            file,
        })
    }

    /// Validate an output target and its existing parent directory.
    pub fn validate_output(
        &self,
        path: &Path,
        request_total: u64,
        request_count: usize,
        expected_size: u64,
    ) -> Result<ValidatedOutputPath, AllowlistError> {
        self.check_request_budget(request_total, request_count)?;
        if expected_size > self.limits.max_file_bytes
            || request_total.saturating_add(expected_size) > self.limits.max_total_bytes
        {
            return Err(AllowlistError::FileTooLarge);
        }
        let parent = path.parent().ok_or(AllowlistError::InvalidPath)?;
        let canonical_parent = self.canonical_existing_directory(parent)?;
        let name = path.file_name().ok_or(AllowlistError::InvalidPath)?;
        if name.to_string_lossy().is_empty() {
            return Err(AllowlistError::InvalidPath);
        }
        let candidate = canonical_parent.join(name);
        let target_identity = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(AllowlistError::Symlink);
                }
                validate_regular_file(&metadata)?;
                if link_count(&metadata) != 1 {
                    return Err(AllowlistError::HardLink);
                }
                Some(file_identity(&metadata))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(AllowlistError::Io(error)),
        };
        if !self.in_root(&candidate) {
            return Err(AllowlistError::OutsideRoot);
        }
        let (root, root_identity, relative_parent) = self.relative_to_root(&canonical_parent)?;
        let parent_handle = open_beneath_directory(root, root_identity, relative_parent)?;
        let parent_metadata = parent_handle.metadata().map_err(AllowlistError::Io)?;
        Ok(ValidatedOutputPath {
            path: candidate,
            target_identity,
            root_path: root.to_owned(),
            root_identity,
            relative_parent: relative_parent.to_owned(),
            parent_identity: file_identity(&parent_metadata),
            file_name: name.to_owned(),
        })
    }

    fn check_request_budget(&self, total: u64, count: usize) -> Result<(), AllowlistError> {
        if count >= self.limits.max_file_count {
            return Err(AllowlistError::FileCountTooLarge);
        }
        if total > self.limits.max_total_bytes {
            return Err(AllowlistError::TotalTooLarge);
        }
        Ok(())
    }

    fn canonical_target(
        &self,
        path: &Path,
        allow_missing: bool,
    ) -> Result<PathBuf, AllowlistError> {
        reject_path_components(path)?;
        let canonical = if allow_missing {
            let parent = path.parent().ok_or(AllowlistError::InvalidPath)?;
            self.canonical_existing_directory(parent)?
                .join(path.file_name().ok_or(AllowlistError::InvalidPath)?)
        } else {
            fs::canonicalize(path).map_err(AllowlistError::Io)?
        };
        if !self.in_root(&canonical) {
            return Err(AllowlistError::OutsideRoot);
        }
        Ok(canonical)
    }

    fn canonical_existing_directory(&self, path: &Path) -> Result<PathBuf, AllowlistError> {
        let canonical = canonical_existing_directory(path)?;
        if !self.in_root(&canonical) && !self.roots.iter().any(|root| root == &canonical) {
            return Err(AllowlistError::OutsideRoot);
        }
        Ok(canonical)
    }

    fn in_root(&self, path: &Path) -> bool {
        self.roots
            .iter()
            .any(|root| path == root || path.starts_with(root))
    }

    fn relative_to_root<'a>(
        &'a self,
        path: &'a Path,
    ) -> Result<(&'a Path, FileIdentity, &'a Path), AllowlistError> {
        let (index, root) = self
            .roots
            .iter()
            .enumerate()
            .filter(|(_, root)| path == root.as_path() || path.starts_with(root))
            .max_by_key(|(_, root)| root.components().count())
            .ok_or(AllowlistError::OutsideRoot)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| AllowlistError::OutsideRoot)?;
        Ok((root, self.root_identities[index], relative))
    }
}

/// Opened, validated regular input file.
pub struct ValidatedInputFile {
    pub path: PathBuf,
    pub size_bytes: u64,
    file: File,
}

impl ValidatedInputFile {
    /// Read the bounded file contents.
    pub fn read_to_end(self) -> Result<Vec<u8>, AllowlistError> {
        let mut bytes = Vec::with_capacity(self.size_bytes as usize);
        self.file
            .take(self.size_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(AllowlistError::Io)?;
        if bytes.len() as u64 != self.size_bytes {
            return Err(AllowlistError::ChangedDuringOpen);
        }
        Ok(bytes)
    }
}

/// Validated output destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedOutputPath {
    pub path: PathBuf,
    target_identity: Option<FileIdentity>,
    root_path: PathBuf,
    root_identity: FileIdentity,
    relative_parent: PathBuf,
    parent_identity: FileIdentity,
    file_name: OsString,
}

impl ValidatedOutputPath {
    /// Return a unique untrusted-download path inside the validated parent.
    pub fn staging_path(&self, token: &str) -> Result<PathBuf, AllowlistError> {
        Ok(self
            .path
            .parent()
            .ok_or(AllowlistError::InvalidPath)?
            .join(staging_name(token)?))
    }

    /// Open the validated destination for a bounded replacement.
    pub fn open_for_write(&self, replace: bool) -> Result<File, AllowlistError> {
        let parent = self.open_parent()?;
        let existing = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(AllowlistError::Io(error)),
        };
        if let Some(metadata) = existing.as_ref() {
            if metadata.file_type().is_symlink() {
                return Err(AllowlistError::Symlink);
            }
            validate_regular_file(metadata)?;
            if link_count(metadata) != 1 {
                return Err(AllowlistError::HardLink);
            }
            if !replace {
                return Err(AllowlistError::ChangedDuringOpen);
            }
            if self.target_identity.is_none() {
                return Err(AllowlistError::ChangedDuringOpen);
            }
            if self
                .target_identity
                .is_some_and(|identity| identity != file_identity(metadata))
            {
                return Err(AllowlistError::ChangedDuringOpen);
            }
        } else if self.target_identity.is_some() {
            return Err(AllowlistError::ChangedDuringOpen);
        }

        let file = open_output_at(&parent, &self.file_name, existing.is_none())?;
        let opened = file.metadata().map_err(AllowlistError::Io)?;
        validate_regular_file(&opened)?;
        if link_count(&opened) != 1 {
            return Err(AllowlistError::HardLink);
        }
        let current = fs::symlink_metadata(&self.path).map_err(AllowlistError::Io)?;
        if current.file_type().is_symlink() || !same_file(&opened, &current) {
            return Err(if current.file_type().is_symlink() {
                AllowlistError::Symlink
            } else {
                AllowlistError::ChangedDuringOpen
            });
        }
        if let Some(expected) = self.target_identity {
            if expected != file_identity(&opened) {
                return Err(AllowlistError::ChangedDuringOpen);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(AllowlistError::Io)?;
        }
        if replace {
            // Truncate only the already-open, single-link inode.
            file.set_len(0).map_err(AllowlistError::Io)?;
        }
        Ok(file)
    }

    /// Atomically replace the destination from already bounded in-memory bytes.
    pub fn replace_atomically(&self, bytes: &[u8], token: &str) -> Result<(), AllowlistError> {
        let parent = self.open_parent()?;
        self.validate_target_at(&parent)?;
        let temporary_name = commit_name(token)?;
        let mut temporary = open_output_at(&parent, &temporary_name, true)?;
        let temporary_identity = file_identity(&temporary.metadata().map_err(AllowlistError::Io)?);
        let result = (|| {
            temporary.write_all(bytes).map_err(AllowlistError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                temporary
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(AllowlistError::Io)?;
            }
            temporary.sync_all().map_err(AllowlistError::Io)?;
            self.validate_target_at(&parent)?;
            rename_at(&parent, &temporary_name, &self.file_name)?;
            parent.sync_all().map_err(AllowlistError::Io)?;
            let installed = open_output_at(&parent, &self.file_name, false)?;
            let metadata = installed.metadata().map_err(AllowlistError::Io)?;
            validate_regular_file(&metadata)?;
            if file_identity(&metadata) != temporary_identity {
                return Err(AllowlistError::ChangedDuringOpen);
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = unlink_at(&parent, &temporary_name);
        }
        result
    }

    /// Remove only this operation's fixed incoming path, without following it.
    pub fn remove_staging(&self, token: &str) -> Result<(), AllowlistError> {
        let parent = self.open_parent()?;
        unlink_at(&parent, &staging_name(token)?)
    }

    fn open_parent(&self) -> Result<File, AllowlistError> {
        let parent =
            open_beneath_directory(&self.root_path, self.root_identity, &self.relative_parent)?;
        let metadata = parent.metadata().map_err(AllowlistError::Io)?;
        if file_identity(&metadata) != self.parent_identity {
            return Err(AllowlistError::ChangedDuringOpen);
        }
        Ok(parent)
    }

    fn validate_target_at(&self, parent: &File) -> Result<(), AllowlistError> {
        match inspect_output_at(parent, &self.file_name)? {
            None if self.target_identity.is_none() => Ok(()),
            Some(metadata) => {
                validate_regular_file(&metadata)?;
                if self.target_identity == Some(file_identity(&metadata)) {
                    Ok(())
                } else {
                    Err(AllowlistError::ChangedDuringOpen)
                }
            }
            None => Err(AllowlistError::ChangedDuringOpen),
        }
    }
}

/// File allowlist validation errors.
#[derive(Debug)]
pub enum AllowlistError {
    Empty,
    InvalidRevision,
    InvalidLimits,
    InvalidPath,
    OutsideRoot,
    ParentMissing,
    Symlink,
    HardLink,
    NonRegular,
    FileTooLarge,
    TotalTooLarge,
    FileCountTooLarge,
    ChangedDuringOpen,
    Io(std::io::Error),
}

impl std::fmt::Display for AllowlistError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Empty => "allowlist is empty",
            Self::InvalidRevision => "allowlist revision is invalid",
            Self::InvalidLimits => "allowlist limits are invalid",
            Self::InvalidPath => "path is invalid",
            Self::OutsideRoot => "path is outside the allowlist",
            Self::ParentMissing => "parent directory is missing",
            Self::Symlink => "symlink path is not allowed",
            Self::HardLink => "hard-linked file is not allowed",
            Self::NonRegular => "only regular files are allowed",
            Self::FileTooLarge => "file exceeds the allowlist limit",
            Self::TotalTooLarge => "request exceeds the total file limit",
            Self::FileCountTooLarge => "request exceeds the file count limit",
            Self::ChangedDuringOpen => "file changed while being validated",
            Self::Io(error) => return write!(formatter, "file validation I/O error: {error}"),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AllowlistError {}

mod allowlist_fs;

use allowlist_fs::*;

#[cfg(all(test, unix))]
#[path = "tests/allowlist.rs"]
mod tests;
