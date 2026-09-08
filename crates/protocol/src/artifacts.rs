use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::crypto::encode_b64url;
use crate::{ArtifactDescriptor, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_PIXELS};

/// Artifact collection limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactLimits {
    pub max_bytes: usize,
    pub max_pixels: u64,
    pub max_count: usize,
    pub max_total_bytes: usize,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_ARTIFACT_BYTES,
            max_pixels: MAX_ARTIFACT_PIXELS,
            max_count: 32,
            max_total_bytes: MAX_ARTIFACT_BYTES,
        }
    }
}

/// Collected artifact with its safe descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    pub descriptor: ArtifactDescriptor,
}

/// Collect PNG/JPEG files under a private request directory.
pub fn collect_artifacts(
    root: &Path,
    limits: ArtifactLimits,
) -> Result<Vec<Artifact>, ArtifactError> {
    if !root.is_absolute()
        || limits.max_bytes == 0
        || limits.max_bytes > MAX_ARTIFACT_BYTES
        || limits.max_pixels == 0
        || limits.max_pixels > MAX_ARTIFACT_PIXELS
        || limits.max_count == 0
        || limits.max_total_bytes == 0
        || limits.max_total_bytes > MAX_ARTIFACT_BYTES
    {
        return Err(ArtifactError::InvalidRoot);
    }
    let metadata = fs::symlink_metadata(root).map_err(ArtifactError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactError::InvalidRoot);
    }
    validate_private_directory(&metadata)?;
    let canonical_root = fs::canonicalize(root).map_err(ArtifactError::Io)?;
    let mut paths = Vec::new();
    collect_paths(&canonical_root, &canonical_root, &mut paths)?;
    paths.sort();
    let mut result = Vec::new();
    let mut total = 0_usize;
    let mut identities = Vec::new();
    for path in paths {
        if result.len() >= limits.max_count {
            return Err(ArtifactError::CountLimit);
        }
        let metadata = fs::symlink_metadata(&path).map_err(ArtifactError::Io)?;
        validate_regular_artifact(&metadata)?;
        let identity = file_identity(&metadata);
        if identities.contains(&identity) {
            return Err(ArtifactError::HardLink);
        }
        identities.push(identity);
        if metadata.len() > limits.max_bytes as u64 {
            return Err(ArtifactError::SizeLimit);
        }
        let bytes = read_bounded(&path, limits.max_bytes)?;
        let (media_type, width, height) =
            dimensions(&bytes).ok_or(ArtifactError::UnsupportedMedia)?;
        if (width as u64).saturating_mul(height as u64) > limits.max_pixels {
            return Err(ArtifactError::PixelLimit);
        }
        total = total.saturating_add(bytes.len());
        if total > limits.max_total_bytes {
            return Err(ArtifactError::TotalLimit);
        }
        result.push(Artifact {
            path,
            descriptor: ArtifactDescriptor {
                artifact_id: crate::opaque_id(),
                media_type: media_type.to_owned(),
                size_bytes: bytes.len() as u64,
                width,
                height,
                content_b64: encode_b64url(&bytes),
            },
        });
    }
    Ok(result)
}

fn collect_paths(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), ArtifactError> {
    for entry in fs::read_dir(current).map_err(ArtifactError::Io)? {
        let entry = entry.map_err(ArtifactError::Io)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(ArtifactError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactError::Symlink);
        }
        if metadata.is_dir() {
            validate_private_directory(&metadata)?;
            collect_paths(root, &path, output)?;
        } else if metadata.is_file() {
            let canonical = fs::canonicalize(&path).map_err(ArtifactError::Io)?;
            if !canonical.starts_with(root) {
                return Err(ArtifactError::OutsideRoot);
            }
            if is_candidate(&path) {
                output.push(canonical);
            }
        }
    }
    Ok(())
}

fn is_candidate(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .as_deref(),
        Some("png" | "jpg" | "jpeg")
    )
}

fn dimensions(bytes: &[u8]) -> Option<(&'static str, u32, u32)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        if width == 0 || height == 0 {
            return None;
        }
        return Some(("image/png", width, height));
    }
    if bytes.starts_with(&[0xff, 0xd8]) {
        let (width, height) = jpeg_dimensions(bytes)?;
        return Some(("image/jpeg", width, height));
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
        if index >= bytes.len() {
            return None;
        }
        let marker = bytes[index];
        index += 1;
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if index + 2 > bytes.len() {
            return None;
        }
        let length = u16::from_be_bytes(bytes[index..index + 2].try_into().ok()?) as usize;
        if length < 2 || index + length > bytes.len() {
            return None;
        }
        let is_sof = matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf);
        if is_sof && length >= 7 {
            let height = u16::from_be_bytes(bytes[index + 3..index + 5].try_into().ok()?) as u32;
            let width = u16::from_be_bytes(bytes[index + 5..index + 7].try_into().ok()?) as u32;
            if width == 0 || height == 0 {
                return None;
            }
            return Some((width, height));
        }
        index += length;
    }
    None
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ArtifactError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(ArtifactError::Io)?;
    let metadata = file.metadata().map_err(ArtifactError::Io)?;
    validate_regular_artifact(&metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len().min(maximum as u64) as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ArtifactError::Io)?;
    if bytes.len() > maximum {
        return Err(ArtifactError::SizeLimit);
    }
    Ok(bytes)
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ArtifactError::UnsafeRoot);
        }
    }
    Ok(())
}

fn validate_regular_artifact(metadata: &fs::Metadata) -> Result<(), ArtifactError> {
    if !metadata.is_file() {
        return Err(ArtifactError::InvalidFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ArtifactError::InvalidFile);
        }
        if metadata.nlink() != 1 {
            return Err(ArtifactError::HardLink);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.len(), 0)
}

/// Artifact validation errors.
#[derive(Debug)]
pub enum ArtifactError {
    InvalidRoot,
    UnsafeRoot,
    HardLink,
    Symlink,
    OutsideRoot,
    InvalidFile,
    UnsupportedMedia,
    SizeLimit,
    PixelLimit,
    TotalLimit,
    CountLimit,
    Io(std::io::Error),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidRoot => "artifact root is invalid",
            Self::UnsafeRoot => "artifact root permissions are unsafe",
            Self::HardLink => "hard-linked artifact is not allowed",
            Self::Symlink => "artifact symlink is not allowed",
            Self::OutsideRoot => "artifact escaped its root",
            Self::InvalidFile => "artifact is not a regular file",
            Self::UnsupportedMedia => "artifact is not a supported image",
            Self::SizeLimit => "artifact exceeds size limit",
            Self::PixelLimit => "artifact exceeds pixel limit",
            Self::TotalLimit => "artifacts exceed total size limit",
            Self::CountLimit => "too many artifacts",
            Self::Io(error) => return write!(formatter, "artifact I/O error: {error}"),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ArtifactError {}
