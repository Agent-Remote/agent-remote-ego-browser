use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ego_browser_bridge_protocol::{
    verify_learning_bundle, LearningBundleManifest, LearningFile, PROTOCOL_VERSION,
    SUPPORTED_LOCAL_RUNTIME_VERSION, SUPPORTED_SKILL_VERSION, TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY,
};
use sha2::{Digest, Sha256};

const MAX_KEY_BYTES: u64 = 4096;
const MAX_FILES: usize = 4096;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("ego-browser-learning-bundle: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = if args.is_empty() {
        "help".to_owned()
    } else {
        args.remove(0)
    };
    match command.as_str() {
        "manifest" => manifest_command(&args),
        "sign" => sign_command(&args),
        "verify" => verify_command(&args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => Err("unknown command; use --help".into()),
    }
}

fn manifest_command(args: &[String]) -> Result<(), String> {
    let root = canonical_bundle_root(required_path(args, "--bundle")?)?;
    let manifest = build_manifest(
        &root,
        required(args, "--bundle-version")?,
        required(args, "--signing-key-id")?,
    )?;
    let bytes = pretty_manifest(&manifest)?;
    if let Some(output) = option(args, "--output") {
        let output = absolute_path(&output)?;
        if output.starts_with(&root) {
            return Err("unsigned manifest output must be outside the bundle root".into());
        }
        write_new_file(&output, &bytes, 0o600)?;
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn sign_command(args: &[String]) -> Result<(), String> {
    let root = canonical_bundle_root(required_path(args, "--bundle")?)?;
    let key_path = required_path(args, "--private-key-file")?;
    let key = load_signing_key(&key_path)?;
    let mut manifest = build_manifest(
        &root,
        required(args, "--bundle-version")?,
        required(args, "--signing-key-id")?,
    )?;
    manifest.signature = STANDARD.encode(
        key.sign(&manifest.signed_bytes().map_err(|error| error.to_string())?)
            .to_bytes(),
    );
    let manifest_path = root.join("manifest.json");
    if fs::symlink_metadata(&manifest_path).is_ok() {
        return Err(
            "manifest.json already exists; remove it explicitly before offline signing".into(),
        );
    }
    atomic_write(&manifest_path, &pretty_manifest(&manifest)?, 0o600)?;
    make_bundle_read_only(&root)?;

    if let Some(output) = option(args, "--public-key-output") {
        let output = absolute_path(&output)?;
        if output.starts_with(&root) {
            return Err("public key output must be outside the bundle root".into());
        }
        let encoded = format!("{}\n", STANDARD.encode(key.verifying_key().to_bytes()));
        write_new_file(&output, encoded.as_bytes(), 0o644)?;
    }
    let digest = verify_learning_bundle(
        &root,
        &key.verifying_key().to_bytes(),
        SUPPORTED_SKILL_VERSION,
        SUPPORTED_LOCAL_RUNTIME_VERSION,
    )
    .map_err(|error| error.to_string())?;
    println!("{digest}");
    Ok(())
}

fn verify_command(args: &[String]) -> Result<(), String> {
    let root = canonical_bundle_root(required_path(args, "--bundle")?)?;
    let key = match option(args, "--public-key-file") {
        Some(path) => load_verifying_key(&PathBuf::from(path))?,
        None => VerifyingKey::from_bytes(&TRUSTED_LEARNING_BUNDLE_PUBLIC_KEY)
            .map_err(|_| "embedded learning bundle public key is invalid".to_owned())?,
    };
    let skill = option(args, "--skill-version").unwrap_or_else(|| SUPPORTED_SKILL_VERSION.into());
    let runtime =
        option(args, "--runtime-version").unwrap_or_else(|| SUPPORTED_LOCAL_RUNTIME_VERSION.into());
    let digest = verify_learning_bundle(&root, &key.to_bytes(), &skill, &runtime)
        .map_err(|error| error.to_string())?;
    println!("{digest}");
    Ok(())
}

fn build_manifest(
    root: &Path,
    bundle_version: String,
    signing_key_id: String,
) -> Result<LearningBundleManifest, String> {
    validate_token(&bundle_version, "bundle version")?;
    validate_token(&signing_key_id, "signing key ID")?;
    let files = collect_files(root)?;
    if files.is_empty() {
        return Err("learning bundle contains no payload files".into());
    }
    Ok(LearningBundleManifest {
        bundle_version,
        skill_version: SUPPORTED_SKILL_VERSION.into(),
        local_ego_browser_runtime_version: SUPPORTED_LOCAL_RUNTIME_VERSION.into(),
        protocol_versions: vec![PROTOCOL_VERSION.into()],
        files,
        signing_key_id,
        signature: String::new(),
    })
}

fn collect_files(root: &Path) -> Result<Vec<LearningFile>, String> {
    let learning_root = root.join("learnings");
    let metadata = fs::symlink_metadata(&learning_root)
        .map_err(|_| "bundle must contain a learnings directory".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("learnings must be a non-symlink directory".into());
    }
    let mut pending = vec![learning_root];
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "learning bundle contains symlink: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "learning path escaped bundle root".to_owned())?;
                validate_relative(relative)?;
                let text = relative
                    .to_str()
                    .ok_or_else(|| "learning path is not UTF-8".to_owned())?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if !paths.insert(text) {
                    return Err("duplicate learning path".into());
                }
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| "learning bundle size overflow".to_owned())?;
                if paths.len() > MAX_FILES || total > MAX_TOTAL_BYTES {
                    return Err("learning bundle exceeds file or byte limits".into());
                }
            } else {
                return Err(format!(
                    "learning bundle contains non-regular entry: {}",
                    path.display()
                ));
            }
        }
    }
    paths
        .into_iter()
        .map(|relative| {
            let path = root.join(&relative);
            let mut bytes = Vec::new();
            OpenOptions::new()
                .read(true)
                .open(&path)
                .and_then(|mut file| file.read_to_end(&mut bytes))
                .map_err(|error| error.to_string())?;
            Ok(LearningFile {
                path: relative,
                size_bytes: bytes.len() as u64,
                sha256: hex_digest(&bytes),
            })
        })
        .collect()
}

fn canonical_bundle_root(path: PathBuf) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("bundle root must be absolute".into());
    }
    reject_symlink_components(&path)?;
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if canonical != path {
        return Err("bundle root must already be canonical".into());
    }
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("bundle root must be a non-symlink directory".into());
    }
    Ok(canonical)
}

fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err("path contains a symlink".into());
            }
        }
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), String> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::RootDir
            )
        })
    {
        return Err("learning bundle path is invalid".into());
    }
    Ok(())
}

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = read_key_file(path, true)?;
    let decoded = decode_key(&bytes)?;
    Ok(SigningKey::from_bytes(&decoded.try_into().map_err(
        |_| "Ed25519 private key must contain exactly 32 bytes".to_owned(),
    )?))
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes = read_key_file(path, false)?;
    let decoded = decode_key(&bytes)?;
    VerifyingKey::from_bytes(
        &decoded
            .try_into()
            .map_err(|_| "Ed25519 public key must contain exactly 32 bytes".to_owned())?,
    )
    .map_err(|_| "Ed25519 public key is invalid".into())
}

fn read_key_file(path: &Path, private: bool) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("key file path must be absolute".into());
    }
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_KEY_BYTES {
        return Err("key path must be a small regular file".into());
    }
    #[cfg(unix)]
    if private
        && (metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0)
    {
        return Err(
            "private key file must be owner-only, singly linked, and owned by the current UID"
                .into(),
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err("key file exceeds size limit".into());
    }
    Ok(bytes)
}

fn decode_key(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() == 32 {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "key file must contain raw bytes or base64".to_owned())?
        .trim();
    STANDARD
        .decode(text)
        .or_else(|_| URL_SAFE_NO_PAD.decode(text))
        .map_err(|_| "key file base64 is invalid".into())
}

fn make_bundle_read_only(root: &Path) -> Result<(), String> {
    let mut directories = vec![root.to_owned()];
    let mut all_directories = Vec::new();
    while let Some(directory) = directories.pop() {
        all_directories.push(directory.clone());
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err("learning bundle contains a symlink".into());
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if metadata.is_file() {
                #[cfg(unix)]
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                    .map_err(|error| error.to_string())?;
            } else {
                return Err("learning bundle contains a non-regular entry".into());
            }
        }
    }
    all_directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    #[cfg(unix)]
    for directory in all_directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "output path has no parent".to_owned())?;
    let temporary = parent.join(format!(".manifest.json.tmp-{}", std::process::id()));
    let result = (|| {
        write_new_file(&temporary, bytes, mode)?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn pretty_manifest(manifest: &LearningBundleManifest) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    option(args, name).ok_or_else(|| format!("{name} is required"))
}

fn required_path(args: &[String], name: &str) -> Result<PathBuf, String> {
    required(args, name).map(PathBuf::from)
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn absolute_path(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("output path must be absolute".into());
    }
    reject_symlink_components(path.parent().unwrap_or(Path::new("/")))?;
    Ok(path)
}

fn validate_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn print_help() {
    println!("Offline Site Learning bundle tool");
    println!("Usage:");
    println!("  ego-browser-learning-bundle manifest --bundle ABSOLUTE_PATH --bundle-version VERSION --signing-key-id ID [--output ABSOLUTE_PATH]");
    println!("  ego-browser-learning-bundle sign --bundle ABSOLUTE_PATH --bundle-version VERSION --signing-key-id ID --private-key-file ABSOLUTE_PATH [--public-key-output ABSOLUTE_PATH]");
    println!("  ego-browser-learning-bundle verify --bundle ABSOLUTE_PATH [--public-key-file ABSOLUTE_PATH]");
    println!("Private keys are accepted only from an explicit owner-only file; environment and stdin key input are unsupported.");
}
