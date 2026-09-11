use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use ego_browser_bridge_protocol::{
    parse_runtime_probe_output, RuntimeProbe, PROTOCOL_VERSION, SUPPORTED_LOCAL_RUNTIME_VERSION,
    SUPPORTED_SKILL_VERSION,
};
use ego_browser_device::{
    canonical_server_url, ActiveBinding, CommunityCredential, CredentialError, CredentialStore,
    DeviceApiClient, DeviceIdentity, VerifiedLocalPolicy, FULL_TRUST_WARNING, TOKEN_MAX_BYTES,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

mod device_service;
mod policy_commands;

use device_service::service;
#[cfg(test)]
use device_service::{
    metric_event, prepare_device_service_listener, same_user_peer, serve_device_peer,
};
#[cfg(test)]
use policy_commands::positional_paths;
use policy_commands::{allowlist, learning};

const DEVICE_PEER_HEARTBEAT: &[u8] = b"EGB1\n";
const DEVICE_PEER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", top_level_error_line(error.as_ref()));
        std::process::exit(2);
    }
}

fn top_level_error_line(error: &(dyn std::error::Error + 'static)) -> String {
    let code = error
        .downcast_ref::<CredentialError>()
        .map(CredentialError::log_code)
        .unwrap_or("operation_failed");
    format!("ego-browser-device error={code}")
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    let store = CredentialStore::new(config_dir()?)?;
    match command.as_str() {
        "register" => register(&store, args.collect()).await?,
        "candidates" => {
            let credential = store.load(now())?;
            let identity = store.load_identity(
                credential.device_id.clone(),
                "community-local-trust".into(),
                credential.credential_profile.clone(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &DeviceApiClient::with_identity(&credential, identity)?
                        .candidates()
                        .await?
                )?
            );
        }
        "claim" => claim(&store, args.collect()).await?,
        "status" => status(&store, args.collect()).await?,
        "allowlist" => allowlist(&store, args.collect()).await?,
        "learning" => learning(&store, args.collect()).await?,
        "service" => service(&store).await?,
        "device-rotate" => device_rotate(&store, args.collect()).await?,
        "device-revoke" => device_revoke(&store, args.collect()).await?,
        "pause" | "resume" | "stop" | "revoke" => {
            lifecycle(&store, &command, args.collect()).await?
        }
        "help" | "--help" | "-h" => print_help(),
        _ => return Err("unknown command; use --help".into()),
    }
    Ok(())
}

mod binding_commands;
mod registration;

use binding_commands::*;
use registration::*;

fn config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::var_os("EGO_BROWSER_DEVICE_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/agent-remote-ego-browser"))
}

fn option(args: &[String], name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut result = None;
    for (index, value) in args.iter().enumerate() {
        if value != name {
            continue;
        }
        if result.is_some() {
            return Err(format!("{name} may only be supplied once").into());
        }
        let candidate = args
            .get(index + 1)
            .filter(|candidate| !candidate.starts_with('-'))
            .ok_or_else(|| format!("{name} requires a value"))?;
        result = Some(candidate.clone());
    }
    Ok(result)
}

fn has_option(args: &[String], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

fn signer_certificate_sha256(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let digest = option(args, "--signer-certificate-sha256")?
        .or_else(|| env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256").ok())
        .ok_or("--signer-certificate-sha256 is required")?
        .to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("signer certificate SHA-256 is invalid".into());
    }
    Ok(digest)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_verified_policy(
    store: &CredentialStore,
) -> Result<(ego_browser_device::LocalPolicy, VerifiedLocalPolicy), Box<dyn std::error::Error>> {
    let runtime = probe_runtime()?;
    Ok(store.load_policy(
        Some(SUPPORTED_SKILL_VERSION),
        Some(&runtime.ego_browser_version),
    )?)
}

fn probe_runtime() -> Result<RuntimeProbe, Box<dyn std::error::Error>> {
    let explicit = env::var_os("EGO_BROWSER_EXECUTABLE");
    let search_path = env::var_os("PATH");
    let home = env::var_os("HOME");
    let candidates = runtime_executable_candidates(
        explicit.as_deref(),
        search_path.as_deref(),
        home.as_deref(),
    )?;
    probe_runtime_candidates(&candidates)
}

fn runtime_executable_candidates(
    explicit: Option<&OsStr>,
    search_path: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(explicit);
        if !path.is_absolute() {
            return Err("EGO_BROWSER_EXECUTABLE must be an absolute path".into());
        }
        let mut candidates = Vec::new();
        push_runtime_candidate(&mut candidates, path);
        if candidates.is_empty() {
            return Err("ego-browser runtime is unavailable".into());
        }
        return Ok(candidates);
    }

    let mut candidates = Vec::new();
    if let Some(search_path) = search_path {
        for directory in env::split_paths(search_path) {
            if !directory.as_os_str().is_empty() {
                push_runtime_candidate(&mut candidates, directory.join("ego-browser"));
            }
        }
    }
    if let Some(home) = home.filter(|value| !value.is_empty()).map(PathBuf::from) {
        push_runtime_candidate(&mut candidates, home.join(".local/bin/ego-browser"));
        push_runtime_candidate(
            &mut candidates,
            home.join(".local/share/ego/active_version_dir/Helpers/ego-browser"),
        );
        #[cfg(target_os = "macos")]
        push_ego_lite_app_candidates(&mut candidates, &home.join("Applications/ego lite.app"));
    }
    #[cfg(target_os = "macos")]
    push_ego_lite_app_candidates(&mut candidates, Path::new("/Applications/ego lite.app"));
    Ok(candidates)
}

#[cfg(target_os = "macos")]
fn push_ego_lite_app_candidates(candidates: &mut Vec<PathBuf>, app: &Path) {
    push_runtime_candidate(
        candidates,
        app.join("Contents/Frameworks/ego Framework.framework/Versions")
            .join(SUPPORTED_LOCAL_RUNTIME_VERSION)
            .join("Helpers/ego-browser"),
    );
    push_runtime_candidate(
        candidates,
        app.join(
            "Contents/Frameworks/ego Framework.framework/Versions/Current/Helpers/ego-browser",
        ),
    );
    push_runtime_candidate(candidates, app.join("Contents/MacOS/ego-browser"));
}

fn push_runtime_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    let Ok(path) = path.canonicalize() else {
        return;
    };
    let Ok(metadata) = path.metadata() else {
        return;
    };
    if !metadata.is_file() || !metadata_is_executable(&metadata) || candidates.contains(&path) {
        return;
    }
    candidates.push(path);
}

fn metadata_is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn probe_runtime_candidates(
    candidates: &[PathBuf],
) -> Result<RuntimeProbe, Box<dyn std::error::Error>> {
    let mut probe_failed = false;
    let mut probe_malformed = false;
    let mut version_mismatched = false;
    for executable in candidates {
        let output = match std::process::Command::new(executable)
            .arg("--version")
            .env_clear()
            .output()
        {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            probe_failed = true;
            continue;
        }
        let probe = match parse_runtime_probe_output(&output.stdout, &output.stderr) {
            Ok(probe) => probe,
            Err(_) => {
                probe_malformed = true;
                continue;
            }
        };
        if probe.ego_browser_version == SUPPORTED_LOCAL_RUNTIME_VERSION {
            return Ok(probe);
        }
        version_mismatched = true;
    }
    if version_mismatched {
        Err("EGO_BROWSER_VERSION_MISMATCH: unsupported local ego-browser runtime".into())
    } else if probe_malformed {
        Err("ego-browser runtime probe is malformed".into())
    } else if probe_failed {
        Err("ego-browser runtime probe failed".into())
    } else {
        Err("ego-browser runtime is unavailable".into())
    }
}

fn print_help() {
    println!("ego-browser-device independent device client");
    println!("Usage: ego-browser-device register --server https://... [--token TOKEN | --token-stdin] --signer-certificate-sha256 HEX");
    println!("       ego-browser-device candidates");
    println!("       ego-browser-device claim TOOL_SESSION --confirm");
    println!("       ego-browser-device status [BINDING]");
    println!("       ego-browser-device allowlist show");
    println!(
        "       ego-browser-device allowlist set ROOT... --confirm [--binding ID --generation N | --token TOKEN --signer-certificate-sha256 HEX]"
    );
    println!("       ego-browser-device learning verify");
    println!(
        "       ego-browser-device learning set BUNDLE --confirm [--token TOKEN --signer-certificate-sha256 HEX]"
    );
    println!("       ego-browser-device service");
    println!("       ego-browser-device device-rotate --token TOKEN --signer-certificate-sha256 HEX --confirm");
    println!("       ego-browser-device device-revoke --confirm");
    println!("       ego-browser-device pause|stop|revoke BINDING --generation N");
    println!("       ego-browser-device resume BINDING --generation N --confirm");
    println!("Full-trust binding requires an explicit session selection and confirmation.");
}

#[cfg(all(test, unix))]
#[path = "tests/main.rs"]
mod tests;
