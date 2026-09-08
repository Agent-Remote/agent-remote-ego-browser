//! Local bridge arguments internals.

use super::*;

pub(super) fn parse_args() -> Result<BridgeArgs, BridgeError> {
    let mut socket = env::var_os("EGO_BROWSER_BRIDGE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("agent-remote-ego-browser.sock"));
    let mut credential_dir = env::var_os("EGO_BROWSER_DEVICE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".config/agent-remote-ego-browser"))
        })
        .ok_or_else(|| BridgeError::ProtocolMessage("HOME is not set".into()))?;
    let mut config = BridgeConfig::from_environment();
    let mut requested_transport =
        env::var("EGO_BROWSER_BRIDGE_MODE")
            .ok()
            .and_then(|value| match value.as_str() {
                "outbound" | "production" => Some(TransportMode::Outbound),
                "unix" | "socket" | "development" => Some(TransportMode::UnixSocket),
                _ => None,
            });
    let mut once = env::var("EGO_BROWSER_BRIDGE_ONCE")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = PathBuf::from(next_arg(&mut args, "--socket")?);
            }
            "--ego-browser" => {
                config.executable = PathBuf::from(next_arg(&mut args, "--ego-browser")?);
            }
            "--work-root" => {
                config.work_root = PathBuf::from(next_arg(&mut args, "--work-root")?);
            }
            "--binding-id" => {
                config.binding_id = next_arg(&mut args, "--binding-id")?;
            }
            "--generation" => {
                config.generation = next_arg(&mut args, "--generation")?
                    .parse()
                    .map_err(|_| BridgeError::ProtocolMessage("invalid generation".into()))?;
            }
            "--credential-dir" => {
                // This path is only used to locate the owner-only Device Client
                // store; it is never passed to the browser child process.
                credential_dir = PathBuf::from(next_arg(&mut args, "--credential-dir")?);
                if !credential_dir.is_absolute() {
                    return Err(BridgeError::ProtocolMessage(
                        "credential directory must be absolute".into(),
                    ));
                }
            }
            "--release-profile" => {
                config.release_profile =
                    parse_release_profile(&next_arg(&mut args, "--release-profile")?)?;
            }
            "--credential-profile" => {
                config.credential_profile =
                    parse_credential_profile(&next_arg(&mut args, "--credential-profile")?)?;
            }
            "--outbound" => requested_transport = Some(TransportMode::Outbound),
            "--unix-socket" | "--development" => {
                requested_transport = Some(TransportMode::UnixSocket)
            }
            "--once" => once = true,
            "--help" | "-h" => {
                println!(
                    "Usage: ego-browser-bridge [--outbound | --unix-socket] [--socket PATH] [--ego-browser PATH] [--work-root PATH] [--binding-id ID] [--generation N]"
                );
                println!("       --credential-dir PATH --once");
                std::process::exit(0);
            }
            _ => {
                return Err(BridgeError::ProtocolMessage(format!(
                    "unsupported argument: {arg}"
                )))
            }
        }
    }
    let transport = requested_transport.unwrap_or_else(|| {
        if is_production_profile(config.release_profile) {
            TransportMode::Outbound
        } else {
            TransportMode::UnixSocket
        }
    });
    if is_production_profile(config.release_profile) && transport == TransportMode::UnixSocket {
        return Err(BridgeError::ProtocolMessage(
            "production Bridge profiles require outbound transport".into(),
        ));
    }
    Ok(BridgeArgs {
        socket,
        credential_dir,
        config,
        transport,
        once,
    })
}

fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, BridgeError> {
    args.next()
        .ok_or_else(|| BridgeError::ProtocolMessage(format!("{name} requires a value")))
}

fn parse_release_profile(value: &str) -> Result<ReleaseProfile, BridgeError> {
    match value {
        "logic-test" | "logic_test" => Ok(ReleaseProfile::LogicTest),
        "development-local" | "development_local" => Ok(ReleaseProfile::DevelopmentLocal),
        "community-local-trust" | "community_local_trust" => {
            Ok(ReleaseProfile::CommunityLocalTrust)
        }
        "developer-id" | "developer_id" => Ok(ReleaseProfile::DeveloperId),
        _ => Err(BridgeError::ProtocolMessage(
            "invalid release profile".into(),
        )),
    }
}

fn parse_credential_profile(value: &str) -> Result<CredentialProfile, BridgeError> {
    match value {
        "community-file" | "community_file" => Ok(CredentialProfile::CommunityFile),
        "keychain-access-group" | "keychain_access_group" => {
            Ok(CredentialProfile::KeychainAccessGroup)
        }
        _ => Err(BridgeError::ProtocolMessage(
            "invalid credential profile".into(),
        )),
    }
}

fn is_production_profile(profile: ReleaseProfile) -> bool {
    matches!(
        profile,
        ReleaseProfile::CommunityLocalTrust | ReleaseProfile::DeveloperId
    )
}
