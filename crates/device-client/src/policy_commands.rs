//! Local allowlist and Site Learning command handlers.

use super::*;

pub(super) async fn allowlist(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("show") => {
            let (policy, verified) = load_verified_policy(store)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "allowlist_revision": verified.allowlist_revision,
                    "roots_digest": verified.allowlist_roots_digest,
                    "roots": policy.allowlist_roots,
                    "limits": {
                        "max_file_bytes": 64 * 1024 * 1024_u64,
                        "max_total_bytes": 256 * 1024 * 1024_u64,
                        "max_file_count": 32,
                    }
                }))?
            );
        }
        Some("set") => {
            if !args.iter().any(|value| value == "--confirm") {
                return Err(
                    "explicit --confirm is required to replace the helper allowlist".into(),
                );
            }
            let binding = option(&args, "--binding")?;
            let generation_option = option(&args, "--generation")?;
            let has_policy_auth =
                has_option(&args, "--token") || has_option(&args, "--signer-certificate-sha256");
            if binding.is_some() && has_policy_auth {
                return Err(
                    "--binding cannot be combined with policy registration credentials".into(),
                );
            }
            if binding.is_none() && generation_option.is_some() {
                return Err("--generation requires --binding".into());
            }
            let policy_transaction = store.begin_policy_update()?;
            let runtime = probe_runtime()?;
            store.load_policy(
                Some(SUPPORTED_SKILL_VERSION),
                Some(&runtime.ego_browser_version),
            )?;
            let roots = positional_paths(
                &args[1..],
                &[
                    "--binding",
                    "--generation",
                    "--token",
                    "--signer-certificate-sha256",
                ],
            )?;
            if roots.is_empty() {
                return Err("at least one allowlist root is required".into());
            }
            let update = policy_transaction.prepare_allowlist_update(roots)?;
            let verified = update.policy().verify(
                Some(SUPPORTED_SKILL_VERSION),
                Some(&runtime.ego_browser_version),
            )?;
            if let Some(binding) = binding {
                let generation = generation_option
                    .ok_or("--generation is required with --binding")?
                    .parse::<u64>()?;
                let credential = store.load(now())?;
                let identity = store.load_identity(
                    credential.device_id.clone(),
                    "community-local-trust".into(),
                    credential.credential_profile.clone(),
                )?;
                let active = match store.load_active_binding(&credential.device_id) {
                    Ok(active) => {
                        if active.binding_id != binding || active.generation != generation {
                            return Err(
                                "the requested binding does not match the active local handoff"
                                    .into(),
                            );
                        }
                        Some(active)
                    }
                    Err(CredentialError::Missing) => None,
                    Err(error) => return Err(error.into()),
                };
                let result = DeviceApiClient::with_identity(&credential, identity)?
                    .confirm_allowlist(
                        &binding,
                        generation,
                        verified
                            .allowlist_revision
                            .checked_sub(1)
                            .ok_or("allowlist revision is invalid")?,
                        verified
                            .allowlist_roots_digest
                            .as_deref()
                            .ok_or("allowlist digest is missing")?,
                    )
                    .await?;
                confirmed_allowlist_generation(
                    &result,
                    &binding,
                    &credential.device_id,
                    generation,
                    &verified,
                    active.as_ref().map(|value| value.task_space_label.as_str()),
                )?;
                store.clear_active_binding()?;
                policy_transaction.commit_policy_update(&update)?;
                if let Some(active) = active {
                    persist_active_binding(
                        store,
                        &credential.device_id,
                        &active.task_space_label,
                        &result,
                    )?;
                }
            } else {
                let credential =
                    synchronize_registered_policy(store, &args, &runtime, &verified).await?;
                if credential.is_some() {
                    // Registration pauses every live binding before returning.
                    store.clear_active_binding()?;
                }
                policy_transaction.commit_policy_update(&update)?;
                if let Some(credential) = credential {
                    store.save(&credential)?;
                }
            }
            println!(
                "helper allowlist updated to revision {}",
                update.policy().allowlist_revision
            );
        }
        _ => return Err("usage: ego-browser-device allowlist show|set ROOT... --confirm".into()),
    }
    Ok(())
}

pub(super) async fn learning(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("verify") => {
            if args.len() != 1 {
                return Err("usage: ego-browser-device learning verify".into());
            }
            let (_, policy) = load_verified_policy(store)?;
            print_learning_status(&policy)?;
        }
        Some("set") => {
            if !args.iter().any(|value| value == "--confirm") {
                return Err("explicit --confirm is required to configure a learning bundle".into());
            }
            let roots = positional_paths(&args[1..], &["--token", "--signer-certificate-sha256"])?;
            if roots.len() != 1 {
                return Err("exactly one learning bundle path is required".into());
            }
            let policy_transaction = store.begin_policy_update()?;
            let update = policy_transaction.prepare_learning_bundle_update(roots[0].clone())?;
            let runtime = probe_runtime()?;
            let verified = update.policy().verify(
                Some(SUPPORTED_SKILL_VERSION),
                Some(&runtime.ego_browser_version),
            )?;
            let credential =
                synchronize_registered_policy(store, &args, &runtime, &verified).await?;
            if credential.is_some() {
                // The Server invalidates live policy generations atomically.
                store.clear_active_binding()?;
            }
            policy_transaction.commit_policy_update(&update)?;
            if let Some(credential) = credential {
                store.save(&credential)?;
            }
            let (_, policy) = load_verified_policy(store)?;
            print_learning_status(&policy)?;
        }
        _ => return Err("usage: ego-browser-device learning verify|set BUNDLE --confirm".into()),
    }
    Ok(())
}

fn print_learning_status(policy: &VerifiedLocalPolicy) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = policy
        .learning_bundle
        .as_ref()
        .ok_or("no signed learning bundle is configured")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "digest": bundle.digest,
            "bundle_version": bundle.bundle_version,
            "skill_version": bundle.skill_version,
            "local_ego_browser_runtime_version": bundle.local_ego_browser_runtime_version,
        }))?
    );
    Ok(())
}

pub(super) fn positional_paths(
    args: &[String],
    valued_options: &[&str],
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        if valued_options.iter().any(|name| value == name) {
            if index + 1 >= args.len() {
                return Err(format!("{value} requires a value").into());
            }
            index += 2;
            continue;
        }
        if value == "--confirm" {
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            return Err(format!("unknown option: {value}").into());
        }
        paths.push(PathBuf::from(value));
        index += 1;
    }
    Ok(paths)
}
