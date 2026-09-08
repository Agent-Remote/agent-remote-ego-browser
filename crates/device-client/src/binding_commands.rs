//! Browser binding lifecycle commands.

use super::*;

pub(super) async fn claim(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = args.first().ok_or("tool session ID is required")?;
    if !args.iter().any(|value| value == "--confirm") {
        eprintln!("{FULL_TRUST_WARNING}");
        return Err("explicit --confirm is required for full-trust binding".into());
    }
    eprintln!("{FULL_TRUST_WARNING} Task Space is a workflow convention, not a security boundary.");
    let task_space_label = format!("agent-remote:{session}");
    let credential = store.load(now())?;
    let (_, policy) = load_verified_policy(store)?;
    let identity = store.load_identity(
        credential.device_id.clone(),
        "community-local-trust".into(),
        credential.credential_profile.clone(),
    )?;
    let result = DeviceApiClient::with_identity(&credential, identity)?
        .claim(serde_json::json!({
            "tool_session_id": session,
            // The device identity is loaded from the owner-only credential store;
            // callers cannot select or substitute a different device on the CLI.
            "ego_browser_device_id": credential.device_id,
            "authorization_mode": "ego_browser_script_full_trust",
            "authorization_policy_version": 1,
            "release_profile": "community-local-trust",
            "credential_profile": "community_file",
            "remote_platform": "linux",
            "local_platform": "macos",
            "device_capabilities": policy.capabilities(),
            "allowlist_revision": policy.allowlist_revision,
            "learning_bundle_digest": policy.learning_bundle_digest(),
            "task_space_label": task_space_label,
            "user_confirmation": true
        }))
        .await?;
    persist_active_binding(store, &credential.device_id, &task_space_label, &result)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub(super) async fn status(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential = store.load(now())?;
    let identity = store.load_identity(
        credential.device_id.clone(),
        "community-local-trust".into(),
        credential.credential_profile.clone(),
    )?;
    let client = DeviceApiClient::with_identity(&credential, identity)?;
    let result = if let Some(binding) = args.first() {
        client.status(binding).await?
    } else {
        client.candidates().await?
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub(super) async fn device_revoke(
    store: &CredentialStore,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.as_slice() != ["--confirm"] {
        return Err("usage: ego-browser-device device-revoke --confirm".into());
    }
    let credential = store.load(now())?;
    let identity = store.load_identity(
        credential.device_id.clone(),
        "community-local-trust".into(),
        credential.credential_profile.clone(),
    )?;
    let result = DeviceApiClient::with_identity(&credential, identity)?
        .revoke_device()
        .await?;
    let response_device_id = result
        .pointer("/data/id")
        .and_then(serde_json::Value::as_str)
        .ok_or("device revoke response did not include an ID")?;
    let response_status = result
        .pointer("/data/status")
        .and_then(serde_json::Value::as_str)
        .ok_or("device revoke response did not include a status")?;
    if response_device_id != credential.device_id || response_status != "revoked" {
        return Err("device revoke response did not match the local device identity".into());
    }
    store.clear()?;
    println!("revoked ego-browser device {response_device_id} and removed local credentials");
    Ok(())
}

pub(super) async fn lifecycle(
    store: &CredentialStore,
    command: &str,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = args.first().ok_or("binding ID is required")?;
    let generation: u64 = option(&args, "--generation")?
        .ok_or("--generation is required")?
        .parse()?;
    let credential = store.load(now())?;
    let identity = store.load_identity(
        credential.device_id.clone(),
        "community-local-trust".into(),
        credential.credential_profile.clone(),
    )?;
    let client = DeviceApiClient::with_identity(&credential, identity)?;
    let resumed_task_space = if command == "resume" {
        Some(
            store
                .load_active_binding(&credential.device_id)?
                .task_space_label,
        )
    } else {
        None
    };
    let result = match command {
        "pause" => client.pause(binding, generation).await?,
        "resume" => {
            if !args.iter().any(|value| value == "--confirm") {
                eprintln!("{FULL_TRUST_WARNING}");
                return Err("explicit --confirm is required to resume full-trust control".into());
            }
            let (_, policy) = load_verified_policy(store)?;
            client
                .resume(
                    binding,
                    generation,
                    policy.allowlist_revision,
                    policy.learning_bundle_digest().map(str::to_owned),
                )
                .await?
        }
        "stop" => client.stop(binding, generation).await?,
        "revoke" => client.revoke(binding, generation).await?,
        _ => unreachable!(),
    };
    match command {
        "stop" | "revoke" => store.clear_active_binding()?,
        "resume" => persist_active_binding(
            store,
            &credential.device_id,
            resumed_task_space
                .as_deref()
                .ok_or("the paused binding handoff is unavailable")?,
            &result,
        )?,
        _ => {}
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub(super) fn persist_active_binding(
    store: &CredentialStore,
    device_id: &str,
    expected_task_space: &str,
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding_id = response
        .pointer("/data/id")
        .and_then(|value| value.as_str())
        .ok_or("binding response did not include an ID")?;
    let generation = response
        .pointer("/data/generation")
        .and_then(|value| value.as_u64())
        .ok_or("binding response did not include a generation")?;
    let authorization_mode = response
        .pointer("/data/authorization_mode")
        .and_then(|value| value.as_str())
        .ok_or("binding response did not include its authorization mode")?;
    let task_space_label = response
        .pointer("/data/task_space_label")
        .and_then(|value| value.as_str())
        .ok_or("binding response did not include its Task Space label")?;
    if task_space_label != expected_task_space {
        return Err("binding response did not match the selected tool session".into());
    }
    if response
        .pointer("/data/ego_browser_device_id")
        .and_then(|value| value.as_str())
        != Some(device_id)
    {
        return Err("binding response did not match the local device identity".into());
    }
    store.save_active_binding(&ActiveBinding {
        version: 1,
        binding_id: binding_id.to_owned(),
        generation,
        device_id: device_id.to_owned(),
        task_space_label: task_space_label.to_owned(),
        authorization_mode: authorization_mode.to_owned(),
        user_confirmation: true,
    })?;
    Ok(())
}
