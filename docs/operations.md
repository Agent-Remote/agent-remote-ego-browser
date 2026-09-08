# Installation and Operations

## Prerequisites

- macOS with a logged-in GUI user and ego lite already installed
- a remote Claude session using an eligible Linux `native` or `docker_sandbox`
  runtime backend with the verified wrapper, Skill, broker mount, identity, and ACL contract
- the official local `ego-browser` runtime version `0.4.7.4`
- an HTTPS Agent Remote Server origin and a user registration token
- `cosign`, `python3`, `plutil`, `launchctl`, `codesign`, and standard macOS tools
- the release archive, release manifest, and both Sigstore bundles
- the expected project signing-certificate SHA-256 from a separately trusted channel

The installer does not install, modify, or remove ego lite.

## Verify and install

```sh
./installer/install-macos.sh \
  --archive agent-remote-ego-browser-macos-universal-0.1.7.tar.gz \
  --archive-sigstore-bundle agent-remote-ego-browser-macos-universal-0.1.7.tar.gz.sigstore.json \
  --manifest agent-remote-ego-browser-0.1.7.release-manifest.json \
  --manifest-sigstore-bundle agent-remote-ego-browser-0.1.7.release-manifest.json.sigstore.json \
  --certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm-local-trust
```

Use `--ego-browser /absolute/path/to/ego-browser` when it is not on `PATH`, or
`--no-start` to install without bootstrapping launch agents. The installer:

1. strictly validates manifest shape and readiness claims;
2. verifies manifest and archive Sigstore identities for the exact release tag;
3. verifies archive digest, inventory, paths, and runtime compatibility;
4. verifies both macOS binaries, Hardened Runtime, and leaf certificate pin;
5. installs immutable files below `~/Library/Application Support/Agent Remote Ego Browser/releases/VERSION`;
6. clears and rechecks quarantine, then verifies the installed release again;
7. writes the protected certificate pin, atomically changes `current`, and installs user launch agents.

## Register and bind

```sh
current="$HOME/Library/Application Support/Agent Remote Ego Browser/current"

"$current/bin/ego-browser-device" register \
  --server https://agent-remote.example.com \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

"$current/bin/ego-browser-device" candidates
"$current/bin/ego-browser-device" claim EXACT_TOOL_SESSION_ID --confirm
"$current/bin/ego-browser-device" status BINDING_ID
```

Registration tokens are command-line input for this initial operation and
should be short-lived. Device Client output never prints the stored replacement
credential or private key. Claim always requires an exact candidate and the
explicit full-trust confirmation. The Server derives
`agent-remote:<tool_session_id>`; the Device Client rejects a different label in
the response and stores the canonical value in the owner-only active-binding
handoff. Resume validates the same label again while advancing the generation.

Rotate the device signing and encryption keys in place with a fresh user token:

```sh
"$current/bin/ego-browser-device" device-rotate \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm
```

Stop active work before rotation. The Device Client preserves the device ID,
creates generation `N+1`, persists its new keys to the owner-only
`ego-browser-device-key.pending.bin` before sending anything, and signs the
registration proof with that new generation. The Server atomically revokes old
bindings and credentials when it accepts the keys. Only an exact, newer Server
response is committed locally; that commit replaces the key and credential,
clears the prior active-binding handoff, and removes the pending file. If the
request, response, or local commit is interrupted, rerun the same command with
a fresh user token. The pending file deliberately reuses the exact generation
and keys so the operation can converge without creating another identity.

## Helper allowlist and Site Learning

```sh
"$current/bin/ego-browser-device" allowlist show
"$current/bin/ego-browser-device" allowlist set /canonical/upload/root \
  --confirm --binding BINDING_ID --generation GENERATION

# Use this form after registration when no binding-scoped CAS is requested.
"$current/bin/ego-browser-device" allowlist set /canonical/upload/root \
  --confirm --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

"$current/bin/ego-browser-device" learning verify
"$current/bin/ego-browser-device" learning set /absolute/signed/bundle \
  --confirm --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST
```

An allowlist update is a compare-and-swap against the current revision when a
binding is supplied. That form and the user-token form are mutually exclusive;
an exact paused response with the next binding generation is required before
the Device Client commits the local policy and replaces its handoff.

Before initial registration, allowlist and learning commands configure local
policy without user-token options. After registration, a policy change without
a binding-scoped allowlist CAS requires a fresh user registration token and the
pinned signing-certificate digest. The Device Client re-registers the same
device identity and key generation with new-key PoP. The Server pauses every
live binding, invalidates old permits, and issues a higher-revision credential.
Only a response matching every submitted version, digest, capability, profile,
certificate, identity, key, and generation is accepted; then the client clears
the active handoff, commits policy, and saves that credential. An interrupted
local commit can be retried with another fresh user token and the same command.

A learning bundle must be read-only, correctly signed, hash complete, and
pinned to Skill `1.2.3` and runtime `0.4.7.4`.

No retained learning-bundle private key currently exists, so a production
learning bundle cannot be issued and `production_ready` remains false.

## Lifecycle and diagnosis

```sh
"$current/bin/ego-browser-device" status BINDING_ID
"$current/bin/ego-browser-device" pause BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" resume BINDING_ID --generation GENERATION --confirm
"$current/bin/ego-browser-device" stop BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" revoke BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" device-revoke --confirm

launchctl print "gui/$(id -u)/dev.agentremote.ego-browser.device"
launchctl print "gui/$(id -u)/dev.agentremote.ego-browser.bridge"
tail -n 100 "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/bridge.log"
tail -n 100 "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/device.log"
```

Remote diagnosis is `ego-browser --doctor`. `ego-browser --reload` asks the
Bridge to clear runtime connection state; it never creates or reauthorizes a
binding. Logs intentionally omit scripts and browser content.

The Device Client sends a fixed heartbeat to the Bridge every two seconds. The
Bridge verifies the same-UID socket and peer, requires an initial heartbeat,
and treats five seconds without a valid heartbeat as authorization loss. It
first revokes local execution, then clears the active-binding handoff, and only
then attempts a generation-bound Server stop for at most ten seconds. A failed
or timed-out stop confirmation does not restore local execution.

The Bridge also runs one independent ownership monitor after the binding is
active. It uses only ego lite's native `listTaskSpaces()` ownership data and arms after it
has observed the canonical space as `agent` owned. A later
`agentDelegatedToUser` or `user` value revokes admission, terminates managed
executions, and then requests a generation-bound pause with reason
`task_space_takeover`. An unexpected monitor failure follows the same order
with `task_space_monitor_unavailable`. Neither helper exceptions nor parsing
script stderr drive this path, and the Bridge never calls claim or takeover
automatically. Resume must be explicitly confirmed; use ego lite's native
`takeOverTaskSpace('agent-remote:<tool_session_id>')` workflow only after the
user has chosen to return control. If the pause call cannot be confirmed, keep
the Bridge stopped and inspect Server state before any fresh authorization.

## Metrics and alerts

Bridge and Device Client logs contain JSON metric events. They are the canonical
local source; there is no local Prometheus endpoint. A collector must attach
`component=bridge` or `component=device_client` from the launch-agent identity,
not from untrusted event text.

| Source | Metric | Finite labels |
| --- | --- | --- |
| Bridge | `ego_browser_execute_total`, `ego_browser_execute_duration_seconds`, `ego_browser_bytes_total` | `status={completed,script_error,timeout,cancelled,bridge_unavailable,ego_runtime_unavailable,lease_expired,binding_revoked,protocol_error,artifact_error,concurrency_conflict,lease_renewal_required,unknown_result}`; bytes add `direction={request,response}`. |
| Bridge | `ego_browser_artifacts_total` | The same status plus `media_type={image/png,image/jpeg,other}`. |
| Device Client | `ego_browser_device_service_up` | `status={ready,stopped}`. |
| Device Client | `ego_browser_device_bridge_peers` | `status={connected,disconnected}` and current peer count. |
| Device Client | `ego_browser_device_peer_total` | `status=rejected`. |
| Device Client | `ego_browser_device_refresh_total` | `status={completed,unregistered,identity_unavailable,client_unavailable,control_plane_error}`. |

Inspect only parseable metric lines:

```sh
jq -R -c 'fromjson? | select(.event == "metric") |
  {metric,status,direction,media_type,value}' \
  "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/bridge.log"

jq -R -c 'fromjson? | select(.event == "metric") |
  {metric,status,value}' \
  "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/device.log"
```

Never add a user, device, tool-session, binding, generation, request, URL,
filename, local path, script, page, input, output, or artifact identifier as a
metric label. Alert on any `unknown_result`; service-up zero or absence; an
unexpected peer drop while a binding is active; three consecutive metadata
refresh failures (about 60 seconds); repeated lease/runtime unavailability; or
an unusual timeout, protocol, artifact, or rejected-peer rate.

## Cross-repository gates

The normal repository gate uses a deterministic fake relay. The mandatory real
control-plane relay gate requires sibling Server and Node checkouts plus a
disposable Redis database:

```sh
AGENT_REMOTE_INTEGRATION_REDIS_URL=redis://127.0.0.1:6379/14 \
  bash integration-tests/real-relay-e2e.sh
```

It starts the actual TLS Server WebSocket route, Redis ticket/pairing state,
Node broker, remote wrapper, Device Client heartbeat service, and outbound
Bridge. Only the final local `ego-browser` executable is fake. It proves three
encrypted rounds, an ownership transition, external takeover termination,
the `task_space_takeover` pause and explicit resume generation, a later
in-flight stop, descendant termination, replay ledger rows, delivered outbox
state, and content-free metrics. Its caught helper-error request deliberately
remains alive until the independent ownership transition stops it. Run the
separate real ego lite canary before changing release readiness; neither gate
alone is a substitute for the other.

## Recovery

- `bridge_unavailable`: register locally if needed, list candidates, and claim
  the exact session. Do not create a temporary or automatic binding.
- `lease_renewal_required` or `lease_expired`: stop the old generation, inspect
  Server/Bridge health, then resume with the current generation and confirm
  full trust again.
- `binding_revoked`: create a new explicit claim. Revoked bindings do not resume.
- `unknown_result`: observe current browser state before deciding what to do;
  never replay the original heredoc automatically.
- runtime/version mismatch: install the exact compatible versions. There is no
  fallback to a remote browser, GUI-control channel, or raw network tunnel.
- local takeover: verify the binding is `paused` with
  `stop_reason=task_space_takeover`, inspect current browser state, explicitly
  resume the returned generation, and only then use ego lite's native takeover helper
  to return ownership to the agent. Never replay the interrupted request.
- `task_space_monitor_unavailable`: keep admission closed, repair the local
  runtime/Bridge service, inspect current browser state and Server generation,
  then explicitly resume. Do not bypass the monitor or synthesize ownership.
- relay loss: the managed process is killed. Reconnect and resume only after
  confirming the browser's current state.
- Device Client heartbeat loss: keep the local binding handoff cleared, verify
  both launch agents and Server outbox convergence, then create a fresh explicit
  generation. Do not reuse the prior local handoff or relay ticket.

For routine key rotation, use `device-rotate` as described above; do not revoke
and recreate the device. If the whole device is compromised or must be retired,
use `ego-browser-device device-revoke --confirm`, then register a new device
only after the Server confirms revocation. Signing-certificate rotation is a
separate release operation and is never implicit: publish and authorize a
reviewed dual-certificate window before changing the locally pinned digest.

## Uninstall

```sh
"$current/installer/uninstall-macos.sh"
"$current/installer/uninstall-macos.sh" --remove-releases
"$current/installer/uninstall-macos.sh" \
  --remove-releases --purge-credentials --confirm-purge
```

The default removes launch agents and the `current` link. Credential deletion
requires the second explicit confirmation. `--remove-releases` removes only the
Bridge release tree. An independently installed `ego-browser` executable, ego
lite, and its browser profile are not changed.
