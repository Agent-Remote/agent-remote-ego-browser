# agent-remote-ego-browser

<p align="center"><img src="assets/agent-remote-icon.svg" alt="Agent Remote icon" width="80" height="80"></p>

<p align="center">
  <a href="https://github.com/Agent-Remote/agent-remote-ego-browser/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Agent-Remote/agent-remote-ego-browser/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Agent-Remote/agent-remote-ego-browser/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Agent-Remote/agent-remote-ego-browser?style=flat&logo=github"></a>
  <img alt="Rust stable" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/github/license/Agent-Remote/agent-remote-ego-browser"></a>
</p>

English | [中文](README.zh-CN.md)

Full-trust bridge from an explicitly selected remote Agent Remote tool session to the user's existing ego lite browser on macOS.

The official remote `ego-browser` Skill keeps its normal heredoc interface. Its Linux wrapper sends each request through the Node's runtime-scoped broker and the Server's opaque relay to an outbound-only local Bridge. The Bridge then runs the script against the user's real ego lite profile.

## Release Status

`production_ready=false` and `release_published=false`.

The repository can be built, tested, packaged, and inspected, but the Server production capability must remain disabled. There is no retained Site Learning signing private key, so no release-signed learning bundle can currently satisfy the production evidence contract. Do not describe the current component as production-ready or publish it as a stable release.

## Security Warning

> A confirmed binding grants the selected remote session full-trust Node.js execution as the macOS user running the Bridge. It can access that user's files, environment, network, browser profile, login state, tabs, Task Spaces, dynamic imports, and subprocess APIs, and it can send accessible data elsewhere.

This warning applies whether the remote tool session uses the `native` or `docker_sandbox` backend. Remote runtime isolation does not sandbox code after it reaches the local Mac. A dedicated Task Space, helper-file allowlist, concurrency locks, and process supervision are workflow and lifecycle controls only. They cannot roll back side effects or contain deliberately detached same-UID processes.

The production Bridge opens no public or LAN listener. Device credentials, signing keys, browser data, and plaintext scripts remain outside the control plane; the Server relays authenticated ciphertext and stores only bounded lifecycle, compatibility, policy, and audit metadata.

## Architecture

```text
remote ego-browser Skill
        |
        v
Linux wrapper in native or docker_sandbox
        |
        v
Node runtime broker -> Server opaque WebSocket relay
        |                         |
        +-------------------------+
                                  v
                     outbound macOS Bridge
                                  |
                                  v
                      supervised ego-browser
                                  |
                                  v
                          local ego lite profile
```

| Component | Responsibility |
| --- | --- |
| Remote wrapper | Preserves the official heredoc CLI, validates bounded input, encrypts requests, and materializes bounded artifacts. |
| Node broker | Admits only the authenticated tool runtime. Native uses its dedicated UID; Docker Sandbox uses its fixed non-root runtime UID/GID plus verified mounts and numeric ACLs. |
| Server relay | Pairs the exact binding generation and forwards opaque encrypted frames. |
| Device Client | Owns independent registration, proof-of-possession keys, explicit claim confirmation, policy, rotation, and revocation. |
| Local Bridge | Maintains the outbound relay, validates leases and policy, enforces replay and concurrency controls, and supervises local processes. |
| ego lite | Retains the real browser profile and executes through the pinned local `ego-browser` runtime. |

Each request uses an X25519-wrapped ChaCha20-Poly1305 session key. Routing identity is authenticated as associated data, relay sequence numbers are persisted against replay, and disconnects, revocation, lease failure, device-peer loss, or Task Space ownership changes fail closed without replaying an unknown result.

## Compatibility

| Surface | Required value |
| --- | --- |
| Bridge, Device Client, remote wrapper | `0.1.6` |
| Protocol | `ego-browser-bridge-v1` |
| Official Skill | `1.2.3` |
| Local `ego-browser` runtime | `0.4.7.4` |
| Remote runtimes | Linux `native` and `docker_sandbox` |
| Remote targets | `amd64`/`arm64`, glibc/musl |
| Local target | macOS universal, `amd64` + `arm64` |

Compatibility is exact. Unknown, partial, or stale capabilities fail closed; there is no fallback to a remote browser, GUI-control channel, raw CDP transport, or automatically selected session.

## Install

The current unpublished build is for development and release inspection only. A future eligible macOS release is installed from its archive, strict aggregate manifest, both Sigstore bundles, and an independently obtained signing-certificate SHA-256:

```sh
./installer/install-macos.sh \
  --archive agent-remote-ego-browser-macos-universal-0.1.6.tar.gz \
  --archive-sigstore-bundle agent-remote-ego-browser-macos-universal-0.1.6.tar.gz.sigstore.json \
  --manifest agent-remote-ego-browser-0.1.6.release-manifest.json \
  --manifest-sigstore-bundle agent-remote-ego-browser-0.1.6.release-manifest.json.sigstore.json \
  --certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm-local-trust
```

The installer verifies readiness claims, tag-bound Sigstore identities, artifact inventory and digest, nested code signatures, Hardened Runtime, the leaf certificate, quarantine state, and the installed files before atomically changing `current`. It does not install, modify, or remove ego lite.

See [Installation and operations](docs/operations.md) for prerequisites, registration, policy setup, observability, recovery, and uninstall details.

## Commands

Register the independent Device Client and bind one exact running tool session:

```sh
ego-browser-device register \
  --server https://agent-remote.example.com \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

ego-browser-device candidates
ego-browser-device claim EXACT_TOOL_SESSION_ID --confirm
ego-browser-device status BINDING_ID
```

Use the normal wrapper interface from that remote session:

```sh
ego-browser <<'EOF'
const page = await useOrCreateTaskSpace('ignored-by-bound-session');
console.log(await page.snapshot());
EOF

ego-browser --doctor
ego-browser --reload
```

Manage the binding lifecycle explicitly:

```sh
ego-browser-device pause BINDING_ID --generation GENERATION
ego-browser-device resume BINDING_ID --generation GENERATION --confirm
ego-browser-device stop BINDING_ID --generation GENERATION
ego-browser-device revoke BINDING_ID --generation GENERATION
ego-browser-device device-rotate --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST --confirm
ego-browser-device device-revoke --confirm
```

Policy commands, Site Learning verification, and full recovery procedures are documented in the operations guide. No flow depends on another local device-control product.

## Development

Use a stable Rust toolchain with `rustfmt` and `clippy`. The complete local gate runs formatting, workspace clippy and tests, Python contract tests, release and installer checks, the deterministic fake-relay integration test, schema validation, and whitespace checks:

```sh
scripts/run-quality-checks.sh
```

Run the real distributed relay proof only with sibling Server and Node checkouts and a disposable Redis database:

```sh
AGENT_REMOTE_INTEGRATION_REDIS_URL=redis://127.0.0.1:6379/14 \
  bash integration-tests/real-relay-e2e.sh
```

That gate uses the real Server relay and Node broker; only the final local `ego-browser` executable is a fixture. A separate real ego lite canary remains mandatory before release-readiness changes.

## Release

Prepare a repository-owned version and rerun the complete gate:

```sh
scripts/prepare-release.sh NEXT_VERSION
scripts/run-quality-checks.sh
```

The preparation script requires a strictly newer semantic version and updates every repository-owned component-version location while leaving protocol, Skill, runtime, schema, dependency, and workflow-action compatibility versions unchanged. Tag-bound workflows produce four Linux wrapper archives and one universal macOS archive with checksums, Sigstore bundles, SPDX SBOMs, provenance, and one strict aggregate manifest.

The current workflow must continue to publish only a prerelease while `production_ready=false`. See [Release, upgrade, and rollback](docs/release.md) for the evidence profile and immutable rollback contract.

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security.md)
- [Installation and operations](docs/operations.md)
- [Release, upgrade, and rollback](docs/release.md)
- [Examples](examples/README.md)

## License

agent-remote-ego-browser is licensed under GPL-3.0-only. See [LICENSE](LICENSE).
