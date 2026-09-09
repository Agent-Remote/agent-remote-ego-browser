# Release, Upgrade, and Rollback

## Evidence profile

Release `0.1.7` targets `community-local-trust`:

| Claim | Required value |
| --- | --- |
| Signing | `project-self-signed` |
| Hardened Runtime | `true` |
| Nested signatures verified | `true` |
| Outbound policy | `application-enforced` |
| Credential profile | `community_file` |
| Apple notarized | `false` |
| Public distribution | `false` |
| Production ready | `true` |
| Learning bundle digest | `6662ad11797f86d721b2d9121049c35b02eff3e71821dc06dfcc190d250788a7` |
| Learning bundle signing key | `ego-browser-learning-2026-09` |
| Readiness blockers | `[]` |

The persistent project certificate and its SHA-256 are CI environment inputs;
they are not generated per build. GitHub Actions signs release assets with
keyless Sigstore identity tied to `release.yml@refs/tags/vVERSION`, publishes
SPDX SBOMs and provenance attestations. The workflow publishes a stable release
only when the generated manifest is production-ready with no blockers;
otherwise it publishes a prerelease. Release `0.1.7` passed this component gate
and its stable GitHub release is recorded as published by the certified root
composition.

## Preparing a release

```sh
scripts/prepare-release.sh NEXT_VERSION
scripts/run-quality-checks.sh
```

The prepare script requires a strictly newer semantic version. It updates the
workspace version, all repository package entries in `Cargo.lock`, `VERSION`,
the protocol capability vector, and every English/Chinese compatibility and
installer example owned by this repository. It rejects stale source values and
any existing changelog heading before writing, adds the dated changelog entry,
leaves dependency, schema, Skill, runtime, and workflow-action versions
unchanged, and finishes with locked workspace validation. The official workflow
commits those files, creates immutable tag `vVERSION`, and dispatches the
tag-bound release workflow.

The release produces four Linux wrapper archives and one universal macOS local
component archive. Each artifact has a checksum, Sigstore bundle, SPDX SBOM,
and provenance. The aggregate strict release manifest binds their exact names,
sizes, digests, versions, platforms, release claims, and signing certificate.

## Upgrade

1. Disable new claims if compatibility has not yet been canaried.
2. Publish and verify the new Server and Node releases first.
3. Install the immutable Node wrapper/Skill pair for the same compatibility row.
4. Download the macOS archive, aggregate manifest, and both Sigstore bundles.
5. Confirm the expected certificate digest through a separate trusted channel.
6. Run `install-macos.sh`; it preserves old release directories and atomically
   changes `current` only after complete verification.
7. Restarted launch agents wait for registration and explicit binding instead
   of crash-looping or auto-binding.
8. Reconfirm full trust, create a fresh generation, and run `--doctor` plus a
   single-user canary. Old permits and requests are never replayed.

Compatibility is exact: wrapper/Bridge/Device Client `0.1.7`, protocol
`ego-browser-bridge-v1`, Skill `1.2.3`, and local runtime `0.4.7.4`. Unknown or
partial capabilities fail closed. There is no browser or transport fallback.

## Rollback

At the control plane, disable new browser claims, revoke active bindings, wait
for the 10-second maximum renewal grace plus managed-process cleanup, and
confirm that the Node broker has no active permits. Then on the Mac:

```sh
current="$HOME/Library/Application Support/Agent Remote Ego Browser/current"
"$current/installer/rollback-macos.sh" PREVIOUS_VERSION
```

Rollback validates the target release against the protected certificate pin
and validates both installed launch-agent definitions before changing
`current`. It then boots both agents. The selected release does not inherit an
old relay ticket, generation, or request; the user must create a fresh explicit
authorization. Preserve terminal binding and audit metadata, and do not perform
a destructive schema downgrade.

If a new release changes the signing certificate, the standard installer
refuses the implicit rotation. A certificate change requires a reviewed
dual-certificate control-plane window, explicit local trust confirmation, a
new signed manifest, revocation of the retired pin, and a new binding
generation.

## Remaining rollout gates

Release `0.1.7` has complete `community-local-trust` component evidence. That
does not imply Apple notarization, public-distribution approval, or deployment
to a production environment. Keep the Server capability disabled until the
exact certified root bundle is installed and verified and the real ego lite
single-user canary succeeds. Future releases must independently reproduce the
signed Site Learning bundle and every readiness claim before being published as
stable.
