# Changelog

All notable changes to this repository are recorded here.

## Unreleased

## 0.1.7 - 2026-09-08

- ci: commit every source updated by release preparation (9128ae3)
- docs: align release sources with v0.1.6 (3078d1e)
- chore: release v0.1.7 (ade046b)

## 0.1.6 - 2026-09-08

- fix(installer): parse the real ego-browser version output (25c12c6)
- test: initialize fake macOS commands before probing the runtime (785548f)
- test: provide a portable ditto fixture (7fbcdab)
- test: emulate macOS installer utilities on Linux (c1ca131)

## 0.1.5 - 2026-09-09

- fix(release): carry the resolved Site Learning key ID into the aggregate manifest (c0a5a74)

## 0.1.4 - 2026-09-09

- fix(release): discover target-specific learning-bundle verifier binaries (583f0b2)

## 0.1.3 - 2026-09-09

- security: rotate the Site Learning bundle trust anchor (3e02e4b)

## 0.1.2 - 2026-09-09

- fix: use portable macOS signing-certificate extraction (2ec5f42)

## 0.1.1 - 2026-09-09

- fix: verify wrapper checksums from the release directory (35cd700)

## 0.1.0 - 2026-09-09

- feat: implement the independent ego-browser Bridge protocol, Linux wrapper,
  local supervisor, and Device Client.
- feat: add explicit binding, policy, replay protection, bounded artifacts, and
  Site Learning verification.
- build: add immutable macOS and Linux packaging, verification, installation,
  rollback, SBOM, provenance, and release-manifest tooling.
- test: cover the Rust components, release contracts, learning bundles, installers,
  and fake/real relay paths.
