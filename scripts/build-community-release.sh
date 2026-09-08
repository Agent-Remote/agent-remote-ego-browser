#!/usr/bin/env bash
set -euo pipefail
# Without a verified learning bundle, the generated manifest remains production_ready=false.

if [ "$(uname -s)" != "Darwin" ]; then
  echo "community-local-trust components must be built on macOS" >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${VERSION:-$(tr -d '[:space:]' < "$repo_root/VERSION")}
signing_identity=${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}
expected_certificate_sha256=${SIGNER_CERTIFICATE_SHA256:?SIGNER_CERTIFICATE_SHA256 is required}
out_dir=${OUT_DIR:-$repo_root/dist/community-release}
learning_bundle_root=${LEARNING_BUNDLE_ROOT:-}
learning_bundle_digest=${LEARNING_BUNDLE_DIGEST:-}
learning_bundle_key_id=${LEARNING_BUNDLE_SIGNING_KEY_ID:-ego-browser-learning-2026-09}

if [ "$version" != "$(tr -d '[:space:]' < "$repo_root/VERSION")" ]; then
  echo "VERSION does not match the immutable source version" >&2
  exit 1
fi
if ! [[ "$expected_certificate_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "SIGNER_CERTIFICATE_SHA256 must contain 64 hexadecimal characters" >&2
  exit 2
fi
expected_certificate_sha256=$(printf '%s' "$expected_certificate_sha256" | tr '[:upper:]' '[:lower:]')
if ! [[ "$learning_bundle_key_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "LEARNING_BUNDLE_SIGNING_KEY_ID is invalid" >&2
  exit 2
fi
if [ -n "$learning_bundle_digest" ]; then
  learning_bundle_digest=${learning_bundle_digest#sha256:}
  if ! [[ "$learning_bundle_digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "LEARNING_BUNDLE_DIGEST must contain 64 hexadecimal characters" >&2
    exit 2
  fi
  learning_bundle_digest=$(printf '%s' "$learning_bundle_digest" | tr '[:upper:]' '[:lower:]')
fi
if [ -n "$learning_bundle_digest" ] && [ -z "$learning_bundle_root" ]; then
  echo "LEARNING_BUNDLE_ROOT is required when LEARNING_BUNDLE_DIGEST is set" >&2
  exit 2
fi
if [ -n "$learning_bundle_root" ] && [[ "$learning_bundle_root" != /* ]]; then
  echo "LEARNING_BUNDLE_ROOT must be an absolute path" >&2
  exit 2
fi

for target in x86_64-apple-darwin aarch64-apple-darwin; do
  rustup target add "$target"
  cargo build --locked --release --target "$target" -p ego-browser-bridge -p ego-browser-device
  cargo build --locked --release --target "$target" \
    -p ego-browser-bridge-protocol --bin ego-browser-learning-bundle
done

staging="$out_dir/package"
rm -rf -- "$staging"
mkdir -p "$staging/bin" "$staging/installer" "$staging/support"
for binary in ego-browser-bridge ego-browser-device ego-browser-learning-bundle; do
  lipo -create \
    "$repo_root/target/x86_64-apple-darwin/release/$binary" \
    "$repo_root/target/aarch64-apple-darwin/release/$binary" \
    -output "$staging/bin/$binary"
  chmod 0555 "$staging/bin/$binary"
  codesign --force --sign "$signing_identity" --options runtime --timestamp=none \
    "$staging/bin/$binary"
done

verify_binary() {
  local binary=$1 certificate_prefix actual details
  codesign --verify --strict --verbose=2 "$binary"
  details=$(codesign --display --verbose=4 "$binary" 2>&1)
  grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' <<<"$details"
  certificate_prefix=$(mktemp "${TMPDIR:-/tmp}/ego-browser-cert.XXXXXX")
  rm -f -- "$certificate_prefix"
  codesign --display --extract-certificates="$certificate_prefix" "$binary"
  actual=$(shasum -a 256 "${certificate_prefix}0" | awk '{print $1}')
  rm -f -- "${certificate_prefix}0" "${certificate_prefix}1" "${certificate_prefix}2"
  if [ "$actual" != "$expected_certificate_sha256" ]; then
    echo "signer certificate fingerprint does not match release pin" >&2
    exit 1
  fi
}

verify_binary "$staging/bin/ego-browser-bridge"
verify_binary "$staging/bin/ego-browser-device"
verify_binary "$staging/bin/ego-browser-learning-bundle"
install -m 0444 "$repo_root/VERSION" "$staging/VERSION"
install -m 0444 "$repo_root/LICENSE" "$staging/LICENSE"
install -m 0555 "$repo_root/installer/install-macos.sh" "$staging/installer/install-macos.sh"
install -m 0555 "$repo_root/installer/uninstall-macos.sh" "$staging/installer/uninstall-macos.sh"
install -m 0555 "$repo_root/installer/rollback-macos.sh" "$staging/installer/rollback-macos.sh"
install -m 0555 "$repo_root/scripts/release_manifest.py" "$staging/support/release_manifest.py"
install -m 0555 "$repo_root/scripts/clear_verified_quarantine.py" \
  "$staging/support/clear_verified_quarantine.py"
install -m 0555 "$repo_root/scripts/verify-community-release.sh" \
  "$staging/support/verify-community-release.sh"
install -m 0555 "$repo_root/scripts/verify-learning-bundle.sh" \
  "$staging/support/verify-learning-bundle.sh"
install -m 0444 "$repo_root/protocol/schemas/release-manifest.schema.json" \
  "$staging/support/release-manifest.schema.json"

if [ -n "$learning_bundle_root" ]; then
  if [ ! -d "$learning_bundle_root" ] || [ -L "$learning_bundle_root" ]; then
    echo "LEARNING_BUNDLE_ROOT must be a non-symlink directory" >&2
    exit 2
  fi
  verified_digest=$(LEARNING_BUNDLE_VERIFIER="" \
    "$repo_root/scripts/verify-learning-bundle.sh" \
    --bundle "$learning_bundle_root" --key-id "$learning_bundle_key_id")
  if [ -n "$learning_bundle_digest" ] && [ "$verified_digest" != "$learning_bundle_digest" ]; then
    echo "LEARNING_BUNDLE_DIGEST does not match the verified bundle" >&2
    exit 1
  fi
  learning_bundle_digest=$verified_digest
  ditto "$learning_bundle_root" "$staging/learning-bundle"
  python3 - "$staging/learning-bundle" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
required = {root / "manifest.json", root / "learnings"}
if not all(path.exists() and not path.is_symlink() for path in required):
    raise SystemExit("packaged learning bundle is incomplete")
for path in [root, *root.rglob("*")]:
    if path.is_symlink():
        raise SystemExit("packaged learning bundle contains a symlink")
    mode = path.stat().st_mode
    if path.is_file() and not stat.S_ISREG(mode):
        raise SystemExit("packaged learning bundle contains a non-regular file")
    if mode & 0o222:
        raise SystemExit("packaged learning bundle is writable")
PY
else
  if [ -n "$learning_bundle_digest" ]; then
    echo "learning bundle digest cannot be set without a bundle" >&2
    exit 2
  fi
fi

python3 - "$staging/SIGNING-EVIDENCE.json" "$version" "$expected_certificate_sha256" \
  "$learning_bundle_digest" "$learning_bundle_key_id" <<'PY'
import json
import sys
from pathlib import Path

output, version, certificate, learning_digest, learning_key_id = sys.argv[1:]
# The no-bundle path is deliberately emitted as "production_ready": false.
production_ready = bool(learning_digest)
value = {
    "schema_version": 1,
    "version": version,
    "profile": "community-local-trust",
    "production_ready": production_ready,
    "readiness_blockers": [] if production_ready else ["learning_bundle_signing_private_key_unavailable"],
    "apple_notarized": False,
    "public_distribution": False,
    "signing_type": "project-self-signed",
    "signer_certificate_sha256": certificate,
    "bridge_signature_verified": True,
    "device_client_signature_verified": True,
    "nested_signatures_verified": True,
    "hardened_runtime": True,
    "outbound_policy": "application-enforced",
    "credential_profile": "community_file",
    "learning_bundle_digest": learning_digest or None,
    "learning_bundle_signing_key_id": learning_key_id,
}
Path(output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
chmod 0444 "$staging/SIGNING-EVIDENCE.json"
printf '%s\n' "$staging"
