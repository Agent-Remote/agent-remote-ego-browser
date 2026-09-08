#!/usr/bin/env bash
set -euo pipefail

package_root=${1:?community package root is required}
expected_certificate_sha256=${2:?expected certificate SHA-256 is required}
expected_version=${3:-}

if [ "$(uname -s)" != "Darwin" ]; then
  echo "community package signature verification requires macOS" >&2
  exit 1
fi
if [ ! -d "$package_root" ] || [ -L "$package_root" ]; then
  echo "community package root must be a non-symlink directory" >&2
  exit 2
fi
package_root=$(cd "$package_root" && pwd -P)
expected_certificate_sha256=$(printf '%s' "$expected_certificate_sha256" | tr '[:upper:]' '[:lower:]')
if ! [[ "$expected_certificate_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid certificate SHA-256" >&2
  exit 2
fi

verify_binary() {
  local binary=$1 prefix actual details
  if [ ! -f "$binary" ] || [ -L "$binary" ] || [ ! -x "$binary" ]; then
    echo "signed component is missing or invalid" >&2
    exit 1
  fi
  codesign --verify --strict --verbose=2 "$binary"
  details=$(codesign --display --verbose=4 "$binary" 2>&1)
  grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' <<<"$details"
  prefix=$(mktemp "${TMPDIR:-/tmp}/ego-browser-cert.XXXXXX")
  rm -f -- "$prefix"
  codesign --display --extract-certificates "$prefix" "$binary"
  actual=$(shasum -a 256 "${prefix}0" | awk '{print $1}')
  rm -f -- "${prefix}0" "${prefix}1" "${prefix}2"
  test "$actual" = "$expected_certificate_sha256"
}

verify_binary "$package_root/bin/ego-browser-bridge"
verify_binary "$package_root/bin/ego-browser-device"
python3 - "$package_root/SIGNING-EVIDENCE.json" "$expected_certificate_sha256" "$expected_version" <<'PY'
import json
import re
import sys
from pathlib import Path

path, expected_certificate, expected_version = sys.argv[1:]
def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate signing evidence field")
        result[key] = value
    return result

value = json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)
required = {
    "schema_version", "version", "profile", "production_ready", "readiness_blockers",
    "apple_notarized", "public_distribution", "signing_type", "signer_certificate_sha256",
    "bridge_signature_verified", "device_client_signature_verified", "nested_signatures_verified",
    "hardened_runtime", "outbound_policy", "credential_profile", "learning_bundle_digest",
    "learning_bundle_signing_key_id",
}
if not isinstance(value, dict) or set(value) != required:
    raise SystemExit("signing evidence fields are invalid")
if (
    value["schema_version"] != 1
    or not isinstance(value["version"], str)
    or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z.-]+)?", value["version"])
    or (expected_version and value["version"] != expected_version)
    or value["profile"] != "community-local-trust"
    or not isinstance(value["production_ready"], bool)
    or not isinstance(value["readiness_blockers"], list)
    or len(value["readiness_blockers"]) != len(set(value["readiness_blockers"]))
    or any(not isinstance(item, str) or not item for item in value["readiness_blockers"])
    or value["apple_notarized"] is not False
    or value["public_distribution"] is not False
    or value["signing_type"] != "project-self-signed"
    or value["signer_certificate_sha256"] != expected_certificate
    or value["bridge_signature_verified"] is not True
    or value["device_client_signature_verified"] is not True
    or value["nested_signatures_verified"] is not True
    or value["hardened_runtime"] is not True
    or value["outbound_policy"] != "application-enforced"
    or value["credential_profile"] != "community_file"
    or not isinstance(value["learning_bundle_signing_key_id"], str)
    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["learning_bundle_signing_key_id"]) is None
):
    raise SystemExit("signing evidence is incompatible or overstates readiness")
digest = value["learning_bundle_digest"]
if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("learning bundle digest is invalid")
if value["production_ready"]:
    if value["readiness_blockers"] or digest is None:
        raise SystemExit("production-ready signing evidence lacks a learning bundle")
else:
    if "learning_bundle_signing_private_key_unavailable" not in value["readiness_blockers"] or digest is not None:
        raise SystemExit("false readiness must retain the learning signing blocker")
PY

signing_digest=$(python3 - "$package_root/SIGNING-EVIDENCE.json" <<'PY'
import json
import sys
value = json.loads(open(sys.argv[1], encoding="utf-8").read())
print(value["learning_bundle_digest"] or "")
PY
)
if [ -n "$signing_digest" ]; then
  if [ ! -d "$package_root/learning-bundle" ] || [ -L "$package_root/learning-bundle" ]; then
    echo "production-ready package is missing its learning bundle" >&2
    exit 1
  fi
  verified_digest=$(LEARNING_BUNDLE_VERIFIER=${LEARNING_BUNDLE_VERIFIER:-} \
    "$package_root/support/verify-learning-bundle.sh" \
    --bundle "$package_root/learning-bundle" \
    --key-id "$(python3 - "$package_root/SIGNING-EVIDENCE.json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["learning_bundle_signing_key_id"])
PY
)")
  if [ "$verified_digest" != "$signing_digest" ]; then
    echo "packaged learning bundle digest does not match signing evidence" >&2
    exit 1
  fi
elif [ -e "$package_root/learning-bundle" ] || [ -L "$package_root/learning-bundle" ]; then
  echo "blocked package must not carry an unbound learning bundle" >&2
  exit 1
fi
