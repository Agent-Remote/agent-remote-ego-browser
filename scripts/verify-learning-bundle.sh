#!/usr/bin/env bash
set -euo pipefail

bundle=""
expected_key_id="ego-browser-learning-2026-09"
public_key_file=""

usage() {
  cat <<'EOF'
Usage: verify-learning-bundle.sh --bundle ABSOLUTE_DIRECTORY [options]

Options:
  --key-id ID             Expected Site Learning signing key identifier.
  --public-key-file FILE  Use an explicit raw Base64 public key instead of the
                          compiled release trust anchor.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) bundle=${2:?--bundle requires a value}; shift 2 ;;
    --key-id) expected_key_id=${2:?--key-id requires a value}; shift 2 ;;
    --public-key-file) public_key_file=${2:?--public-key-file requires a value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$bundle" ] || [[ "$bundle" != /* ]]; then
  echo "learning bundle must be an absolute directory" >&2
  exit 2
fi
if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then
  echo "learning bundle must be a non-symlink directory" >&2
  exit 2
fi
if ! [[ "$expected_key_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "learning bundle key ID is invalid" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
package_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
verifier=${LEARNING_BUNDLE_VERIFIER:-}
if [ -z "$verifier" ]; then
  for candidate in \
    "$package_root/bin/ego-browser-learning-bundle" \
    "$repo_root/target/release/ego-browser-learning-bundle" \
    "$repo_root/target/x86_64-apple-darwin/release/ego-browser-learning-bundle" \
    "$repo_root/target/aarch64-apple-darwin/release/ego-browser-learning-bundle" \
    "$repo_root/target/debug/ego-browser-learning-bundle"; do
    if [ -x "$candidate" ]; then
      verifier=$candidate
      break
    fi
  done
fi
if [ -z "$verifier" ]; then
  echo "ego-browser-learning-bundle verifier is unavailable" >&2
  exit 1
fi

manifest="$bundle/manifest.json"
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
  echo "learning bundle manifest is missing or unsafe" >&2
  exit 2
fi
python3 - "$manifest" "$expected_key_id" <<'PY'
import json
import re
import sys
from pathlib import Path

path, expected_key_id = sys.argv[1:]

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SystemExit("learning bundle manifest contains duplicate fields")
        result[key] = value
    return result

value = json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)
if not isinstance(value, dict) or value.get("signing_key_id") != expected_key_id:
    raise SystemExit("learning bundle signing key ID does not match the release pin")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", expected_key_id):
    raise SystemExit("learning bundle signing key ID is invalid")
PY

arguments=(verify --bundle "$bundle")
if [ -n "$public_key_file" ]; then
  if [ ! -f "$public_key_file" ] || [ -L "$public_key_file" ]; then
    echo "learning bundle public key must be a regular file" >&2
    exit 2
  fi
  arguments+=(--public-key-file "$public_key_file")
fi

digest=$(
  "$verifier" "${arguments[@]}" |
    tr -d '[:space:]'
)
if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "learning bundle verifier returned an invalid digest" >&2
  exit 1
fi
printf '%s\n' "${digest#sha256:}"
