#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
script="$root/scripts/install.sh"

test -x "$script"
bash -n "$script"

help_output=$(bash "$script" --help)
for expected in \
  "curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-ego-browser/main/scripts/install.sh" \
  "--confirm-local-trust" \
  "--confirm-full-trust" \
  "--certificate-sha256" \
  "--archive-sigstore-bundle" \
  "--manifest-sigstore-bundle" \
  "--skip-ego-lite" \
  "--session-id"; do
  grep -F -- "$expected" <<<"$help_output" >/dev/null
done

python3 - "$script" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
required_fragments = (
    'DEFAULT_CERTIFICATE_SHA256="1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5"',
    'EGO_LITE_INSTALL_SCRIPT_COMMIT="36053d07001a910cb806a15d42d00fdea1cdea3d"',
    'EGO_LITE_INSTALL_SCRIPT_SHA256="7a4c307c9a8ee6abae094f7cd497a81992de81e1fc37719fde61c43fd841d057"',
    'cosign',
    'cosign verify-blob',
    'validate_archive_paths',
    'verify_release_inputs',
    'installer/install-macos.sh',
    '--confirm-local-trust',
    'claim "$SESSION_ID" --confirm',
    'EGO_BROWSER_RELEASE_REPOSITORY="$REPOSITORY"',
    'EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" register',
    'CONFIRM_FULL_TRUST',
)
for fragment in required_fragments:
    if fragment not in source:
        raise SystemExit(f"install script is missing required contract: {fragment}")

# A session claim must remain tied to an explicitly supplied ID and confirmation.
claim_guard = 'if [ -n "$SESSION_ID" ]; then'
if claim_guard not in source or 'CONFIRM_FULL_TRUST' not in source:
    raise SystemExit("full-trust claim guard is missing")
PY

echo "one-click install script contract passed"

# Exercise the bootstrap path with a local, deterministic archive.  The fake
# Darwin tools let this run on Linux without downloading a release or touching
# the user's launch agents.
work=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-install-script-test.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/package/installer" "$work/fake-bin" "$work/install-root"

# The generated fixture must expand its own positional parameters at runtime.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
  'if [ -n "${FAKE_INSTALL_LOG:-}" ]; then printf "%s\n" "$*" > "$FAKE_INSTALL_LOG"; fi' \
  'if [ -n "${FAKE_DEVICE_LOG:-}" ]; then' \
  '  mkdir -p "$EGO_BROWSER_INSTALL_ROOT/current/bin"' \
  '  printf "%s\n" "#!/bin/sh" '\''printf "%s|%s\\n" "$EGO_BROWSER_EXECUTABLE" "$*" >> "$FAKE_DEVICE_LOG"'\'' > "$EGO_BROWSER_INSTALL_ROOT/current/bin/ego-browser-device"' \
  '  chmod 0755 "$EGO_BROWSER_INSTALL_ROOT/current/bin/ego-browser-device"' \
  'fi' \
  >"$work/package/installer/install-macos.sh"
chmod 0755 "$work/package/installer/install-macos.sh"
printf '%s\n' '#!/bin/sh' \
  'printf "ego-browser 0.4.7.4\\n"' \
  'printf "  chromium 150\\n"' \
  'printf "  node v24\\n"' >"$work/runtime"
chmod 0755 "$work/runtime"
printf '%s\n' '#!/bin/sh' 'printf "Darwin\\n"' >"$work/fake-bin/uname"
printf '%s\n' '#!/bin/sh' 'printf "501\\n"' >"$work/fake-bin/id"
# Keep the host Homebrew path from shadowing the deterministic fake cosign.
printf '%s\n' '#!/bin/sh' 'exit 1' >"$work/fake-bin/brew"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' '[ "${FAKE_COSIGN_FAIL:-0}" = 1 ] && exit 1' 'exit 0' >"$work/fake-bin/cosign"
chmod 0755 "$work/fake-bin/uname" "$work/fake-bin/id" "$work/fake-bin/brew" "$work/fake-bin/cosign"

printf '%s\n' '0.1.9' >"$work/package/VERSION"
printf '%s\n' 'fixture' >"$work/package/LICENSE"
printf '%s\n' 'fixture' >"$work/archive.sigstore.json"
printf '%s\n' 'fixture' >"$work/manifest.sigstore.json"
tar -C "$work/package" -czf "$work/archive.tar.gz" installer VERSION LICENSE
if command -v shasum >/dev/null 2>&1; then
  archive_digest=$(shasum -a 256 "$work/archive.tar.gz" | awk '{print $1}')
else
  archive_digest=$(sha256sum "$work/archive.tar.gz" | awk '{print $1}')
fi
archive_size=$(stat -f '%z' "$work/archive.tar.gz" 2>/dev/null || stat -c '%s' "$work/archive.tar.gz")
printf '%s\n' "{\"version\":\"0.1.9\",\"component\":\"agent-remote-ego-browser\",\"local_platform\":\"macos\",\"signer_certificate_sha256\":\"1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5\",\"artifacts\":[{\"name\":\"agent-remote-ego-browser-macos-universal-0.1.9.tar.gz\",\"kind\":\"macos_local_components\",\"sha256\":\"$archive_digest\",\"size_bytes\":$archive_size}]}" \
  >"$work/manifest.json"

# A failed preflight must not execute the installer extracted from the archive.
marker="$work/should-not-run"
if FAKE_COSIGN_FAIL=1 FAKE_INSTALL_LOG="$marker" \
  PATH="$work/fake-bin:/usr/bin:/bin" \
  bash "$script" \
    --archive "$work/archive.tar.gz" \
    --archive-sigstore-bundle "$work/archive.sigstore.json" \
    --manifest "$work/manifest.json" \
    --manifest-sigstore-bundle "$work/manifest.sigstore.json" \
    --ego-browser "$work/runtime" \
    --install-root "$work/install-root" \
    --skip-dependency-install --skip-ego-lite --no-start --confirm-local-trust \
    >"$work/preflight-output" 2>&1; then
  echo "bootstrap accepted a failed release preflight" >&2
  exit 1
fi
test ! -e "$marker"
echo "one-click install preflight guard passed"

FAKE_INSTALL_LOG="$work/invocation.log" \
PATH="$work/fake-bin:/usr/bin:/bin" \
  bash "$script" \
    --archive "$work/archive.tar.gz" \
    --archive-sigstore-bundle "$work/archive.sigstore.json" \
    --manifest "$work/manifest.json" \
    --manifest-sigstore-bundle "$work/manifest.sigstore.json" \
    --ego-browser "$work/runtime" \
    --install-root "$work/install-root" \
    --skip-dependency-install --skip-ego-lite --no-start --confirm-local-trust \
    >"$work/output" 2>&1

grep -F -- "one-click installation completed" "$work/output" >/dev/null
grep -F -- "--confirm-local-trust" "$work/invocation.log" >/dev/null
echo "one-click install local-archive smoke passed"

device_log="$work/device.log"
runtime_real="$(cd "$(dirname "$work/runtime")" && pwd -P)/$(basename "$work/runtime")"
FAKE_DEVICE_LOG="$device_log" \
FAKE_INSTALL_LOG="$work/registration-invocation.log" \
PATH="$work/fake-bin:/usr/bin:/bin" \
  bash "$script" \
    --archive "$work/archive.tar.gz" \
    --archive-sigstore-bundle "$work/archive.sigstore.json" \
    --manifest "$work/manifest.json" \
    --manifest-sigstore-bundle "$work/manifest.sigstore.json" \
    --ego-browser "$work/runtime" \
    --install-root "$work/registered-install-root" \
    --skip-dependency-install --skip-ego-lite --no-start --confirm-local-trust \
    --server https://example.invalid --token test-token \
    >"$work/registration-output" 2>&1
grep -F -- "$runtime_real|register" "$device_log" >/dev/null
grep -F -- "$runtime_real|candidates" "$device_log" >/dev/null
if grep -F -- '|claim ' "$device_log" >/dev/null; then
  echo "bootstrap claimed a session without an explicit session ID" >&2
  exit 1
fi
echo "one-click install registration smoke passed"
