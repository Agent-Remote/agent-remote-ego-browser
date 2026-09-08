#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  echo "Usage: rollback-macos.sh VERSION"
  exit 0
fi
version=${1:?rollback version is required}
if [ "$(uname -s)" != "Darwin" ] || [ "$(id -u)" -eq 0 ]; then
  echo "run this user-level rollback on macOS without sudo" >&2
  exit 1
fi
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid rollback version" >&2
  exit 2
fi
install_root=${EGO_BROWSER_INSTALL_ROOT:-$HOME/Library/Application Support/Agent Remote Ego Browser}
launch_agents=${EGO_BROWSER_LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}
release="$install_root/releases/$version"
certificate_pin="$install_root/TRUSTED_CERTIFICATE_SHA256"
read_verified_certificate_pin() {
  python3 - "$1" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as error:
    raise SystemExit(f"trusted release certificate pin is unavailable: {error}") from error
with os.fdopen(descriptor, "rb") as source:
    metadata = os.fstat(source.fileno())
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise SystemExit(
            "trusted release certificate pin must be an owner-owned, singly linked 0400 regular file"
        )
    value = source.read(66)
if len(value) > 65:
    raise SystemExit("trusted release certificate pin is oversized")
sys.stdout.buffer.write(value)
PY
}
if [ ! -d "$release" ] || [ -L "$release" ] || [ ! -x "$release/bin/ego-browser-bridge" ] || \
   [ ! -x "$release/bin/ego-browser-device" ]; then
  echo "rollback release is unavailable or invalid" >&2
  exit 1
fi
expected_certificate_sha256=$(read_verified_certificate_pin "$certificate_pin")
if ! [[ "$expected_certificate_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "trusted release certificate pin is invalid" >&2
  exit 1
fi
"$release/support/verify-community-release.sh" \
  "$release" "$expected_certificate_sha256" "$version"
bridge_plist="$launch_agents/dev.agentremote.ego-browser.bridge.plist"
device_plist="$launch_agents/dev.agentremote.ego-browser.device.plist"
for plist in "$device_plist" "$bridge_plist"; do
  if [ ! -f "$plist" ] || [ -L "$plist" ]; then
    echo "rollback requires the installed user launch-agent definitions" >&2
    exit 1
  fi
done
current="$install_root/current"
if [ -e "$current" ] && [ ! -L "$current" ]; then
  echo "refusing to replace non-symlink current path" >&2
  exit 1
fi
next="$install_root/.current-rollback-$$"
trap 'rm -f -- "$next"' EXIT
ln -s "$release" "$next"
mv -fh "$next" "$current"
domain="gui/$(id -u)"
launchctl bootout "$domain" "$bridge_plist" >/dev/null 2>&1 || true
launchctl bootout "$domain" "$device_plist" >/dev/null 2>&1 || true
launchctl bootstrap "$domain" "$device_plist"
launchctl bootstrap "$domain" "$bridge_plist"
echo "activated ego-browser Bridge release $version; bindings require a fresh relay ticket and are never replayed"
