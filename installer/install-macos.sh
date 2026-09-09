#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
archive=""
manifest=""
manifest_sigstore_bundle=""
archive_sigstore_bundle=""
expected_certificate_sha256=""
ego_browser_path=""
release_repository="${EGO_BROWSER_RELEASE_REPOSITORY:-Agent-Remote/agent-remote-ego-browser}"
confirmed=0
start_agents=1

usage() {
  cat <<'EOF'
Usage: install-macos.sh --archive FILE --archive-sigstore-bundle FILE \
  --manifest FILE --manifest-sigstore-bundle FILE \
  --certificate-sha256 HEX --confirm-local-trust [options]

Options:
  --ego-browser PATH   Canonical local ego-browser runtime path.
  --no-start           Install launch agents without bootstrapping them.

Environment:
  EGO_BROWSER_RELEASE_REPOSITORY  GitHub OWNER/REPO used for the tag-bound Sigstore identity.

This installs only the independent ego-browser Bridge and Device Client for the
current macOS user. It never installs, changes, or removes ego lite itself.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive) archive=${2:?--archive requires a value}; shift 2 ;;
    --manifest) manifest=${2:?--manifest requires a value}; shift 2 ;;
    --manifest-sigstore-bundle) manifest_sigstore_bundle=${2:?--manifest-sigstore-bundle requires a value}; shift 2 ;;
    --archive-sigstore-bundle) archive_sigstore_bundle=${2:?--archive-sigstore-bundle requires a value}; shift 2 ;;
    --certificate-sha256) expected_certificate_sha256=${2:?--certificate-sha256 requires a value}; shift 2 ;;
    --ego-browser) ego_browser_path=${2:?--ego-browser requires a value}; shift 2 ;;
    --confirm-local-trust) confirmed=1; shift ;;
    --no-start) start_agents=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "the local Bridge installer supports macOS only" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "run this user-level installer without sudo" >&2
  exit 1
fi
if [ "$confirmed" -ne 1 ]; then
  echo "--confirm-local-trust is required: this is project-self-signed, not Apple notarized, and grants full-trust local Node execution" >&2
  exit 2
fi
if ! [[ "$release_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid release repository" >&2
  exit 2
fi
expected_certificate_sha256=$(printf '%s' "$expected_certificate_sha256" | tr '[:upper:]' '[:lower:]')
if ! [[ "$expected_certificate_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid expected certificate SHA-256" >&2
  exit 2
fi
for input in "$archive" "$manifest" "$manifest_sigstore_bundle" "$archive_sigstore_bundle"; do
  if [ ! -f "$input" ] || [ -L "$input" ]; then
    echo "release inputs must be non-symlink regular files" >&2
    exit 2
  fi
done
archive=$(cd "$(dirname "$archive")" && pwd -P)/$(basename "$archive")
manifest=$(cd "$(dirname "$manifest")" && pwd -P)/$(basename "$manifest")
manifest_sigstore_bundle=$(cd "$(dirname "$manifest_sigstore_bundle")" && pwd -P)/$(basename "$manifest_sigstore_bundle")
archive_sigstore_bundle=$(cd "$(dirname "$archive_sigstore_bundle")" && pwd -P)/$(basename "$archive_sigstore_bundle")

verifier=${RELEASE_MANIFEST_VERIFIER:-}
if [ -z "$verifier" ]; then
  if [ -f "$script_dir/../scripts/release_manifest.py" ]; then
    verifier="$script_dir/../scripts/release_manifest.py"
  elif [ -f "$script_dir/../support/release_manifest.py" ]; then
    verifier="$script_dir/../support/release_manifest.py"
  else
    echo "release manifest verifier is unavailable" >&2
    exit 1
  fi
fi
python3 "$verifier" verify --manifest "$manifest" \
  --expected-certificate-sha256 "$expected_certificate_sha256" >/dev/null

metadata=$(mktemp "${TMPDIR:-/tmp}/ego-browser-install-metadata.XXXXXX")
work=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-install.XXXXXX")
staging=""
pin_staging=""
cleanup() {
  rm -f -- "$metadata"
  # The verified package is deliberately made read-only before activation.  If
  # a later check fails, make the temporary extraction writable so cleanup can
  # remove the complete staging tree without leaking signed learning files.
  if [ -n "$work" ] && [ -d "$work" ]; then
    chmod -R u+w -- "$work" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
  [ -z "$staging" ] || rm -rf -- "$staging"
  [ -z "$pin_staging" ] || rm -f -- "$pin_staging"
}
trap cleanup EXIT

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

python3 - "$manifest" "$(basename "$archive")" > "$metadata" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_bytes())
name = sys.argv[2]
matches = [artifact for artifact in manifest["artifacts"] if artifact["name"] == name]
if len(matches) != 1 or matches[0]["kind"] != "macos_local_components":
    raise SystemExit("archive is not the macOS artifact in the verified manifest")
print(manifest["version"])
print(matches[0]["sha256"])
print(manifest["signer_certificate_sha256"])
PY
version=$(sed -n '1p' "$metadata")
expected_archive_sha256=$(sed -n '2p' "$metadata")
manifest_certificate_sha256=$(sed -n '3p' "$metadata")
if [ "$manifest_certificate_sha256" != "$expected_certificate_sha256" ]; then
  echo "release certificate pin changed during verification" >&2
  exit 1
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to authenticate the release manifest and archive" >&2
  exit 1
fi
release_identity="https://github.com/${release_repository}/.github/workflows/release.yml@refs/tags/v${version}"
cosign verify-blob \
  --bundle "$manifest_sigstore_bundle" \
  --certificate-identity "$release_identity" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$manifest" >/dev/null
cosign verify-blob \
  --bundle "$archive_sigstore_bundle" \
  --certificate-identity "$release_identity" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$archive" >/dev/null
actual_archive_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
if [ "$actual_archive_sha256" != "$expected_archive_sha256" ]; then
  echo "macOS archive SHA-256 verification failed" >&2
  exit 1
fi

python3 - "$archive" <<'PY'
import tarfile
import sys

required = {
    "bin/ego-browser-bridge",
    "bin/ego-browser-device",
    "installer/install-macos.sh",
    "installer/uninstall-macos.sh",
    "installer/rollback-macos.sh",
    "support/clear_verified_quarantine.py",
    "support/release_manifest.py",
    "support/release-manifest.schema.json",
    "support/verify-community-release.sh",
    "SIGNING-EVIDENCE.json",
    "VERSION",
    "LICENSE",
}
optional_files = {
    "bin/ego-browser-learning-bundle",
    "support/verify-learning-bundle.sh",
}
allowed_roots = {"bin", "installer", "support", "learning-bundle"}
expected = required | allowed_roots | optional_files
seen = set()
with tarfile.open(sys.argv[1], "r:gz") as archive:
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        if not name or name.startswith("/") or "\\" in name:
            raise SystemExit("archive contains an invalid path")
        parts = name.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("archive contains path traversal")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit("archive contains a link or special file")
        is_learning_entry = name == "learning-bundle" or name.startswith("learning-bundle/")
        if name in seen or (name not in expected and not is_learning_entry):
            raise SystemExit("archive contains an unexpected or duplicate path")
        seen.add(name)
        if (name in allowed_roots and not member.isdir()) or (
            name not in allowed_roots and not member.isfile() and not is_learning_entry
        ) or (
            is_learning_entry and name != "learning-bundle" and
            not (member.isdir() or member.isfile())
        ):
            raise SystemExit("archive entry type is invalid")
if not required.issubset(seen):
    raise SystemExit("archive package inventory is incomplete")
PY
tar -xzf "$archive" -C "$work"
if [ "$(tr -d '[:space:]' < "$work/VERSION")" != "$version" ]; then
  echo "package and release manifest versions differ" >&2
  exit 1
fi
"$work/support/verify-community-release.sh" "$work" "$expected_certificate_sha256" "$version"

if [ -z "$ego_browser_path" ]; then
  ego_browser_path=$(command -v ego-browser || true)
fi
if [ -z "$ego_browser_path" ]; then
  echo "the official local ego-browser runtime is not installed or is not on PATH" >&2
  exit 1
fi
ego_browser_path=$(python3 - "$ego_browser_path" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("ego-browser path must be absolute")
resolved = path.resolve(strict=True)
if not resolved.is_file() or not os.access(resolved, os.X_OK):
    raise SystemExit("ego-browser path must resolve to an executable regular file")
print(resolved)
PY
)
runtime_version=$(
  env -i HOME="$HOME" PATH="/usr/bin:/bin" "$ego_browser_path" --version \
    | python3 -c '
import json
import re
import sys

raw = sys.stdin.read()
version = None
try:
    value = json.loads(raw)
except json.JSONDecodeError:
    lines = raw.splitlines()
    if len(lines) == 3 and lines[0].startswith("ego-browser "):
        version = lines[0][len("ego-browser "):]
else:
    if isinstance(value, dict):
        version = value.get("ego_browser_version")

if not isinstance(version, str) or re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", version) is None:
    raise SystemExit("ego-browser runtime probe is malformed")
print(version)
'
)
if [ "$runtime_version" != "0.4.7.4" ]; then
  echo "local ego-browser runtime version $runtime_version is incompatible; expected 0.4.7.4" >&2
  exit 1
fi

install_root=${EGO_BROWSER_INSTALL_ROOT:-$HOME/Library/Application Support/Agent Remote Ego Browser}
launch_agents=${EGO_BROWSER_LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}
case "$install_root" in "$HOME"/*) ;; *) echo "install root must stay inside the current home directory" >&2; exit 2 ;; esac
case "$launch_agents" in "$HOME"/*) ;; *) echo "launch-agent directory must stay inside the current home directory" >&2; exit 2 ;; esac
python3 - "$HOME" "$install_root" "$launch_agents" <<'PY'
import os
import sys
from pathlib import Path

home = Path(sys.argv[1]).resolve(strict=True)
for raw in sys.argv[2:]:
    path = Path(raw)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            raise SystemExit("installation path contains a symlink")
    parent = path.parent
    while not parent.exists():
        parent = parent.parent
    if home not in (parent.resolve(), *parent.resolve().parents):
        raise SystemExit("installation path escaped the current home directory")
PY

releases="$install_root/releases"
release="$releases/$version"
certificate_pin="$install_root/TRUSTED_CERTIFICATE_SHA256"
mkdir -p "$releases" "$install_root/state" "$install_root/logs" "$launch_agents"
chmod 0700 "$install_root" "$releases" "$install_root/state" "$install_root/logs" "$launch_agents"
if [ -e "$release" ]; then
  if [ -L "$release" ] || [ ! -f "$release/ARCHIVE_SHA256" ] || \
     [ "$(tr -d '[:space:]' < "$release/ARCHIVE_SHA256")" != "$actual_archive_sha256" ]; then
    echo "release $version already exists with different or invalid bytes" >&2
    exit 1
  fi
  "$release/support/verify-community-release.sh" "$release" "$expected_certificate_sha256" "$version"
else
  staging="$releases/.${version}.install-$$"
  mkdir "$staging"
  ditto "$work" "$staging"
  printf '%s\n' "$actual_archive_sha256" > "$staging/ARCHIVE_SHA256"
  find "$staging" -type f -exec chmod 0400 {} +
  chmod 0500 "$staging/bin/ego-browser-bridge" "$staging/bin/ego-browser-device" \
    "$staging/installer/install-macos.sh" "$staging/installer/uninstall-macos.sh" \
    "$staging/installer/rollback-macos.sh" "$staging/support/release_manifest.py" \
    "$staging/support/clear_verified_quarantine.py" \
    "$staging/support/verify-community-release.sh"
  for optional in \
    "$staging/bin/ego-browser-learning-bundle" \
    "$staging/support/verify-learning-bundle.sh"; do
    if [ -f "$optional" ]; then
      chmod 0500 "$optional"
    fi
  done
  find "$staging" -type d -exec chmod 0500 {} +
  mv "$staging" "$release"
  staging=""
fi

python3 "$release/support/clear_verified_quarantine.py" "$release"
"$release/support/verify-community-release.sh" "$release" "$expected_certificate_sha256" "$version"
if [ -e "$certificate_pin" ] || [ -L "$certificate_pin" ]; then
  installed_certificate_sha256=$(read_verified_certificate_pin "$certificate_pin")
  if [ "$installed_certificate_sha256" != "$expected_certificate_sha256" ]; then
    echo "refusing an implicit trusted certificate rotation" >&2
    exit 1
  fi
fi
pin_staging=$(mktemp "$install_root/.certificate-pin.XXXXXX")
printf '%s\n' "$expected_certificate_sha256" > "$pin_staging"
chmod 0400 "$pin_staging"
mv -f "$pin_staging" "$certificate_pin"
pin_staging=""
if [ "$(read_verified_certificate_pin "$certificate_pin")" != "$expected_certificate_sha256" ]; then
  echo "trusted release certificate pin verification failed after installation" >&2
  exit 1
fi

current="$install_root/current"
if [ -e "$current" ] && [ ! -L "$current" ]; then
  echo "refusing to replace non-symlink current path" >&2
  exit 1
fi
next_link="$install_root/.current-$$"
ln -s "$release" "$next_link"
mv -fh "$next_link" "$current"

credential_dir="$HOME/.config/agent-remote-ego-browser"
mkdir -p "$credential_dir"
chmod 0700 "$credential_dir"
bridge_plist="$launch_agents/dev.agentremote.ego-browser.bridge.plist"
device_plist="$launch_agents/dev.agentremote.ego-browser.device.plist"
python3 - "$bridge_plist.tmp" "$device_plist.tmp" "$current" "$credential_dir" \
  "$install_root" "$ego_browser_path" "$expected_certificate_sha256" <<'PY'
import plistlib
import sys
from pathlib import Path

bridge_output, device_output, current, credentials, root, runtime, certificate = sys.argv[1:]
common = {
    "ProcessType": "Interactive",
    "RunAtLoad": True,
    "KeepAlive": {"SuccessfulExit": False, "NetworkState": True},
    "ThrottleInterval": 30,
}
bridge = {
    **common,
    "Label": "dev.agentremote.ego-browser.bridge",
    "ProgramArguments": [
        f"{current}/bin/ego-browser-bridge", "--outbound",
        "--credential-dir", credentials,
        "--work-root", f"{root}/state/bridge",
        "--release-profile", "community-local-trust",
        "--credential-profile", "community-file",
    ],
    "EnvironmentVariables": {
        "EGO_BROWSER_EXECUTABLE": runtime,
        "EGO_BROWSER_RELEASE_PROFILE": "community-local-trust",
        "EGO_BROWSER_CREDENTIAL_PROFILE": "community_file",
        "EGO_BROWSER_SIGNER_CERTIFICATE_SHA256": certificate,
        "PATH": f"{Path(runtime).parent}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
    },
    "StandardOutPath": f"{root}/logs/bridge.log",
    "StandardErrorPath": f"{root}/logs/bridge.log",
}
device = {
    **common,
    "Label": "dev.agentremote.ego-browser.device",
    "ProgramArguments": [f"{current}/bin/ego-browser-device", "service"],
    "EnvironmentVariables": {
        "EGO_BROWSER_DEVICE_HOME": credentials,
        "EGO_BROWSER_EXECUTABLE": runtime,
        "EGO_BROWSER_SIGNER_CERTIFICATE_SHA256": certificate,
        "PATH": f"{Path(runtime).parent}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
    },
    "StandardOutPath": f"{root}/logs/device.log",
    "StandardErrorPath": f"{root}/logs/device.log",
}
for path, value in ((bridge_output, bridge), (device_output, device)):
    with Path(path).open("wb") as output:
        plistlib.dump(value, output, fmt=plistlib.FMT_XML, sort_keys=True)
PY
chmod 0600 "$bridge_plist.tmp" "$device_plist.tmp"
mv -f "$bridge_plist.tmp" "$bridge_plist"
mv -f "$device_plist.tmp" "$device_plist"
plutil -lint "$bridge_plist" "$device_plist" >/dev/null

if [ "$start_agents" -eq 1 ]; then
  domain="gui/$(id -u)"
  launchctl bootout "$domain" "$bridge_plist" >/dev/null 2>&1 || true
  launchctl bootout "$domain" "$device_plist" >/dev/null 2>&1 || true
  launchctl bootstrap "$domain" "$device_plist"
  launchctl bootstrap "$domain" "$bridge_plist"
fi

echo "installed ego-browser Bridge $version for the current user"
readiness=$(python3 - "$current/SIGNING-EVIDENCE.json" <<'PY'
import json
import sys
value = json.loads(open(sys.argv[1], encoding="utf-8").read())
if value["production_ready"]:
    print("production_ready=true")
    print(f"learning_bundle_digest={value['learning_bundle_digest']}")
else:
    print("production_ready=false")
    print("readiness_blockers=" + ",".join(value["readiness_blockers"]))
PY
)
printf '%s\n' "$readiness"
echo "register explicitly with: $current/bin/ego-browser-device register --server https://SERVER --token TOKEN --signer-certificate-sha256 $expected_certificate_sha256"
