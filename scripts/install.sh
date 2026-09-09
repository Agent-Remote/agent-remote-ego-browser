#!/usr/bin/env bash
set -euo pipefail

# Bootstrap installer for the macOS Bridge.  The signed release installer remains
# the authority for archive, manifest, certificate, and code-signing validation;
# this script only supplies the surrounding download and first-run plumbing.

DEFAULT_REPOSITORY="Agent-Remote/agent-remote-ego-browser"
# The community signing certificate is persistent across releases. A rotation
# deliberately requires an explicit --certificate-sha256 override.
DEFAULT_CERTIFICATE_SHA256="1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5"
EGO_LITE_INSTALL_SCRIPT_COMMIT="36053d07001a910cb806a15d42d00fdea1cdea3d"
EGO_LITE_INSTALL_SCRIPT_SHA256="7a4c307c9a8ee6abae094f7cd497a81992de81e1fc37719fde61c43fd841d057"
EGO_LITE_INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/citrolabs/ego-lite/${EGO_LITE_INSTALL_SCRIPT_COMMIT}/skills/ego-browser/scripts/install.sh"
EXPECTED_RUNTIME_VERSION="0.4.7.4"

REPOSITORY="${EGO_BROWSER_REPO:-$DEFAULT_REPOSITORY}"
VERSION="${EGO_BROWSER_VERSION:-latest}"
CERTIFICATE_SHA256="${EGO_BROWSER_CERTIFICATE_SHA256:-}"
SERVER_URL="${EGO_BROWSER_SERVER_URL:-}"
REGISTRATION_TOKEN="${EGO_BROWSER_REGISTRATION_TOKEN:-}"
SESSION_ID="${EGO_BROWSER_SESSION_ID:-}"
RUNTIME_PATH="${EGO_BROWSER_RUNTIME_PATH:-}"
AGENT_REMOTE_PATH="${EGO_BROWSER_AGENT_REMOTE:-}"
INSTALL_ROOT="${EGO_BROWSER_INSTALL_ROOT:-}"
ARCHIVE_PATH="${EGO_BROWSER_ARCHIVE:-}"
ARCHIVE_SIGSTORE_PATH="${EGO_BROWSER_ARCHIVE_SIGSTORE_BUNDLE:-}"
MANIFEST_PATH="${EGO_BROWSER_MANIFEST:-}"
MANIFEST_SIGSTORE_PATH="${EGO_BROWSER_MANIFEST_SIGSTORE_BUNDLE:-}"
TMP_BASE="${EGO_BROWSER_INSTALL_TMPDIR:-${TMPDIR:-/tmp}}"
EGO_LITE_WAIT_SECONDS="${EGO_BROWSER_EGO_LITE_WAIT_SECONDS:-600}"

AUTO_INSTALL_EGO_LITE=1
AUTO_INSTALL_DEPENDENCIES=1
CONFIRM_LOCAL_TRUST=0
CONFIRM_FULL_TRUST=0
NO_START=0
KEEP_TEMP=0
NON_INTERACTIVE=0
ALLOW_HTTP=0
WORK=""

usage() {
  cat <<'EOF'
Usage:
  scripts/install.sh [options]
  curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-ego-browser/main/scripts/install.sh | bash -s -- [options]

Installs the verified macOS ego-browser Bridge and Device Client.  By default it
downloads the latest release, installs ego lite when it is absent, and starts
the two per-user launch agents.  The first ego lite GUI onboarding still needs
to be completed by the logged-in macOS user.

Options:
  --version VERSION             Release version, for example 0.1.9 or v0.1.9.
  --repo OWNER/REPO             GitHub repository to download from.
  --certificate-sha256 HEX      Expected release signing certificate SHA-256.
  --server URL                  Register the local Device Client after install.
  --token TOKEN                 Short-lived user registration token.
  --session-id ID               Claim this exact tool session after registration.
  --agent-remote PATH           Override the agent-remote CLI used for stored credentials.
  --confirm-local-trust         Accept the project-self-signed full-trust Bridge.
  --confirm-full-trust          Permit the explicit session claim (requires --session-id).
  --ego-browser PATH             Absolute path to the local ego-browser runtime.
  --install-root PATH            Override the per-user Bridge install root.
  --archive FILE                 Use a local archive instead of downloading one.
  --archive-sigstore-bundle FILE  Sigstore bundle for --archive.
  --manifest FILE                Local aggregate release manifest.
  --manifest-sigstore-bundle FILE  Sigstore bundle for --manifest.
  --skip-ego-lite                Do not install ego lite if the runtime is missing.
  --skip-dependency-install      Do not install missing Homebrew dependencies.
  --ego-lite-wait-seconds N      Wait time for first-run onboarding (default: 600).
  --no-start                     Install launch agents without bootstrapping them.
  --non-interactive               Never read a token or onboarding confirmation from /dev/tty.
  --allow-http                   Allow an http:// server URL (local testing only).
  --keep-temp                    Keep downloaded and extracted files for inspection.
  -h, --help                    Show this help.

Environment variables mirror the main options with the EGO_BROWSER_ prefix,
including EGO_BROWSER_REGISTRATION_TOKEN, EGO_BROWSER_SESSION_ID, and
EGO_BROWSER_AGENT_REMOTE.

A claim is intentionally never inferred from a candidate list.  Supplying
--session-id together with --confirm-full-trust is required to grant the remote
session the current macOS user's full local Node.js authority.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --repo)
      REPOSITORY="${2:?--repo requires OWNER/REPO}"
      shift 2
      ;;
    --certificate-sha256)
      CERTIFICATE_SHA256="${2:?--certificate-sha256 requires a value}"
      shift 2
      ;;
    --server)
      SERVER_URL="${2:?--server requires a URL}"
      shift 2
      ;;
    --token)
      REGISTRATION_TOKEN="${2:?--token requires a value}"
      shift 2
      ;;
    --session-id)
      SESSION_ID="${2:?--session-id requires a value}"
      shift 2
      ;;
    --agent-remote)
      AGENT_REMOTE_PATH="${2:?--agent-remote requires a path}"
      shift 2
      ;;
    --confirm-local-trust)
      CONFIRM_LOCAL_TRUST=1
      shift
      ;;
    --confirm-full-trust)
      CONFIRM_FULL_TRUST=1
      shift
      ;;
    --ego-browser)
      RUNTIME_PATH="${2:?--ego-browser requires a path}"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="${2:?--install-root requires a path}"
      shift 2
      ;;
    --archive)
      ARCHIVE_PATH="${2:?--archive requires a path}"
      shift 2
      ;;
    --archive-sigstore-bundle)
      ARCHIVE_SIGSTORE_PATH="${2:?--archive-sigstore-bundle requires a path}"
      shift 2
      ;;
    --manifest)
      MANIFEST_PATH="${2:?--manifest requires a path}"
      shift 2
      ;;
    --manifest-sigstore-bundle)
      MANIFEST_SIGSTORE_PATH="${2:?--manifest-sigstore-bundle requires a path}"
      shift 2
      ;;
    --skip-ego-lite)
      AUTO_INSTALL_EGO_LITE=0
      shift
      ;;
    --skip-dependency-install)
      AUTO_INSTALL_DEPENDENCIES=0
      shift
      ;;
    --ego-lite-wait-seconds)
      EGO_LITE_WAIT_SECONDS="${2:?--ego-lite-wait-seconds requires a number}"
      shift 2
      ;;
    --no-start)
      NO_START=1
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --allow-http)
      ALLOW_HTTP=1
      shift
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (use --help for usage)"
      ;;
  esac
done

cleanup() {
  if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
    return
  fi
  if [ "$KEEP_TEMP" -eq 1 ]; then
    log "kept temporary directory: $WORK"
    return
  fi
  chmod -R u+w -- "$WORK" >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}

trap cleanup EXIT HUP INT TERM

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

refresh_brew_path() {
  local candidate prefix
  if ! command -v brew >/dev/null 2>&1; then
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
      if [ -x "$candidate" ]; then
        PATH="$(dirname "$candidate"):$PATH"
        export PATH
        break
      fi
    done
  fi
  if command -v brew >/dev/null 2>&1; then
    prefix="$(brew --prefix 2>/dev/null || true)"
    if [ -n "$prefix" ] && [ -d "$prefix/bin" ]; then
      PATH="$prefix/bin:$prefix/sbin:$PATH"
      export PATH
    fi
  fi
}

ensure_homebrew_formula() {
  local command_name="$1"
  local formula="$2"
  if command -v "$command_name" >/dev/null 2>&1; then
    return
  fi
  if [ "$AUTO_INSTALL_DEPENDENCIES" -eq 1 ] && command -v brew >/dev/null 2>&1; then
    log "${command_name} is missing; installing Homebrew formula ${formula} ..."
    brew install "$formula"
    refresh_brew_path
  fi
  need_cmd "$command_name"
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

absolute_path() {
  local value="$1"
  local parent base
  case "$value" in
    /*) ;;
    *)
      parent=$(dirname "$value")
      base=$(basename "$value")
      value="$(cd "$parent" 2>/dev/null && printf '%s/%s' "$PWD" "$base")" || return 1
      ;;
  esac
  printf '%s\n' "$value"
}

regular_file() {
  local value
  value=$(absolute_path "$1") || die "cannot resolve path: $1"
  [ -f "$value" ] || die "expected a regular file: $value"
  [ ! -L "$value" ] || die "symlink inputs are not accepted: $value"
  printf '%s\n' "$value"
}

validate_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]] ||
    die "invalid release version: $1"
}

validate_repository() {
  [[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
    die "invalid GitHub repository: $REPOSITORY"
}

validate_certificate() {
  CERTIFICATE_SHA256=$(printf '%s' "$CERTIFICATE_SHA256" | tr '[:upper:]' '[:lower:]')
  [[ "$CERTIFICATE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    die "certificate SHA-256 must contain exactly 64 hexadecimal characters"
}

resolve_latest_version() {
  local effective tag
  effective=$(curl --fail --show-error --silent --location \
    --output /dev/null --write-out '%{url_effective}' \
    "https://github.com/${REPOSITORY}/releases/latest" || true)
  tag="${effective##*/}"
  if [ -z "$tag" ] || [ "$tag" = "latest" ] || [ "$tag" = "releases" ]; then
    tag=$(curl --fail --show-error --silent --location \
      "https://api.github.com/repos/${REPOSITORY}/releases/latest" |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name", ""))' || true)
  fi
  [ -n "$tag" ] || die "failed to resolve the latest release; retry with an explicit --version"
  VERSION="${tag#v}"
}

read_manifest_version() {
  python3 - "$1" <<'PY'
import json
import re
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_bytes())
version = value.get("version") if isinstance(value, dict) else None
if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z.-]+)?", version) is None:
    raise SystemExit("release manifest has no valid version")
print(version)
PY
}

select_certificate_pin() {
  if [ -z "$CERTIFICATE_SHA256" ]; then
    if [ "$REPOSITORY" = "$DEFAULT_REPOSITORY" ]; then
      CERTIFICATE_SHA256="$DEFAULT_CERTIFICATE_SHA256"
    else
      die "no trusted certificate pin is embedded for ${REPOSITORY}; pass --certificate-sha256"
    fi
  fi
  validate_certificate
}

validate_server_options() {
  if [ -n "$INSTALL_ROOT" ] && [[ "$INSTALL_ROOT" != /* ]]; then
    die "--install-root must be an absolute path"
  fi
  if [ -n "$AGENT_REMOTE_PATH" ] && [[ "$AGENT_REMOTE_PATH" != /* ]]; then
    die "--agent-remote must be an absolute path"
  fi
  if [ -n "$AGENT_REMOTE_PATH" ]; then
    AGENT_REMOTE_PATH=$(canonical_executable "$AGENT_REMOTE_PATH" 2>/dev/null) ||
      die "--agent-remote must point to an executable regular file"
  fi
  if [ -n "$SERVER_URL" ]; then
    case "$SERVER_URL" in
      https://*) ;;
      http://*)
        [ "$ALLOW_HTTP" -eq 1 ] || die "--server must use https:// (use --allow-http only for local testing)"
        ;;
      *) die "--server must be an https:// URL" ;;
    esac
  fi
  if [ -n "$REGISTRATION_TOKEN" ] && [ -z "$SERVER_URL" ]; then
    die "--token requires --server"
  fi
  if [ -n "$SESSION_ID" ] && [ "$CONFIRM_FULL_TRUST" -ne 1 ]; then
    die "claiming a session requires --confirm-full-trust"
  fi
  if [ "$CONFIRM_FULL_TRUST" -eq 1 ] && [ -z "$SESSION_ID" ]; then
    die "--confirm-full-trust requires --session-id"
  fi
}

find_agent_remote_cli() {
  local candidate configured_home
  if [ -n "$AGENT_REMOTE_PATH" ]; then
    candidate=$(canonical_executable "$AGENT_REMOTE_PATH" 2>/dev/null || true)
    [ -n "$candidate" ] || return 1
    printf '%s\n' "$candidate"
    return 0
  fi

  candidate=$(command -v agent-remote || true)
  if [ -n "$candidate" ]; then
    candidate=$(canonical_executable "$candidate" 2>/dev/null || true)
    if [ -n "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  for candidate in "$HOME/.local/bin/agent-remote" "/usr/local/bin/agent-remote" \
    "/opt/homebrew/bin/agent-remote"; do
    if [ -f "$candidate" ]; then
      candidate=$(canonical_executable "$candidate" 2>/dev/null || true)
      if [ -n "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done

  configured_home="${AGENT_REMOTE_HOME:-}"
  if [ -n "$configured_home" ] && [ -f "$configured_home/bin/agent-remote" ]; then
    candidate=$(canonical_executable "$configured_home/bin/agent-remote" 2>/dev/null || true)
    if [ -n "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

agent_remote_register_supported() {
  local cli="$1"
  local help
  help=$("$cli" ego-browser register --help 2>&1) || return 1
  case "$help" in
    *"--signer-certificate-sha256"*) return 0 ;;
    *) return 1 ;;
  esac
}

device_token_stdin_supported() {
  local device="$1"
  local help
  help=$(EGO_BROWSER_DEVICE_HOME="$WORK/device-capability-probe" "$device" --help 2>&1) || return 1
  case "$help" in
    *"--token-stdin"*) return 0 ;;
    *) return 1 ;;
  esac
}

find_runtime_candidate() {
  local candidate app
  if [ -n "$RUNTIME_PATH" ]; then
    printf '%s\n' "$RUNTIME_PATH"
    return 0
  fi
  candidate=$(command -v ego-browser || true)
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  for candidate in "$HOME/.local/bin/ego-browser" \
    "/Applications/ego lite.app/Contents/MacOS/ego-browser" \
    "$HOME/Applications/ego lite.app/Contents/MacOS/ego-browser"; do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  for app in "/Applications/ego lite.app" "$HOME/Applications/ego lite.app"; do
    if [ -d "$app/Contents" ]; then
      candidate=$(find "$app/Contents" -type f -name ego-browser -perm -111 -print -quit 2>/dev/null || true)
      if [ -n "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

canonical_executable() {
  python3 - "$1" <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("ego-browser path must be absolute")
try:
    resolved = path.resolve(strict=True)
except FileNotFoundError as error:
    raise SystemExit("ego-browser executable was not found") from error
metadata = resolved.stat()
if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
    raise SystemExit("ego-browser path must resolve to an executable regular file")
print(resolved)
PY
}

probe_runtime_version() {
  local path="$1"
  local raw
  # ego lite writes its non-interactive version response to stderr.  Capture
  # both streams, while still requiring a successful command and an exact
  # parseable response below.
  raw=$(env -i HOME="$HOME" \
    PATH="$(dirname "$path"):/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
    "$path" --version 2>&1) || return 1
  printf '%s' "$raw" | python3 -c '
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
    raise SystemExit(1)
print(version)
'
}

verify_runtime() {
  local candidate version
  candidate=$(find_runtime_candidate || true)
  [ -n "$candidate" ] || return 1
  candidate=$(canonical_executable "$candidate") || die "invalid local ego-browser executable: $candidate"
  version=$(probe_runtime_version "$candidate" || true)
  [ -n "$version" ] || die "local ego-browser runtime did not return a valid --version response"
  [ "$version" = "$EXPECTED_RUNTIME_VERSION" ] ||
    die "local ego-browser runtime is $version; this Bridge requires $EXPECTED_RUNTIME_VERSION"
  RUNTIME_PATH="$candidate"
  return 0
}

download_ego_lite_installer() {
  local destination="$WORK/ego-lite-install.sh"
  local actual
  log "ego lite is not available; downloading the pinned official installer ..."
  curl --fail --show-error --location --retry 5 --retry-delay 3 \
    "$EGO_LITE_INSTALL_SCRIPT_URL" -o "$destination"
  actual=$(sha256_file "$destination")
  [ "$actual" = "$EGO_LITE_INSTALL_SCRIPT_SHA256" ] ||
    die "official ego lite installer checksum mismatch"
  chmod 0500 "$destination"
  printf '%s\n' "$destination"
}

install_or_verify_ego_lite() {
  local installed_by_script=0
  if verify_runtime; then
    return
  fi
  [ "$AUTO_INSTALL_EGO_LITE" -eq 1 ] ||
    die "ego lite / ego-browser $EXPECTED_RUNTIME_VERSION is not installed (remove --skip-ego-lite to install it)"
  need_cmd hdiutil
  need_cmd open
  need_cmd xattr
  local installer
  installer=$(download_ego_lite_installer)
  sh "$installer"
  installed_by_script=1
  if [ "$NON_INTERACTIVE" -eq 0 ] && [ -r /dev/tty ]; then
    printf '%s\n' "Complete ego lite's GUI onboarding, then press Enter here to continue." >/dev/tty
    IFS= read -r _ </dev/tty || true
  fi

  local deadline now candidate version last_version
  deadline=$(( $(date +%s) + EGO_LITE_WAIT_SECONDS ))
  last_version=""
  while :; do
    candidate=$(find_runtime_candidate || true)
    if [ -n "$candidate" ]; then
      candidate=$(canonical_executable "$candidate") || true
      if [ -n "$candidate" ]; then
        version=$(probe_runtime_version "$candidate" || true)
        if [ "$version" = "$EXPECTED_RUNTIME_VERSION" ]; then
          RUNTIME_PATH="$candidate"
          return
        fi
        last_version="$version"
      fi
    fi
    now=$(date +%s)
    [ "$now" -lt "$deadline" ] || break
    sleep 2
  done
  if [ -n "$last_version" ]; then
    die "ego lite reported runtime $last_version; this Bridge requires $EXPECTED_RUNTIME_VERSION"
  fi
  if [ "$installed_by_script" -eq 1 ]; then
    die "ego-browser runtime did not become available after onboarding; set --ego-browser explicitly or retry"
  fi
  die "ego-browser runtime is unavailable"
}

prepare_release_inputs() {
  local archive_name manifest_name base_url manifest_version requested_version input_dir
  if [ -n "$ARCHIVE_PATH" ] || [ -n "$ARCHIVE_SIGSTORE_PATH" ] ||
    [ -n "$MANIFEST_PATH" ] || [ -n "$MANIFEST_SIGSTORE_PATH" ]; then
    [ -n "$ARCHIVE_PATH" ] && [ -n "$ARCHIVE_SIGSTORE_PATH" ] &&
      [ -n "$MANIFEST_PATH" ] && [ -n "$MANIFEST_SIGSTORE_PATH" ] ||
      die "--archive, --archive-sigstore-bundle, --manifest, and --manifest-sigstore-bundle must be supplied together"
    ARCHIVE_PATH=$(regular_file "$ARCHIVE_PATH")
    ARCHIVE_SIGSTORE_PATH=$(regular_file "$ARCHIVE_SIGSTORE_PATH")
    MANIFEST_PATH=$(regular_file "$MANIFEST_PATH")
    MANIFEST_SIGSTORE_PATH=$(regular_file "$MANIFEST_SIGSTORE_PATH")
    requested_version="${VERSION#v}"
    if [ "$requested_version" != "latest" ]; then
      validate_version "$requested_version"
    fi
    manifest_version=$(read_manifest_version "$MANIFEST_PATH")
    if [ "$requested_version" != "latest" ] &&
      [ "$requested_version" != "$manifest_version" ]; then
      die "local release manifest is $manifest_version, but --version requested $requested_version"
    fi
    VERSION="$manifest_version"
    # Keep a private snapshot of caller-supplied files and give the archive the
    # canonical release filename expected by the signed artifact inventory.
    input_dir="$WORK/release-inputs"
    mkdir -p "$input_dir"
    archive_name="agent-remote-ego-browser-macos-universal-${VERSION}.tar.gz"
    manifest_name="agent-remote-ego-browser-${VERSION}.release-manifest.json"
    cp "$ARCHIVE_PATH" "$input_dir/$archive_name"
    cp "$ARCHIVE_SIGSTORE_PATH" "$input_dir/$archive_name.sigstore.json"
    cp "$MANIFEST_PATH" "$input_dir/$manifest_name"
    cp "$MANIFEST_SIGSTORE_PATH" "$input_dir/$manifest_name.sigstore.json"
    chmod 0400 "$input_dir"/*
    ARCHIVE_PATH="$input_dir/$archive_name"
    ARCHIVE_SIGSTORE_PATH="$input_dir/$archive_name.sigstore.json"
    MANIFEST_PATH="$input_dir/$manifest_name"
    MANIFEST_SIGSTORE_PATH="$input_dir/$manifest_name.sigstore.json"
    return
  fi

  if [ "$VERSION" = "latest" ]; then
    resolve_latest_version
  else
    VERSION="${VERSION#v}"
  fi
  validate_version "$VERSION"
  archive_name="agent-remote-ego-browser-macos-universal-${VERSION}.tar.gz"
  manifest_name="agent-remote-ego-browser-${VERSION}.release-manifest.json"
  base_url="https://github.com/${REPOSITORY}/releases/download/v${VERSION}"
  ARCHIVE_PATH="$WORK/$archive_name"
  ARCHIVE_SIGSTORE_PATH="$WORK/$archive_name.sigstore.json"
  MANIFEST_PATH="$WORK/$manifest_name"
  MANIFEST_SIGSTORE_PATH="$WORK/$manifest_name.sigstore.json"
  log "downloading release v${VERSION} ..."
  curl --fail --show-error --location --retry 5 --retry-delay 3 \
    "$base_url/$archive_name" -o "$ARCHIVE_PATH"
  curl --fail --show-error --location --retry 5 --retry-delay 3 \
    "$base_url/$archive_name.sigstore.json" -o "$ARCHIVE_SIGSTORE_PATH"
  curl --fail --show-error --location --retry 5 --retry-delay 3 \
    "$base_url/$manifest_name" -o "$MANIFEST_PATH"
  curl --fail --show-error --location --retry 5 --retry-delay 3 \
    "$base_url/$manifest_name.sigstore.json" -o "$MANIFEST_SIGSTORE_PATH"
}

validate_archive_paths() {
  python3 - "$1" <<'PY'
import tarfile
import sys

with tarfile.open(sys.argv[1], "r:gz") as archive:
    seen = set()
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        if not name or name in seen or name.startswith("/") or "\\" in name:
            raise SystemExit("archive contains an invalid, duplicate, or absolute path")
        parts = name.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("archive contains path traversal")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit("archive contains a link or special file")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("archive contains a non-regular or non-directory entry")
        seen.add(name)
PY
}

# The packaged installer is itself release content. Authenticate the archive
# and manifest before executing any shell code extracted from that archive.
verify_release_inputs() {
  local archive_name release_identity actual_archive_sha256
  archive_name=$(basename "$ARCHIVE_PATH")
  validate_archive_paths "$ARCHIVE_PATH"
  release_identity="https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/v${VERSION}"
  log "authenticating release manifest and archive ..."
  cosign verify-blob \
    --bundle "$MANIFEST_SIGSTORE_PATH" \
    --certificate-identity "$release_identity" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$MANIFEST_PATH" >/dev/null
  cosign verify-blob \
    --bundle "$ARCHIVE_SIGSTORE_PATH" \
    --certificate-identity "$release_identity" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$ARCHIVE_PATH" >/dev/null
  actual_archive_sha256=$(sha256_file "$ARCHIVE_PATH")
  python3 - "$MANIFEST_PATH" "$ARCHIVE_PATH" "$archive_name" "$VERSION" \
    "$CERTIFICATE_SHA256" "$actual_archive_sha256" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest_path, archive_path, archive_name, expected_version, expected_certificate, actual_digest = sys.argv[1:]


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate release manifest field: {key}")
        result[key] = value
    return result


try:
    manifest = json.loads(
        Path(manifest_path).read_bytes(), object_pairs_hook=reject_duplicates
    )
except (OSError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"release manifest is not valid JSON: {error}") from error

if not isinstance(manifest, dict):
    raise SystemExit("release manifest is not an object")
version = manifest.get("version")
if not isinstance(version, str) or not re.fullmatch(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z.-]+)?", version
):
    raise SystemExit("release manifest version is invalid")
if version != expected_version:
    raise SystemExit("release manifest version does not match the requested release")
if manifest.get("component") != "agent-remote-ego-browser":
    raise SystemExit("release manifest component is unexpected")
if manifest.get("signer_certificate_sha256") != expected_certificate:
    raise SystemExit("release manifest certificate pin does not match")
if manifest.get("local_platform") != "macos":
    raise SystemExit("release manifest local platform is unexpected")
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, list):
    raise SystemExit("release manifest artifact inventory is invalid")
matches = [
    item for item in artifacts
    if isinstance(item, dict) and item.get("name") == archive_name
]
if len(matches) != 1 or matches[0].get("kind") != "macos_local_components":
    raise SystemExit("release manifest does not identify this macOS archive")
artifact = matches[0]
if not isinstance(actual_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", actual_digest):
    raise SystemExit("computed archive digest is invalid")
if artifact.get("sha256") != actual_digest:
    raise SystemExit("macOS archive digest does not match the signed manifest")
archive_size = Path(archive_path).stat().st_size
if artifact.get("size_bytes") != archive_size:
    raise SystemExit("macOS archive size does not match the signed manifest")
PY
}

extract_release() {
  local package_dir="$WORK/package"
  validate_archive_paths "$ARCHIVE_PATH"
  mkdir -p "$package_dir"
  tar -xzf "$ARCHIVE_PATH" -C "$package_dir"
  [ -x "$package_dir/installer/install-macos.sh" ] ||
    die "downloaded release does not contain installer/install-macos.sh"
  printf '%s\n' "$package_dir"
}

install_bridge() {
  local package_dir="$1"
  local installer_args
  installer_args=(
    --archive "$ARCHIVE_PATH"
    --archive-sigstore-bundle "$ARCHIVE_SIGSTORE_PATH"
    --manifest "$MANIFEST_PATH"
    --manifest-sigstore-bundle "$MANIFEST_SIGSTORE_PATH"
    --certificate-sha256 "$CERTIFICATE_SHA256"
    --ego-browser "$RUNTIME_PATH"
    --confirm-local-trust
  )
  if [ "$NO_START" -eq 1 ]; then
    installer_args+=(--no-start)
  fi
  log "verifying and installing Bridge v${VERSION} ..."
  if [ -n "$INSTALL_ROOT" ]; then
    EGO_BROWSER_RELEASE_REPOSITORY="$REPOSITORY" \
      EGO_BROWSER_INSTALL_ROOT="$INSTALL_ROOT" \
      "$package_dir/installer/install-macos.sh" "${installer_args[@]}"
  else
    EGO_BROWSER_RELEASE_REPOSITORY="$REPOSITORY" \
      "$package_dir/installer/install-macos.sh" "${installer_args[@]}"
  fi
}

read_token_from_tty() {
  [ "$NON_INTERACTIVE" -eq 0 ] && [ -r /dev/tty ] ||
    die "--token is required with --server in non-interactive mode"
  printf '%s' "Registration token: " >/dev/tty
  IFS= read -r -s REGISTRATION_TOKEN </dev/tty || true
  printf '\n' >/dev/tty
  [ -n "$REGISTRATION_TOKEN" ] || die "registration token cannot be empty"
}

register_with_device() {
  local device="$1"
  [ -n "$REGISTRATION_TOKEN" ] || die "registration token cannot be empty"

  if device_token_stdin_supported "$device"; then
    # Keep the token out of argv and shell history on current Device Clients.
    printf '%s' "$REGISTRATION_TOKEN" |
      EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" register \
        --server "$SERVER_URL" \
        --token-stdin \
        --signer-certificate-sha256 "$CERTIFICATE_SHA256"
  else
    # Older releases predate --token-stdin. Preserve their explicit-token
    # interface so an existing installation can still be bootstrapped.
    EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" register \
      --server "$SERVER_URL" \
      --token "$REGISTRATION_TOKEN" \
      --signer-certificate-sha256 "$CERTIFICATE_SHA256"
  fi
  REGISTRATION_TOKEN=""
}

register_with_agent_remote() {
  local cli="$1"
  local register_args
  register_args=(ego-browser register --signer-certificate-sha256 "$CERTIFICATE_SHA256")
  if [ -n "$SERVER_URL" ]; then
    register_args+=(--server-url "$SERVER_URL")
  fi
  log "using the stored agent-remote credential to register this Mac Device Client ..."
  AGENT_REMOTE_EGO_BROWSER_DEVICE="$2" \
    EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" \
    "$cli" "${register_args[@]}"
}

register_and_claim() {
  local current_root device cli auto_registration_supported
  local requested_server registration_complete
  requested_server="$SERVER_URL"
  registration_complete=0
  current_root="${INSTALL_ROOT:-$HOME/Library/Application Support/Agent Remote Ego Browser}/current"
  device="$current_root/bin/ego-browser-device"
  [ -x "$device" ] || die "installed Device Client is unavailable: $device"

  # A logged-in agent-remote CLI owns the credential store. Delegate token
  # retrieval to it instead of asking users to paste a token into this script.
  # Capability checks keep older CLI/Device Client releases on the legacy path.
  if [ -z "$REGISTRATION_TOKEN" ]; then
    cli=$(find_agent_remote_cli || true)
    auto_registration_supported=0
    if [ -n "$cli" ] && agent_remote_register_supported "$cli" &&
      device_token_stdin_supported "$device"; then
      auto_registration_supported=1
      if register_with_agent_remote "$cli" "$device"; then
        registration_complete=1
      elif [ -z "$requested_server" ] && [ -n "$SESSION_ID" ]; then
        die "automatic agent-remote registration failed; check login and server configuration"
      elif [ -z "$requested_server" ]; then
        log "agent-remote credential is unavailable; Bridge installed without registration"
        return 0
      else
        log "automatic agent-remote registration failed; falling back to a manual token"
      fi
    fi
    if [ "$auto_registration_supported" -eq 0 ] && [ -z "$requested_server" ]; then
      if [ -n "$SESSION_ID" ]; then
        die "--session-id requires a logged-in agent-remote CLI or an explicit --server and --token"
      fi
      log "agent-remote CLI with stored credentials was not found; Bridge installed without registration"
      return 0
    fi
  fi

  if [ "$registration_complete" -eq 0 ]; then
    [ -n "$SERVER_URL" ] || die "a server URL is required for manual Device Client registration"
    if [ -z "$REGISTRATION_TOKEN" ]; then
      read_token_from_tty
    fi
    log "registering this Mac Device Client ..."
    register_with_device "$device"
  fi

  log "fetching exact running tool-session candidates ..."
  EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" candidates
  if [ -n "$SESSION_ID" ]; then
    log "claiming the explicitly supplied tool session ..."
    EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" claim "$SESSION_ID" --confirm
    EGO_BROWSER_EXECUTABLE="$RUNTIME_PATH" "$device" status
  else
    log "device registered; no session was claimed"
    log "claim only an exact candidate after reviewing the full-trust warning:"
    log "  \"$device\" claim TOOL_SESSION_ID --confirm"
  fi
}

main() {
  [ "$(uname -s)" = "Darwin" ] || die "this one-click installer supports macOS only"
  [ "$(id -u)" -ne 0 ] || die "run this user-level installer without sudo"
  [ "$CONFIRM_LOCAL_TRUST" -eq 1 ] ||
    die "--confirm-local-trust is required: the Bridge is project-self-signed and grants full-trust local Node execution"
  [[ "$EGO_LITE_WAIT_SECONDS" =~ ^[0-9]+$ ]] ||
    die "--ego-lite-wait-seconds must be a non-negative integer"
  validate_repository
  validate_server_options
  refresh_brew_path
  need_cmd curl
  need_cmd tar
  need_cmd cp
  ensure_homebrew_formula python3 python
  need_cmd mktemp
  if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    die "missing required command: shasum or sha256sum"
  fi
  ensure_homebrew_formula cosign cosign

  TMP_BASE="${TMP_BASE%/}"
  [ -d "$TMP_BASE" ] || die "temporary directory does not exist: $TMP_BASE"
  WORK=$(mktemp -d "$TMP_BASE/agent-remote-ego-browser-install.XXXXXX")

  prepare_release_inputs
  validate_version "$VERSION"
  select_certificate_pin
  verify_release_inputs
  install_or_verify_ego_lite
  package_dir=$(extract_release)
  install_bridge "$package_dir"
  register_and_claim

  log "one-click installation completed"
  log "local runtime: $RUNTIME_PATH ($EXPECTED_RUNTIME_VERSION)"
  log "Bridge install root: ${INSTALL_ROOT:-$HOME/Library/Application Support/Agent Remote Ego Browser}"
  log "run the remote wrapper from the selected Linux Claude session with: ego-browser --doctor"
}

main "$@"
