#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
workspace_parent=$(dirname "$root")
server_root=${AGENT_REMOTE_SERVER_ROOT:-"$workspace_parent/agent-remote-server"}
node_root=${AGENT_REMOTE_NODE_ROOT:-"$workspace_parent/agent-remote-node"}
cli_root=${AGENT_REMOTE_CLI_ROOT:-"$workspace_parent/agent-remote-cli"}
redis_url=${AGENT_REMOTE_INTEGRATION_REDIS_URL:-redis://127.0.0.1:6379/14}
work=$(mktemp -d "/tmp/ego-browser-relay.XXXXXX")
work=$(cd "$work" && pwd -P)
server_pid=""
device_pid=""
broker_pid=""
bridge_pid=""
wrapper_pid=""
setup_a_pid=""
setup_b_pid=""

cleanup() {
  for pid in "$setup_a_pid" "$setup_b_pid" "$wrapper_pid" "$bridge_pid" "$broker_pid" "$device_pid" "$server_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf -- "$work"
}
trap cleanup EXIT

for directory in "$server_root" "$node_root" "$cli_root"; do
  if [ ! -d "$directory" ]; then
    echo "required sibling repository is missing: $directory" >&2
    exit 1
  fi
done

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)[sys.argv[2]])
PY
}

umask 077
server_port=$(free_port)
server_url="https://127.0.0.1:$server_port"
database_url="sqlite+aiosqlite:///$work/server.sqlite3"
bridge_version=$(tr -d '[:space:]' <"$root/VERSION")
if [[ ! "$bridge_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Bridge VERSION is invalid" >&2
  exit 1
fi
release_profile="development-local"
certificate_digest="development"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=agent-remote-relay-e2e-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=127.0.0.1" \
  -keyout "$work/server.key" -out "$work/server.csr" >/dev/null 2>&1
cat >"$work/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF
openssl x509 -req -sha256 -days 1 \
  -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -extfile "$work/server.ext" -out "$work/server.crt" >/dev/null 2>&1

cargo build --quiet --locked \
  --manifest-path "$root/Cargo.toml" \
  -p ego-browser-bridge -p ego-browser-device -p ego-browser-remote
cargo build --quiet --locked \
  --manifest-path "$cli_root/Cargo.toml" \
  --bin agent-remote
(
  cd "$node_root"
  go build -o "$work/ego-browser-broker-integration" \
    ./internal/egobrowser/integrationtest
)

fake_runtime="$work/local-ego-browser"
runtime_version_file="$work/runtime-version"
printf '%s\n' '0.4.7.4' >"$runtime_version_file"
counter="$work/runtime-count"
child_pid_file="$work/revoked-descendant-pid"
takeover_child_pid_file="$work/takeover-descendant-pid"
ownership_file="$work/task-space-ownership"
monitor_armed_file="$work/task-space-monitor-armed"
cat >"$fake_runtime" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  runtime_version=\$(/usr/bin/tr -d '[:space:]' <'$runtime_version_file')
  printf 'ego-browser %s\n' "\$runtime_version"
  printf '%s\n' '  chromium 150.0.7871.101' '  node v24.18.0'
  exit 0
fi
test "\${1:-}" = "nodejs" || exit 64
script=\$(/bin/cat)
case "\$script" in
  *agent-remote-task-space-ownership-monitor-v1*)
    observed_agent=0
    while :; do
      ownership=missing
      test ! -f '$ownership_file' || ownership=\$(/usr/bin/tr -d '[:space:]' <'$ownership_file')
      case "\$ownership" in
        agent)
          observed_agent=1
          printf '%s\n' armed >'$monitor_armed_file'
          ;;
        agentDelegatedToUser|user)
          test "\$observed_agent" -eq 0 || exit 73
          ;;
        missing) ;;
        *) exit 74 ;;
      esac
      /bin/sleep 0.05
    done
    ;;
esac
printf '%s\n' agent >'$ownership_file'
count=0
test ! -f '$counter' || count=\$(/bin/cat '$counter')
count=\$((count + 1))
printf '%s\n' "\$count" >'$counter'
case "\$script" in
  *takeover-e2e-marker*)
    /bin/sleep 30 &
    descendant=\$!
    printf '%s\n' "\$descendant" >'$takeover_child_pid_file'
    wait "\$descendant"
    ;;
  *revocation-e2e-marker*)
    /bin/sleep 30 &
    descendant=\$!
    printf '%s\n' "\$descendant" >'$child_pid_file'
    wait "\$descendant"
    ;;
esac
printf 'real-relay-runtime-round=%s\n%s' "\$count" "\$script"
EOF
chmod 0700 "$fake_runtime"

fixture="$work/fixture.json"
(
  cd "$server_root"
  DATABASE_URL="$database_url" \
  REDIS_URL="$redis_url" \
  PUBLIC_BASE_URL="$server_url" \
  AGENT_REMOTE_SECRET_KEY=ego-browser-real-relay-e2e-secret \
  EGO_BROWSER_EXPECTED_WRAPPER_VERSION="$bridge_version" \
  EGO_BROWSER_E2E_FIXTURE_PATH="$fixture" \
    uv run python scripts/seed-ego-browser-relay-e2e.py
)
node_id=$(json_field "$fixture" node_id)
node_token=$(json_field "$fixture" node_token)
tool_session_id=$(json_field "$fixture" tool_session_id)
user_token=$(json_field "$fixture" user_token)

(
  cd "$server_root"
  DATABASE_URL="$database_url" \
  REDIS_URL="$redis_url" \
  PUBLIC_BASE_URL="$server_url" \
  AGENT_REMOTE_SECRET_KEY=ego-browser-real-relay-e2e-secret \
  EGO_BROWSER_BRIDGE_ENABLED=true \
  EGO_BROWSER_REQUIRE_DEVICE_POP=true \
  EGO_BROWSER_LEASE_RENEW_INTERVAL_SECONDS=5 \
  EGO_BROWSER_EXPECTED_RELEASE_PROFILE="$release_profile" \
  EGO_BROWSER_EXPECTED_WRAPPER_VERSION="$bridge_version" \
  LOG_LEVEL=INFO \
    uv run uvicorn agent_remote_server.main:app \
      --host 127.0.0.1 --port "$server_port" \
      --ssl-keyfile "$work/server.key" --ssl-certfile "$work/server.crt"
) >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if curl --silent --show-error --fail --cacert "$work/ca.crt" \
    "$server_url/healthz" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || {
    cat "$work/server.log" >&2
    exit 1
  }
  sleep 0.05
done
curl --silent --show-error --fail --cacert "$work/ca.crt" \
  "$server_url/healthz" >/dev/null

device_home="$work/device-home"
mkdir -p "$device_home"
chmod 0700 "$device_home"
cat >"$device_home/ego-browser-policy.json" <<'EOF'
{"version":1,"policy_revision":1,"allowlist_revision":1,"allowlist_roots":[],"allowlist_roots_digest":null,"learning_bundle_root":null}
EOF
chmod 0600 "$device_home/ego-browser-policy.json"
device="$root/target/debug/ego-browser-device"
bridge="$root/target/debug/ego-browser-bridge"
wrapper="$root/target/debug/ego-browser"
cli="$cli_root/target/debug/agent-remote"

run_device() {
  SSL_CERT_FILE="$work/ca.crt" \
  EGO_BROWSER_DEVICE_HOME="$device_home" \
  EGO_BROWSER_EXECUTABLE="$fake_runtime" \
  EGO_BROWSER_RELEASE_PROFILE="$release_profile" \
  EGO_BROWSER_SIGNER_CERTIFICATE_SHA256="$certificate_digest" \
    "$device" "$@"
}

cli_home="$work/cli-home"
cli_user_home="$work/cli-user-home"
install_root="$work/bridge-install"
release="$install_root/releases/0.1.12"
installer_log="$work/setup-installer-args.log"
uninstaller_log="$work/uninstaller.log"
device_args_log="$work/setup-device-args.log"
mkdir -p "$cli_home/secrets" "$cli_user_home" "$release/bin" "$release/installer"
chmod 0700 "$cli_home" "$cli_home/secrets" "$cli_user_home" "$install_root" \
  "$install_root/releases" "$release" "$release/bin" "$release/installer"
printf '%s\n' '0.1.12' >"$release/VERSION"
cat >"$release/SIGNING-EVIDENCE.json" <<'EOF'
{
  "schema_version": 1,
  "version": "0.1.12",
  "profile": "community-local-trust",
  "signer_certificate_sha256": "1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5"
}
EOF
printf '%s\n' \
  '1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5' \
  >"$install_root/TRUSTED_CERTIFICATE_SHA256"
chmod 0400 "$release/VERSION" "$release/SIGNING-EVIDENCE.json" \
  "$install_root/TRUSTED_CERTIFICATE_SHA256"
cat >"$release/installer/install-macos.sh" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 2
test "$1" = "--setup"
test "$2" = "--yes"
test "${EGO_BROWSER_DEVICE_HOME:-}" = "$EGO_BROWSER_E2E_DEVICE_HOME"
printf '%s\n' "$*" >>"$EGO_BROWSER_E2E_INSTALLER_ARGS_LOG"
EOF
cat >"$release/installer/uninstall-macos.sh" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 0
test "${EGO_BROWSER_INSTALL_ROOT:-}" = "$EGO_BROWSER_E2E_INSTALL_ROOT"
test -L "$EGO_BROWSER_INSTALL_ROOT/current"
printf '%s\n' uninstall >>"$EGO_BROWSER_E2E_UNINSTALLER_LOG"
rm -f -- "$EGO_BROWSER_INSTALL_ROOT/current"
EOF
cat >"$release/bin/ego-browser-device" <<'EOF'
#!/bin/sh
set -eu
test "${EGO_BROWSER_DEVICE_HOME:-}" = "$EGO_BROWSER_E2E_DEVICE_HOME"
printf '%s\n' "$*" >>"$EGO_BROWSER_E2E_DEVICE_ARGS_LOG"
if [ "${1:-}" = "ensure" ]; then
  exec "$EGO_BROWSER_E2E_REAL_DEVICE" "$@" \
    --release-profile development-local \
    --signer-certificate-sha256 development
fi
exec "$EGO_BROWSER_E2E_REAL_DEVICE" "$@"
EOF
chmod 0500 "$release/installer/install-macos.sh" \
  "$release/installer/uninstall-macos.sh" "$release/bin/ego-browser-device"
ln -s "$release" "$install_root/current"

printf 'server_url = "%s"\n' "$server_url" >"$cli_home/config.toml"
chmod 0600 "$cli_home/config.toml"
secret_key="user-token:$server_url"
secret_key=${secret_key//[^a-zA-Z0-9_.-]/_}
printf '%s' "$user_token" >"$cli_home/secrets/$secret_key.secret"
chmod 0600 "$cli_home/secrets/$secret_key.secret"

# Select the development profile without bypassing trust or token validation.
run_managed_cli() {
  HOME="$cli_user_home" \
  SSL_CERT_FILE="$work/ca.crt" \
  AGENT_REMOTE_HOME="$cli_home" \
  AGENT_REMOTE_SECRET_BACKEND=file \
  AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME="$device_home" \
  EGO_BROWSER_INSTALL_ROOT="$install_root" \
  EGO_BROWSER_EXECUTABLE="$fake_runtime" \
  EGO_BROWSER_E2E_DEVICE_HOME="$device_home" \
  EGO_BROWSER_E2E_INSTALL_ROOT="$install_root" \
  EGO_BROWSER_E2E_INSTALLER_ARGS_LOG="$installer_log" \
  EGO_BROWSER_E2E_UNINSTALLER_LOG="$uninstaller_log" \
  EGO_BROWSER_E2E_DEVICE_ARGS_LOG="$device_args_log" \
  EGO_BROWSER_E2E_REAL_DEVICE="$device" \
    "$cli" --json --color never "$@"
}

run_managed_setup() {
  run_managed_cli ego-browser setup --yes
}

if ! run_managed_setup >"$work/setup-first.json"; then
  cat "$work/setup-first.json" >&2
  cat "$work/server.log" >&2
  exit 1
fi
identity_sha256=$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')
if ! run_managed_setup >"$work/setup-repeat.json"; then
  cat "$work/setup-repeat.json" >&2
  cat "$work/server.log" >&2
  exit 1
fi
test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
  "$identity_sha256"
python3 - "$work/server.sqlite3" "$work/setup-first.json" "$work/setup-repeat.json" \
  "$device_home/ego-browser-device-key.bin" "$device_home/ego-browser-local-admission.json" <<'PY'
import json
import os
import stat
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    device_count = connection.execute("SELECT count(*) FROM ego_browser_devices").fetchone()[0]
    ensure_count = connection.execute("SELECT count(*) FROM ego_browser_ensure_requests").fetchone()[0]
    binding_count = connection.execute("SELECT count(*) FROM ego_browser_bindings").fetchone()[0]
assert device_count == 1, device_count
assert ensure_count == 1, ensure_count
assert binding_count == 0, binding_count
for path in sys.argv[2:4]:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert result["error_code"] is None, result
    assert result["command"] == "setup", result
    assert result["result"] == "ready", result
key_metadata = os.stat(sys.argv[4], follow_symlinks=False)
assert stat.S_IMODE(key_metadata.st_mode) == 0o600, oct(stat.S_IMODE(key_metadata.st_mode))
assert key_metadata.st_nlink == 1, key_metadata.st_nlink
with open(sys.argv[5], encoding="utf-8") as handle:
    admission = json.load(handle)
assert admission["state"] == "ready", admission
PY

run_concurrent_managed_setup() {
  run_managed_setup >"$work/setup-concurrent-a.json" &
  setup_a_pid=$!
  run_managed_setup >"$work/setup-concurrent-b.json" &
  setup_b_pid=$!
  setup_a_status=0
  setup_b_status=0
  if wait "$setup_a_pid"; then
    setup_a_status=0
  else
    setup_a_status=$?
  fi
  setup_a_pid=""
  if wait "$setup_b_pid"; then
    setup_b_status=0
  else
    setup_b_status=$?
  fi
  setup_b_pid=""
  if [ "$setup_a_status" -ne 0 ] && [ "$setup_b_status" -ne 0 ]; then
    cat "$work/setup-concurrent-a.json" "$work/setup-concurrent-b.json" >&2
    exit 1
  fi
  python3 - "$work/setup-concurrent-a.json" "$setup_a_status" \
    "$work/setup-concurrent-b.json" "$setup_b_status" <<'PY'
import json
import sys

for path, raw_status in ((sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])):
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    status = int(raw_status)
    if status == 0:
        assert result["error_code"] is None, result
        assert result["result"] == "ready", result
    else:
        assert result["error_code"] == "local_lock_busy", result
PY
}

run_concurrent_managed_setup
test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
  "$identity_sha256"
python3 - "$work/server.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    device_count = connection.execute("SELECT count(*) FROM ego_browser_devices").fetchone()[0]
    ensure_count = connection.execute("SELECT count(*) FROM ego_browser_ensure_requests").fetchone()[0]
assert device_count == 1, device_count
assert ensure_count == 1, ensure_count
PY

refresh_expired_credential_with_managed_setup() {
  credential="$device_home/ego-browser-credential.json"
  initial_revision=$(json_field "$credential" revision)
  python3 - "$credential" <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    credential = json.load(handle)
credential["expires_at_unix"] = 1
temporary = f"{path}.expire-{os.getpid()}"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(credential, handle, separators=(",", ":"))
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, path)
PY
  if ! run_managed_setup >"$work/setup-refresh.json"; then
    cat "$work/setup-refresh.json" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  refreshed_revision=$(json_field "$credential" revision)
  test "$refreshed_revision" -gt "$initial_revision"
}

refresh_expired_credential_with_managed_setup
test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
  "$identity_sha256"
python3 - "$work/server.sqlite3" "$work/setup-refresh.json" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    device_count = connection.execute("SELECT count(*) FROM ego_browser_devices").fetchone()[0]
    ensure_count = connection.execute("SELECT count(*) FROM ego_browser_ensure_requests").fetchone()[0]
    binding_count = connection.execute("SELECT count(*) FROM ego_browser_bindings").fetchone()[0]
assert device_count == 1, device_count
assert ensure_count == 2, ensure_count
assert binding_count == 0, binding_count
with open(sys.argv[2], encoding="utf-8") as handle:
    result = json.load(handle)
assert result["error_code"] is None, result
assert result["result"] == "ready", result
PY

recover_lost_credential_commit_with_managed_setup() {
  credential="$device_home/ego-browser-credential.json"
  pending="$device_home/ego-browser-pending-registration.json"
  stale_credential="$work/lost-commit-stale-credential.json"
  pending_snapshot="$work/lost-commit-pending-registration.json"
  committed_credential="$work/lost-commit-server-result.json"
  operation_key="lost-credential-commit-e2e-key-20260914"

  # Restore post-response, pre-commit state to verify idempotent recovery.
  python3 - "$work/server.sqlite3" "$credential" "$pending" \
    "$stale_credential" "$pending_snapshot" "$operation_key" <<'PY'
import hashlib
import json
import os
import sqlite3
import sys
import time


def atomic_json(path, value):
    temporary = f"{path}.replace-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


database, credential_path, pending_path, stale_path, pending_snapshot, operation_key = sys.argv[1:]
with open(credential_path, encoding="utf-8") as handle:
    credential = json.load(handle)
with sqlite3.connect(database) as connection:
    rows = connection.execute(
        "SELECT generation, public_key, encryption_public_key, release_profile, "
        "credential_profile, server_origin FROM ego_browser_devices"
    ).fetchall()
assert len(rows) == 1, rows
generation, public_key, encryption_public_key, release_profile, credential_profile, origin = rows[0]
assert release_profile == credential["release_profile"], (release_profile, credential)
assert credential_profile == credential["credential_profile"], (credential_profile, credential)
assert origin == credential["server_url"], (origin, credential)
pending = {
    "version": 1,
    "device_id": credential["device_id"],
    "device_generation": generation,
    "server_url": credential["server_url"],
    "release_profile": release_profile,
    "credential_profile": credential_profile,
    "enrollment_mode": "ensure",
    "signing_public_key_sha256": hashlib.sha256(public_key.encode("ascii")).hexdigest(),
    "encryption_public_key_sha256": hashlib.sha256(
        encryption_public_key.encode("ascii")
    ).hexdigest(),
    "idempotency_key": operation_key,
    "created_at_unix": int(time.time()),
    "last_error_code": None,
}
credential["expires_at_unix"] = 1
atomic_json(credential_path, credential)
atomic_json(stale_path, credential)
atomic_json(pending_path, pending)
atomic_json(pending_snapshot, pending)
PY

  if ! run_managed_setup >"$work/setup-lost-commit-first.json"; then
    cat "$work/setup-lost-commit-first.json" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  test ! -e "$pending"
  cp -p "$credential" "$committed_credential"

  python3 - "$stale_credential" "$credential" "$pending_snapshot" "$pending" <<'PY'
import os
import sys


def atomic_copy(source, destination):
    temporary = f"{destination}.restore-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(source, "rb") as source_file, os.fdopen(descriptor, "wb") as destination_file:
        destination_file.write(source_file.read())
        destination_file.flush()
        os.fsync(destination_file.fileno())
    os.replace(temporary, destination)


atomic_copy(sys.argv[1], sys.argv[2])
atomic_copy(sys.argv[3], sys.argv[4])
PY

  if ! run_managed_setup >"$work/setup-lost-commit-recovered.json"; then
    cat "$work/setup-lost-commit-recovered.json" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  cmp "$committed_credential" "$credential"
  test ! -e "$pending"
  test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
    "$identity_sha256"
  python3 - "$work/server.sqlite3" "$work/setup-lost-commit-first.json" \
    "$work/setup-lost-commit-recovered.json" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    device_count = connection.execute("SELECT count(*) FROM ego_browser_devices").fetchone()[0]
    ensure_count = connection.execute("SELECT count(*) FROM ego_browser_ensure_requests").fetchone()[0]
    credential_count = connection.execute(
        "SELECT count(*) FROM ego_browser_device_credentials"
    ).fetchone()[0]
assert device_count == 1, device_count
assert ensure_count == 3, ensure_count
assert credential_count == 3, credential_count
for path in sys.argv[2:]:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert result["error_code"] is None, result
    assert result["result"] == "ready", result
PY
}

recover_lost_credential_commit_with_managed_setup

expected_device_args="ensure --server $server_url --token-stdin"
python3 - "$installer_log" "$device_args_log" "$expected_device_args" <<'PY'
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    installer_calls = handle.read().splitlines()
with open(sys.argv[2], encoding="utf-8") as handle:
    device_calls = handle.read().splitlines()
assert installer_calls == ["--setup --yes"] * 7, installer_calls
assert device_calls == [sys.argv[3]] * 7, device_calls
PY
if grep -Fq "$user_token" "$work/setup-first.json" "$work/setup-repeat.json" \
  "$work/setup-concurrent-a.json" "$work/setup-concurrent-b.json" \
  "$work/setup-refresh.json" "$work/setup-lost-commit-first.json" \
  "$work/setup-lost-commit-recovered.json" "$installer_log" "$device_args_log"; then
  echo "managed setup exposed its control-plane token" >&2
  exit 1
fi

mismatch_setup_closes_local_admission() {
  printf '%s\n' '9.9.9' >"$runtime_version_file"
  if run_managed_setup >"$work/setup-runtime-mismatch.json"; then
    echo "managed setup accepted an unsupported runtime" >&2
    exit 1
  fi
  python3 - "$work/setup-runtime-mismatch.json" \
    "$device_home/ego-browser-local-admission.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
assert result["error_code"] == "compatibility_mismatch", result
with open(sys.argv[2], encoding="utf-8") as handle:
    admission = json.load(handle)
assert admission["state"] == "closed", admission
PY
  test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
    "$identity_sha256"
  test ! -e "$device_home/ego-browser-pending-registration.json"

  printf '%s\n' '0.4.7.4' >"$runtime_version_file"
  run_managed_setup >"$work/setup-runtime-recovered.json"
  test "$(json_field "$device_home/ego-browser-local-admission.json" state)" = ready

  python3 - "$device_home/ego-browser-policy.json" invalid <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    policy = json.load(handle)
policy["allowlist_roots_digest"] = "sha256:" + "0" * 64 if sys.argv[2] == "invalid" else None
temporary = f"{path}.replace-{os.getpid()}"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(policy, handle, separators=(",", ":"))
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, path)
PY
  if run_managed_setup >"$work/setup-policy-mismatch.json"; then
    echo "managed setup accepted a tampered local policy" >&2
    exit 1
  fi
  python3 - "$work/setup-policy-mismatch.json" \
    "$device_home/ego-browser-local-admission.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
assert result["error_code"] == "compatibility_mismatch", result
with open(sys.argv[2], encoding="utf-8") as handle:
    admission = json.load(handle)
assert admission["state"] == "closed", admission
PY
  test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
    "$identity_sha256"
  test ! -e "$device_home/ego-browser-pending-registration.json"

  python3 - "$device_home/ego-browser-policy.json" valid <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    policy = json.load(handle)
policy["allowlist_roots_digest"] = None
temporary = f"{path}.replace-{os.getpid()}"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(policy, handle, separators=(",", ":"))
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, path)
PY
  run_managed_setup >"$work/setup-policy-recovered.json"
  test "$(json_field "$device_home/ego-browser-local-admission.json" state)" = ready
  test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
    "$identity_sha256"
  python3 - "$work/server.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    device_count = connection.execute("SELECT count(*) FROM ego_browser_devices").fetchone()[0]
    ensure_count = connection.execute("SELECT count(*) FROM ego_browser_ensure_requests").fetchone()[0]
assert device_count == 1, device_count
assert ensure_count == 3, ensure_count
PY
  if grep -Fq "$user_token" "$work/setup-runtime-mismatch.json" \
    "$work/setup-runtime-recovered.json" "$work/setup-policy-mismatch.json" \
    "$work/setup-policy-recovered.json"; then
    echo "mismatch setup exposed its control-plane token" >&2
    exit 1
  fi
}

mismatch_setup_closes_local_admission
run_device candidates >"$work/candidates.json"
python3 - "$work/candidates.json" "$tool_session_id" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))["data"]["items"]
assert any(item["tool_session_id"] == sys.argv[2] and item["controllable"] for item in items)
PY
run_device claim "$tool_session_id" --confirm \
  >"$work/claim.json" 2>"$work/claim.err"
binding_file="$device_home/ego-browser-active-binding.json"
binding_id=$(json_field "$binding_file" binding_id)

run_device service >"$work/device.log" 2>&1 &
device_pid=$!
for _ in $(seq 1 200); do
  [ -S "$device_home/device-service.sock" ] && break
  kill -0 "$device_pid" 2>/dev/null || {
    cat "$work/device.log" >&2
    exit 1
  }
  sleep 0.05
done
test -S "$device_home/device-service.sock"

broker_context="$work/broker-context.json"
SSL_CERT_FILE="$work/ca.crt" \
  "$work/ego-browser-broker-integration" \
    --server-url "$server_url" \
    --node-id "$node_id" \
    --node-token "$node_token" \
    --tool-session-id "$tool_session_id" \
    --socket "$work/broker.sock" \
    --state-root "$work/broker-state" \
    --ca-certificate "$work/ca.crt" \
    --context-file "$broker_context" >"$work/broker.log" 2>&1 &
broker_pid=$!
for _ in $(seq 1 200); do
  [ -f "$broker_context" ] && break
  kill -0 "$broker_pid" 2>/dev/null || {
    cat "$work/broker.log" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$broker_context"
broker_socket=$(json_field "$broker_context" broker_socket)
broker_nonce=$(json_field "$broker_context" startup_nonce)

SSL_CERT_FILE="$work/ca.crt" \
EGO_BROWSER_DEVICE_HOME="$device_home" \
EGO_BROWSER_EXECUTABLE="$fake_runtime" \
EGO_BROWSER_WORK_ROOT="$work/bridge-work" \
EGO_BROWSER_RELEASE_PROFILE="$release_profile" \
EGO_BROWSER_CREDENTIAL_PROFILE=community_file \
EGO_BROWSER_SIGNER_CERTIFICATE_SHA256="$certificate_digest" \
  "$bridge" --outbound --once --credential-dir "$device_home" \
  >"$work/bridge.log" 2>&1 &
bridge_pid=$!

run_wrapper() {
  EGO_BROWSER_BROKER_SOCKET="$broker_socket" \
  EGO_BROWSER_BROKER_NONCE="$broker_nonce" \
  EGO_BROWSER_DEFAULT_TASK_SPACE="user-owned-space" \
  EGO_BROWSER_CONCURRENCY_MODE=task_space \
  EGO_BROWSER_TASK_SPACE_SCOPE="agent-remote:$tool_session_id" \
    "$wrapper" "$@"
}

for _ in $(seq 1 200); do
  doctor=$(run_wrapper --doctor 2>/dev/null || true)
  if python3 - "$doctor" <<'PY'
import json
import sys
try:
    bindings = json.loads(sys.argv[1])["bindings"]
except (KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if len(bindings) == 1 and bindings[0]["status"] == "active" else 1)
PY
  then
    break
  fi
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done

renew_path="\"path\": \"/api/v1/ego-browser/bindings/$binding_id/renew\""
for _ in $(seq 1 200); do
  grep -Fq "$renew_path" "$work/server.log" && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
grep -Fq "$renew_path" "$work/server.log"

for round in 1 2 3; do
  output=$(printf "cliLog('real-relay-round-%s')\n" "$round" | run_wrapper nodejs)
  grep -Fq "real-relay-runtime-round=$round" <<<"$output"
  grep -Fq "real-relay-round-$round" <<<"$output"
  grep -Fq "const agentRemoteDefaultTaskSpace = \"agent-remote:$tool_session_id\";" <<<"$output"
  ! grep -Fq 'const agentRemoteDefaultTaskSpace = "user-owned-space";' <<<"$output"
done
test "$(tr -d '[:space:]' <"$counter")" = "3"

for _ in $(seq 1 100); do
  [ -f "$monitor_armed_file" ] && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$monitor_armed_file"

(
  cat <<'EOF' | run_wrapper nodejs
// takeover-e2e-marker
try {
  await snapshotText()
} catch (_error) {
  cliLog('helper error was caught; the managed process is still running')
}
await new Promise(() => {})
EOF
) >"$work/takeover.out" 2>"$work/takeover.err" &
wrapper_pid=$!
for _ in $(seq 1 200); do
  [ -f "$takeover_child_pid_file" ] && break
  kill -0 "$wrapper_pid" 2>/dev/null || {
    cat "$work/takeover.err" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$takeover_child_pid_file"
takeover_child=$(tr -d '[:space:]' <"$takeover_child_pid_file")
printf '%s\n' user >"$ownership_file"
if wait "$wrapper_pid"; then
  echo "Task Space takeover did not stop the remote request" >&2
  exit 1
fi
wrapper_pid=""
if wait "$bridge_pid"; then
  echo "Task Space takeover did not stop the outbound Bridge" >&2
  exit 1
fi
bridge_pid=""
for _ in $(seq 1 100); do
  ! kill -0 "$takeover_child" 2>/dev/null && break
  sleep 0.05
done
if kill -0 "$takeover_child" 2>/dev/null; then
  echo "Task Space takeover left the supervised browser descendant running" >&2
  exit 1
fi

python3 - "$work/server.sqlite3" "$binding_id" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
status, generation, reason = connection.execute(
    "SELECT status, generation, stop_reason FROM ego_browser_bindings WHERE id = ?",
    (sys.argv[2].replace("-", ""),),
).fetchone()
assert (status, generation, reason) == ("paused", 2, "task_space_takeover")
ledger = dict(
    connection.execute(
        "SELECT direction, count(*) FROM ego_browser_request_ledger GROUP BY direction"
    ).fetchall()
)
assert ledger == {"request": 4, "response": 3}, ledger
PY

run_device resume "$binding_id" --generation 2 --confirm \
  >"$work/resume.json" 2>"$work/resume.err"
test "$(json_field "$binding_file" generation)" = "3"
test "$(json_field "$binding_file" task_space_label)" = "agent-remote:$tool_session_id"

kill "$broker_pid" >/dev/null 2>&1 || true
wait "$broker_pid" >/dev/null 2>&1 || true
broker_pid=""
broker_context="$work/broker-context-resumed.json"
SSL_CERT_FILE="$work/ca.crt" \
  "$work/ego-browser-broker-integration" \
    --server-url "$server_url" \
    --node-id "$node_id" \
    --node-token "$node_token" \
    --tool-session-id "$tool_session_id" \
    --socket "$work/broker-resumed.sock" \
    --state-root "$work/broker-state" \
    --ca-certificate "$work/ca.crt" \
    --context-file "$broker_context" >>"$work/broker.log" 2>&1 &
broker_pid=$!
for _ in $(seq 1 200); do
  [ -f "$broker_context" ] && break
  kill -0 "$broker_pid" 2>/dev/null || {
    cat "$work/broker.log" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$broker_context"
broker_socket=$(json_field "$broker_context" broker_socket)
broker_nonce=$(json_field "$broker_context" startup_nonce)

rm -f -- "$monitor_armed_file"
SSL_CERT_FILE="$work/ca.crt" \
EGO_BROWSER_DEVICE_HOME="$device_home" \
EGO_BROWSER_EXECUTABLE="$fake_runtime" \
EGO_BROWSER_WORK_ROOT="$work/bridge-work" \
EGO_BROWSER_RELEASE_PROFILE="$release_profile" \
EGO_BROWSER_CREDENTIAL_PROFILE=community_file \
EGO_BROWSER_SIGNER_CERTIFICATE_SHA256="$certificate_digest" \
  "$bridge" --outbound --once --credential-dir "$device_home" \
  >>"$work/bridge.log" 2>&1 &
bridge_pid=$!

for _ in $(seq 1 200); do
  doctor=$(run_wrapper --doctor 2>/dev/null || true)
  if python3 - "$doctor" <<'PY'
import json
import sys
try:
    bindings = json.loads(sys.argv[1])["bindings"]
except (KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if len(bindings) == 1 and bindings[0]["status"] == "active" else 1)
PY
  then
    break
  fi
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done

recovery_output=$(cat <<EOF | run_wrapper nodejs
const task = await takeOverTaskSpace('agent-remote:$tool_session_id')
cliLog(JSON.stringify({ recovered: true, id: task.id }))
EOF
)
grep -Fq "takeOverTaskSpace('agent-remote:$tool_session_id')" <<<"$recovery_output"
for _ in $(seq 1 100); do
  [ -f "$monitor_armed_file" ] && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$monitor_armed_file"

(
  printf '%s\n' "cliLog('revocation-e2e-marker')" | run_wrapper nodejs
) >"$work/revoked.out" 2>"$work/revoked.err" &
wrapper_pid=$!
for _ in $(seq 1 200); do
  [ -f "$child_pid_file" ] && break
  kill -0 "$wrapper_pid" 2>/dev/null || {
    cat "$work/revoked.err" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$child_pid_file"
revoked_child=$(tr -d '[:space:]' <"$child_pid_file")
run_device stop "$binding_id" --generation 3 >"$work/stop.json"
if wait "$wrapper_pid"; then
  echo "revoked real-relay wrapper execution unexpectedly succeeded" >&2
  exit 1
fi
wrapper_pid=""
for _ in $(seq 1 100); do
  ! kill -0 "$revoked_child" 2>/dev/null && break
  sleep 0.05
done
if kill -0 "$revoked_child" 2>/dev/null; then
  echo "revocation left the supervised browser descendant running" >&2
  exit 1
fi

python3 - "$work/server.sqlite3" "$binding_id" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
status, generation = connection.execute(
    "SELECT status, generation FROM ego_browser_bindings WHERE id = ?",
    (sys.argv[2].replace("-", ""),),
).fetchone()
assert (status, generation) == ("stopped", 4)
ledger = dict(
    connection.execute(
        "SELECT direction, count(*) FROM ego_browser_request_ledger GROUP BY direction"
    ).fetchall()
)
assert ledger == {"request": 6, "response": 4}, ledger
pending = connection.execute(
    "SELECT count(*) FROM ego_browser_revocation_outbox WHERE delivered_at IS NULL"
).fetchone()[0]
assert pending == 0, pending
PY

for log in "$work/server.log" "$work/broker.log" "$work/bridge.log" "$work/device.log"; do
  for marker in "takeover-e2e-marker" "revocation-e2e-marker"; do
    if grep -Fq "$marker" "$log"; then
      echo "browser script content leaked into $(basename "$log")" >&2
      exit 1
    fi
  done
done
grep -Fq "ego-browser-bridge error=protocol_error" "$work/bridge.log"
if grep -Fq "Task Space control was taken over; explicit binding resume is required" "$work/bridge.log"; then
  echo "Bridge operational log rendered unrestricted error text" >&2
  exit 1
fi
grep -Fq "ego_browser_revocations_total" "$work/server.log"
grep -Fq "ego_browser_bytes_total" "$work/server.log"
grep -Fq "ego_browser_execute_total" "$work/broker.log"
grep -Fq '"metric":"ego_browser_execute_total"' "$work/bridge.log"
grep -Fq '"metric":"ego_browser_device_bridge_peers"' "$work/device.log"

remove_then_forget_with_retained_release() {
  for pid in "$bridge_pid" "$broker_pid" "$device_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  bridge_pid=""
  broker_pid=""
  device_pid=""

  if ! run_managed_cli ego-browser remove --yes >"$work/remove.json"; then
    cat "$work/remove.json" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  test ! -L "$install_root/current"
  test -x "$release/bin/ego-browser-device"
  test "$(shasum -a 256 "$device_home/ego-browser-device-key.bin" | awk '{print $1}')" = \
    "$identity_sha256"
  test -f "$device_home/ego-browser-device-metadata.json"
  test -f "$device_home/ego-browser-policy.json"
  test ! -e "$device_home/ego-browser-credential.json"
  test ! -e "$device_home/ego-browser-active-binding.json"

  if ! run_managed_cli ego-browser forget-this-mac --yes >"$work/forget.json"; then
    cat "$work/forget.json" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  for state_file in ego-browser-device-key.bin ego-browser-device-metadata.json \
    ego-browser-credential.json ego-browser-policy.json ego-browser-active-binding.json \
    ego-browser-pending-registration.json ego-browser-local-admission.json; do
    test ! -e "$device_home/$state_file"
  done
  test ! -e "$cli_home/ego-browser-pending-revocation.json"

  python3 - "$work/server.sqlite3" "$device_args_log" "$uninstaller_log" \
    "$work/remove.json" "$work/forget.json" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    devices = connection.execute(
        "SELECT status FROM ego_browser_devices"
    ).fetchall()
assert devices == [("revoked",)], devices
with open(sys.argv[2], encoding="utf-8") as handle:
    calls = handle.read().splitlines()
assert calls[-4:] == [
    "metadata",
    "retire-local --confirmed-stopped",
    "metadata",
    "purge-local --confirmed-revoked",
], calls
with open(sys.argv[3], encoding="utf-8") as handle:
    assert handle.read().splitlines() == ["uninstall"]
for path, command in ((sys.argv[4], "remove"), (sys.argv[5], "forget-this-mac")):
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert result["error_code"] is None, result
    assert result["command"] == command, result
PY
  if grep -Fq "$user_token" "$work/remove.json" "$work/forget.json" \
    "$uninstaller_log" "$device_args_log"; then
    echo "remove/forget exposed its control-plane token" >&2
    exit 1
  fi
}

remove_then_forget_with_retained_release

echo "real relay E2E passed: managed setup, TLS/PoP relay, Task Space takeover, heartbeat, remove, and forget"
