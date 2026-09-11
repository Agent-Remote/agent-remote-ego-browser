#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
workspace_parent=$(dirname "$root")
server_root=${AGENT_REMOTE_SERVER_ROOT:-"$workspace_parent/agent-remote-server"}
node_root=${AGENT_REMOTE_NODE_ROOT:-"$workspace_parent/agent-remote-node"}
redis_url=${AGENT_REMOTE_INTEGRATION_REDIS_URL:-redis://127.0.0.1:6379/14}
work=$(mktemp -d "/tmp/ego-browser-relay.XXXXXX")
work=$(cd "$work" && pwd -P)
server_pid=""
device_pid=""
broker_pid=""
bridge_pid=""
wrapper_pid=""

cleanup() {
  for pid in "$wrapper_pid" "$bridge_pid" "$broker_pid" "$device_pid" "$server_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf -- "$work"
}
trap cleanup EXIT

for directory in "$server_root" "$node_root"; do
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
certificate_digest=$(printf 'a%.0s' $(seq 1 64))

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
(
  cd "$node_root"
  go build -o "$work/ego-browser-broker-integration" \
    ./internal/egobrowser/integrationtest
)

fake_runtime="$work/local-ego-browser"
counter="$work/runtime-count"
child_pid_file="$work/revoked-descendant-pid"
takeover_child_pid_file="$work/takeover-descendant-pid"
ownership_file="$work/task-space-ownership"
monitor_armed_file="$work/task-space-monitor-armed"
cat >"$fake_runtime" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf '%s\n' 'ego-browser 0.4.7.4' '  chromium 150.0.7871.101' '  node v24.18.0'
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
  EGO_BROWSER_EXPECTED_RELEASE_PROFILE=community-local-trust \
  EGO_BROWSER_EXPECTED_SIGNER_CERTIFICATE_SHA256="$certificate_digest" \
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
device="$root/target/debug/ego-browser-device"
bridge="$root/target/debug/ego-browser-bridge"
wrapper="$root/target/debug/ego-browser"

run_device() {
  SSL_CERT_FILE="$work/ca.crt" \
  EGO_BROWSER_DEVICE_HOME="$device_home" \
  EGO_BROWSER_EXECUTABLE="$fake_runtime" \
  EGO_BROWSER_SIGNER_CERTIFICATE_SHA256="$certificate_digest" \
    "$device" "$@"
}

run_device register \
  --server "$server_url" \
  --token "$user_token" \
  --signer-certificate-sha256 "$certificate_digest" >"$work/register.out"
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
EGO_BROWSER_RELEASE_PROFILE=community-local-trust \
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
EGO_BROWSER_RELEASE_PROFILE=community-local-trust \
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

echo "real relay E2E passed: TLS/PoP relay, Task Space takeover pause/resume, heartbeat, and revocation cleanup"
