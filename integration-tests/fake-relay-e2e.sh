#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-fake-relay.XXXXXX")
work=$(cd "$work" && pwd -P)
bridge_pid=""
cleanup() {
  if [ -n "$bridge_pid" ]; then
    kill "$bridge_pid" >/dev/null 2>&1 || true
    wait "$bridge_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

cargo build --quiet --locked -p ego-browser-bridge -p ego-browser-remote
bridge="$root/target/debug/ego-browser-bridge"
wrapper="$root/target/debug/ego-browser"
fake_runtime="$work/local-ego-browser"
counter="$work/runtime-count"
child_pid_file="$work/descendant-pid"
peer_loss_pid_file="$work/peer-loss-descendant-pid"
cat > "$fake_runtime" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf '%s\n' '{"ego_browser_version":"0.4.7.4","ego_lite_version":"0.4.7.4"}'
  exit 0
fi
test "\${1:-}" = "nodejs" || exit 64
script=\$(/bin/cat)
case "\$script" in
  *task-space-preamble-behavior*)
    printf '%s' "\$script" | node -e '
const fs = require("node:fs");
globalThis.__taskSpaceCalls = [];
globalThis.useOrCreateTaskSpace = async name => {
  globalThis.__taskSpaceCalls.push(name);
  return { id: 7, name };
};
globalThis.claimTaskSpace = async () => ({ claimed: true });
globalThis.takeOverTaskSpace = async () => ({ takenOver: true });
globalThis.cliLog = value => console.log(value);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
new AsyncFunction(fs.readFileSync(0, "utf8"))().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
'
    exit \$?
    ;;
esac
count=0
test ! -f '$counter' || count=\$(/bin/cat '$counter')
count=\$((count + 1))
printf '%s\n' "\$count" > '$counter'
case "\$script" in
  *artifact-marker*)
    /usr/bin/python3 -c 'import base64,sys; open(sys.argv[1], "wb").write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="))' "\$TMPDIR/capture.png"
    ;;
  *spawn-marker*)
    /bin/sleep 30 &
    descendant=\$!
    printf '%s\n' "\$descendant" > '$child_pid_file'
    wait "\$descendant"
    ;;
  *peer-loss-marker*)
    /bin/sleep 30 &
    descendant=\$!
    printf '%s\n' "\$descendant" > '$peer_loss_pid_file'
    wait "\$descendant"
    ;;
esac
printf 'runtime-round=%s\n%s' "\$count" "\$script"
EOF
chmod 0700 "$fake_runtime"

socket="$work/broker.sock"
nonce="fake-relay-nonce-$(id -u)-$$"
binding="binding-fake-relay"
EGO_BROWSER_EXECUTABLE="$fake_runtime" \
EGO_BROWSER_WORK_ROOT="$work/bridge-work" \
EGO_BROWSER_BINDING_ID="$binding" \
EGO_BROWSER_BROKER_NONCE="$nonce" \
EGO_BROWSER_DEFAULT_TASK_SPACE="agent-remote:test-session" \
EGO_BROWSER_RELEASE_PROFILE=development_local \
  "$bridge" --unix-socket --socket "$socket" >"$work/bridge.log" 2>&1 &
bridge_pid=$!
for _ in $(seq 1 100); do
  [ -S "$socket" ] && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
test -S "$socket"

run_wrapper() {
  EGO_BROWSER_BROKER_SOCKET="$socket" \
  EGO_BROWSER_BROKER_NONCE="$nonce" \
  EGO_BROWSER_DEFAULT_TASK_SPACE="user-owned-space" \
  EGO_BROWSER_CONCURRENCY_MODE=task_space \
  EGO_BROWSER_TASK_SPACE_SCOPE="agent-remote:test-session" \
    "$wrapper" "$@"
}

for round in 1 2 3; do
  output=$(printf "cliLog('remote-script-round-%s')\n" "$round" | run_wrapper nodejs)
  grep -Fq "runtime-round=$round" <<<"$output"
  grep -Fq "remote-script-round-$round" <<<"$output"
  grep -Fq 'const agentRemoteDefaultTaskSpace = "agent-remote:test-session";' <<<"$output"
  ! grep -Fq 'const agentRemoteDefaultTaskSpace = "user-owned-space";' <<<"$output"
done
test "$(tr -d '[:space:]' < "$counter")" = "3"

preamble_behavior=$(cat <<'EOF' | run_wrapper nodejs
// task-space-preamble-behavior
const task = await useOrCreateTaskSpace('must-not-be-selected')
cliLog(JSON.stringify({
  selectedName: task.name,
  calls: globalThis.__taskSpaceCalls,
  claimHelper: typeof globalThis.claimTaskSpace,
  takeoverHelper: typeof globalThis.takeOverTaskSpace
}))
EOF
)
grep -Fq '"selectedName":"agent-remote:test-session"' <<<"$preamble_behavior"
grep -Fq '"calls":["agent-remote:test-session"]' <<<"$preamble_behavior"
grep -Fq '"claimHelper":"function"' <<<"$preamble_behavior"
grep -Fq '"takeoverHelper":"function"' <<<"$preamble_behavior"
! grep -Fq '"selectedName":"must-not-be-selected"' <<<"$preamble_behavior"
test "$(tr -d '[:space:]' < "$counter")" = "3"

doctor=$(run_wrapper --doctor)
grep -Fq '"bridge":"ready"' <<<"$doctor"
if printf 'cliLog("wrong nonce")\n' | \
  EGO_BROWSER_BROKER_SOCKET="$socket" \
  EGO_BROWSER_BROKER_NONCE=wrong \
  "$wrapper" nodejs >"$work/wrong-nonce.out" 2>"$work/wrong-nonce.err"; then
  echo "wrapper request with the wrong startup nonce was accepted" >&2
  exit 1
fi
injected_binding_output=$(printf 'cliLog("injected binding ignored")\n' | \
  EGO_BROWSER_BROKER_SOCKET="$socket" \
  EGO_BROWSER_BROKER_NONCE="$nonce" \
  EGO_BROWSER_BINDING_ID=wrong-binding \
  "$wrapper" nodejs)
grep -Fq 'runtime-round=4' <<<"$injected_binding_output"
grep -Fq 'injected binding ignored' <<<"$injected_binding_output"
test "$(tr -d '[:space:]' < "$counter")" = "4"

wrapper_tmp="$work/wrapper-tmp"
mkdir "$wrapper_tmp"
chmod 0700 "$wrapper_tmp"
TMPDIR="$wrapper_tmp" run_wrapper nodejs <<'EOF' >"$work/artifact.out" 2>"$work/artifact.err"
cliLog('artifact-marker')
EOF
artifact_path=$(sed -n 's/^artifact: //p' "$work/artifact.err")
test -n "$artifact_path"
test -f "$artifact_path"
case "$artifact_path" in
  "$wrapper_tmp"/agent-remote-ego-browser-artifacts/request-*/*.png) ;;
  *) echo "wrapper reported an unexpected artifact path" >&2; exit 1 ;;
esac

if EGO_BROWSER_TIMEOUT_MS=150 run_wrapper nodejs <<'EOF' >"$work/timeout.out" 2>"$work/timeout.err"
cliLog('spawn-marker')
EOF
then
  echo "timed-out wrapper execution unexpectedly succeeded" >&2
  exit 1
fi
grep -Fq 'Timeout' "$work/timeout.err"
test -f "$child_pid_file"
descendant_pid=$(tr -d '[:space:]' < "$child_pid_file")
for _ in $(seq 1 40); do
  ! kill -0 "$descendant_pid" 2>/dev/null && break
  sleep 0.05
done
if kill -0 "$descendant_pid" 2>/dev/null; then
  echo "supervisor left the timed-out descendant running" >&2
  exit 1
fi

run_wrapper --reload >/dev/null
if printf 'cliLog("after revoke")\n' | run_wrapper nodejs >"$work/revoked.out" 2>"$work/revoked.err"; then
  echo "cancelled generation accepted a new execution" >&2
  exit 1
fi
test "$(tr -d '[:space:]' < "$counter")" = "6"

kill "$bridge_pid"
wait "$bridge_pid" >/dev/null 2>&1 || true
bridge_pid=""
socket="$work/peer.sock"
EGO_BROWSER_EXECUTABLE="$fake_runtime" \
EGO_BROWSER_WORK_ROOT="$work/peer-loss-bridge-work" \
EGO_BROWSER_BINDING_ID="$binding" \
EGO_BROWSER_BROKER_NONCE="$nonce" \
EGO_BROWSER_DEFAULT_TASK_SPACE="agent-remote:test-session" \
EGO_BROWSER_RELEASE_PROFILE=development_local \
  "$bridge" --unix-socket --socket "$socket" >"$work/peer-loss-bridge.log" 2>&1 &
bridge_pid=$!
for _ in $(seq 1 100); do
  [ -S "$socket" ] && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/peer-loss-bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
test -S "$socket"

(
  printf '%s\n' "cliLog('peer-loss-marker')" | run_wrapper nodejs
) >"$work/peer-loss.out" 2>"$work/peer-loss.err" &
wrapper_pid=$!
for _ in $(seq 1 100); do
  [ -f "$peer_loss_pid_file" ] && break
  kill -0 "$bridge_pid" 2>/dev/null || {
    cat "$work/bridge.log" >&2
    exit 1
  }
  sleep 0.05
done
test -f "$peer_loss_pid_file"
peer_loss_pid=$(tr -d '[:space:]' < "$peer_loss_pid_file")
kill -KILL "$bridge_pid"
wait "$bridge_pid" >/dev/null 2>&1 || true
bridge_pid=""
if wait "$wrapper_pid"; then
  echo "wrapper execution survived abrupt Bridge loss" >&2
  exit 1
fi
for _ in $(seq 1 40); do
  ! kill -0 "$peer_loss_pid" 2>/dev/null && break
  sleep 0.05
done
if kill -0 "$peer_loss_pid" 2>/dev/null; then
  echo "supervisor left the descendant running after Bridge loss" >&2
  exit 1
fi

echo "fake relay E2E passed: state, nonce/task-space authority, binding injection isolation, artifacts, timeout/revoke, and Bridge-loss cleanup"
