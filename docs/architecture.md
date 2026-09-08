# Architecture

## Data path

```text
remote fclaude session
  -> official ego-browser Skill
  -> immutable Linux ego-browser wrapper
  -> owner-only Node broker socket
  -> authenticated control-plane relay
  -> outbound macOS Bridge connection
  -> real local ego-browser process
  -> ego lite and its existing local profile
```

The wrapper reads one bounded heredoc and asks the trusted Node broker for a
single-use permit. The broker, not the wrapper, owns the binding identity,
generation, relay ticket, monotonic sequence, lease renewal, and relay socket.
The wrapper cannot choose a user, device, tool session, Node, or generation.
The broker also derives `agent-remote:<tool_session_id>` from the authenticated
session nonce and returns it in the permit. The wrapper copies that value into
the encrypted request instead of trusting a shell environment override.

The remote wrapper is available in both `native` and `docker_sandbox` Linux
Claude runtimes. The privileged Node helper resolves the identity from
root-owned runtime state: a dedicated non-root host UID for Native Runtime, or
the configured fixed non-root runtime UID/GID for Docker Sandbox. Docker startup
also verifies and mounts the release-pinned wrapper, Skill, and broker path.
Numeric POSIX ACLs grant only that resolved identity traverse access to the
broker directory and read/write access to the broker socket; the broker then
requires both the process-local nonce and an exact Linux `SO_PEERCRED` match.
UID 0, stale trusted specs, mismatched mounts, and unresolved identities are
ineligible.

The Server authenticates and validates the outer envelope, including channel,
binding kind, binding ID, generation, sequence, direction, ciphertext length,
and request ID. It forwards opaque ciphertext and never receives the script,
stdout, stderr, screenshot bytes, page data, URLs, or local paths.

For each request, the broker creates a random ChaCha20-Poly1305 key and wraps it
to the registered Bridge X25519 public key. The key-wrap transcript binds the
binding, generation, request ID, and sequence. Outer routing fields are AEAD
associated data, so the relay cannot alter them without authentication failure.

Production Server workers share relay state through Redis. One-use tickets and
proof challenges are atomically consumed, binding/generation/role presence has
a five-second TTL, and endpoint-specific Pub/Sub channels carry opaque frames
and close notifications. The two roles may terminate on different workers.
Duplicate role presence, missing subscribers, stale presence, malformed shared
state, or Redis failure closes the pair rather than falling back to local-only
pairing. PostgreSQL revocation outbox rows drive idempotent cross-worker close
notifications after lifecycle commits.

## Identity and authorization

The Device Client owns an independent Ed25519 proof-of-possession identity and
X25519 encryption key. A mutation first obtains a short-lived, single-use
Server challenge. Its signed transcript binds the operation, canonical request
payload, challenge, device and binding generations, release and credential
profiles, binding ID, and Server host. A challenge cannot be replayed or moved
to another operation or payload.

There is no automatic or "most recent session" binding. The user lists
candidates, selects one tool-session ID, sees the full-trust warning, and
confirms the claim. The Server derives the only valid Task Space label as
`agent-remote:<tool_session_id>` and rejects a client-supplied mismatch. The
Device Client requires the claim or resume response to return that same label
before saving it in the owner-only active-binding handoff. The Bridge loads the
label from that handoff and rejects an encrypted request whose default label or
declared Task Space scope differs. Only an `active` binding with a healthy lease
and matching capabilities can admit execution.

## Lifecycle

A binding starts with a 60-second lease, renews every 20 seconds, has a
10-second renewal-failure grace, and an eight-hour absolute TTL. Admission
requires at least 20 seconds of lease time. One execution is capped at 120
seconds, and a binding accepts at most four concurrent requests.

Normal requests use Task Space then Tab cooperative locks. Conflicts fail
immediately. Missing, wildcard, or unparseable scope takes the binding lock.
These locks avoid accidental workflow races; full-trust code can bypass them.
For the official Skill's normal path, the Bridge preamble remaps
`useOrCreateTaskSpace(...)` to the permit-derived dedicated name. It does not
eagerly select a space or wrap `claimTaskSpace`, `takeOverTaskSpace`, raw CDP,
or other full-trust helpers, so explicit handoff recovery and the documented
bypass semantics remain intact.

After activation, the Bridge starts a separate read-only ownership monitor
through the same execution supervisor used for requests. Its script calls only
ego lite's native `listTaskSpaces()` API and reads the matching space's `ownership`; it never
calls or wraps `useOrCreateTaskSpace`, `claimTaskSpace`, or
`takeOverTaskSpace`. A missing space or a pre-existing user-owned state does not
trigger a stop. The monitor first arms after observing `ownership="agent"` and
then treats a transition to `agentDelegatedToUser` or `user` as a takeover.
Duplicate matches, unknown ownership values, process failure, or unexpected
monitor exit are monitor-unavailable failures. The Bridge keeps the
supervisor's control pipe open, so Bridge death closes the pipe and terminates
the monitor runtime rather than leaving an independent browser client behind.

Pause, stop, revoke, tool-session termination, lease expiry, relay loss, policy
drift, and generation change stop new admission. The Bridge terminates its
managed process group and never replays a script whose result is unknown.
Completed side effects cannot be rolled back, and a deliberately detached
same-UID process is outside the supervisor's guarantee.

On Task Space takeover, the Bridge first revokes local admission and
waits for managed executions to terminate, then asks the Server to pause the
exact generation with reason `task_space_takeover`. Monitor loss follows the
same ordering with reason `task_space_monitor_unavailable`. Failure or timeout
of that bounded Server call never reopens local admission. The paused binding
keeps its canonical label, but the Device Client must explicitly confirm
resume, which advances the generation. Recovery may then use ego lite's native
claim/takeover helper to return ownership to the agent; neither the monitor nor
the Bridge performs an automatic claim or takeover.

The independent Device Client also acts as the local authorization liveness
peer. Its current-UID, mode `0600` Unix socket emits a fixed heartbeat every two
seconds. The Bridge checks socket identity before and after connect, verifies
the peer UID, requires the initial heartbeat, and enforces a five-second ongoing
timeout. On loss, ordering is fail closed: revoke the supervisor and terminate
managed executions, clear the local active-binding handoff, then attempt a
generation-bound Server stop for at most ten seconds. Failure to confirm the
Server stop never restores local admission.

## Local data

The browser profile remains in ego lite on the Mac. The control plane stores
only identity, authorization, version, policy digest, lifecycle, and audit
metadata. The Bridge uses a private work root for bounded stdout, stderr, and
screenshot staging and removes request directories after collection.

The helper file policy canonicalizes configured roots and rejects traversal,
symlinks, hard links, non-regular files, and configured size/count excesses.
It protects helper-mediated upload and artifact paths only. Full-trust script
code still has the filesystem and network rights of the Bridge user.

Bridge and Device Client metric events are content-free JSON lines with finite
status, direction, and media-type values. Their sources, alert conditions,
containment, and recovery procedures are listed in `operations.md`. Their
launch-agent-facing top-level failures likewise use finite error codes and
never render wrapped error text.
