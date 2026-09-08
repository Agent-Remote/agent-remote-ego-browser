# Security Model

## Accepted trust boundary

Authorization mode `ego_browser_script_full_trust` grants arbitrary Node.js
heredoc execution under the Bridge's macOS UID without App Sandbox isolation.
It includes the complete ego lite browser surface, browser login data, cookies,
localhost and LAN access, user-readable files and environment, dynamic imports,
network requests, and subprocess creation. End-to-end encryption protects data
in transit; it does not prevent either authorized endpoint from reading or
exfiltrating it.

A dedicated Task Space is the official Skill's navigation convention. It is
not an authorization boundary. Explicit full-trust code can enumerate, claim,
or take over other Task Spaces and tabs or use raw CDP.

For the normal wrapper path, the Node broker derives the dedicated name from
the nonce-bound tool session and carries it in the one-time permit. The Bridge
preamble remaps only `useOrCreateTaskSpace` to that name. It deliberately does
not wrap claim, takeover, tab, or CDP helpers. The Server independently derives
the same canonical name at claim time, rejects mismatches, and returns it for
the Device Client to validate and store in the owner-only handoff. The Bridge
accepts only request labels and Task Space scopes that match that bound value.

Takeover detection is independent of request scripts and helper errors. A
separate supervised runtime calls only `listTaskSpaces()` and reads native
`ownership`. It arms only after the bound space reports `agent`, then treats
`agentDelegatedToUser` or `user` as takeover. It never calls or wraps claim,
takeover, or create/select helpers. The monitor being unavailable is itself a
fail-closed event; Bridge death closes its supervisor control pipe and kills
the monitor runtime.

## Network and origin policy

Production components never listen on a public or LAN socket. Registration
accepts one canonical HTTPS origin only: no userinfo, path, query, fragment, or
redirect. API requests disable redirects. The Bridge derives WSS from that
same stored origin and accepts only the fixed Server-issued relay path for the
current binding. Relay URLs, ticket material, scripts, and keys are not read
from project files or arbitrary environment overrides.

The application-enforced policy is not a host firewall. Operators should still
apply host egress policy where available and treat DNS, CA trust, and the
configured HTTPS origin as deployment security dependencies.

## Credentials

The community profile stores the Device Client identity, policy, active-binding
handoff, and short-lived credential in `~/.config/agent-remote-ego-browser`.
Directories must be owned by the current UID with mode `0700`; sensitive files
must be owner-owned, regular, singly linked, and mode `0600`. Symlinks, hard
links, foreign ownership, group/world access, malformed data, and generation
mismatch fail closed. Writes use an owner-only temporary file and atomic rename.

The macOS installer stores the trusted release certificate digest separately
as a current-UID, singly linked `0400` regular file. Installation refuses an
implicit certificate rotation. Explicit same-device key rotation creates and
persists an owner-only next-generation identity before the request, proves
possession with the new signing key, rejects stale or mismatched responses, and
clears the old binding handoff only after Server confirmation. The pending
identity is retained across interrupted requests and partial local commits so a
retry uses exactly the same generation and keys. Device revocation remains a
separate destructive flow; private keys never enter the control plane or normal
logs.

Policy is local-only before initial registration. Once a credential exists,
changing Site Learning or changing the allowlist without a binding-scoped CAS
requires fresh user authentication and same-device PoP registration. The Server
first pauses live bindings and invalidates their permits. The Device Client
accepts only an exact policy-and-identity response with a newer credential,
clears the reconnect handoff, and then commits the verified local policy. A
network error or mismatched response therefore cannot silently create a locally
advertised policy that the Server never authorized.

## Release trust

`community-local-trust` uses a persistent project self-signed certificate,
Hardened Runtime, nested code-signature verification, a user-confirmed
certificate SHA-256 pin, Sigstore release-asset signatures, SBOMs, and build
provenance. It is not Apple notarized and is not a public-distribution profile.
The installer clears quarantine only after manifest, artifact, digest, and code
signature verification, then recursively verifies that no quarantine attribute
remains and verifies the installed release again.

`development_local` and Unix-socket modes are for tests with non-sensitive
data. They cannot be used as a production transport or readiness substitute.

## Stop guarantees

The supervisor creates a process group, bounds execution and output, and kills
the managed group on timeout, revocation, lease loss, relay loss, or user
takeover. This guarantees cessation of the supervised execution unit. It does
not undo browser, filesystem, or network side effects and cannot guarantee
removal of a process that hostile same-UID code deliberately detached.

For a takeover, local admission is revoked and managed executions are allowed
to terminate before the Bridge requests a generation-bound Server pause with
the content-free reason `task_space_takeover`. Monitor failure uses
`task_space_monitor_unavailable`. A failed pause request does not undo the local
revocation. Resuming requires another explicit full-trust confirmation and a
new generation; no component automatically claims or takes over the space.

## Logging and incident response

Do not log or audit heredocs, page text, screenshots, cookies, input values,
URLs, local paths, relay tickets, access tokens, private keys, or plaintext
inner frames. Operational logs may contain finite error codes, versions,
binding/generation identifiers, sizes, durations, and lifecycle reasons.
Device-originated pause reasons are restricted to a finite protocol set, and
the Server normalizes every unknown lifecycle reason to `other` before storage.

On suspected host or identity compromise: revoke the binding and device rather
than relying on routine key rotation, stop both user launch agents, rotate
affected web sessions and local secrets, inspect the Bridge logs for metadata
only, reinstall a verified release, and register a new device identity. Do not
resume an old generation or replay an unknown request.
