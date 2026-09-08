#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
current_version=$(tr -d '[:space:]' < "$root/VERSION")
prepare_version=$(python3 - "$current_version" <<'PY'
import re
import sys

match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+].*)?", sys.argv[1])
if match is None:
    raise SystemExit("repository VERSION is not semantic")
print(f"{match.group(1)}.{match.group(2)}.{int(match.group(3)) + 1}")
PY
)
work=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-release-test.XXXXXX")
uninstall_work=""
cleanup() {
  rm -rf -- "$work"
  if [ -n "$uninstall_work" ] && [ -d "$uninstall_work" ]; then
    chmod -R u+w -- "$uninstall_work" >/dev/null 2>&1 || true
    rm -rf -- "$uninstall_work"
  fi
}
trap cleanup EXIT

fake_wrapper="$work/ego-browser"
printf '#!/bin/sh\nprintf wrapper-test\\n\n' > "$fake_wrapper"
chmod 0700 "$fake_wrapper"
for label in linux-amd64-glibc linux-arm64-glibc linux-amd64-musl linux-arm64-musl; do
  LABEL="$label" BINARY_PATH="$fake_wrapper" OUT_DIR="$work/out" \
    bash "$root/scripts/package-wrapper-release.sh" >/dev/null
  archive="$work/out/agent-remote-ego-browser-wrapper-${label}-${current_version}.tar.gz"
  test -f "$archive"
  (cd "$work/out" && sha256sum --check "$(basename "$archive").sha256")
  listing=$(tar -tzf "$archive" | LC_ALL=C sort)
  test "$listing" = $'SHA256SUMS\nVERSION\nego-browser'
  unpack="$work/unpack-$label"
  mkdir "$unpack"
  tar -xzf "$archive" -C "$unpack"
  test "$(tr -d '[:space:]' < "$unpack/VERSION")" = "$current_version"
  test -x "$unpack/ego-browser"
done

prepare_seed="$work/prepare-seed"
mutable_version_files=(
  Cargo.toml
  Cargo.lock
  VERSION
  CHANGELOG.md
  README.md
  README.zh-CN.md
  docs/operations.md
  docs/operations.zh-CN.md
  docs/release.md
  docs/release.zh-CN.md
  protocol/test-vectors/ego-browser-bridge-v1.json
)
invariant_version_files=(
  protocol/schemas/bridge-capability.schema.json
  protocol/schemas/release-manifest.schema.json
  installer/install-macos.sh
  .github/workflows/ci.yml
  .github/workflows/prepare-release.yml
  .github/workflows/release.yml
)
for relative in "${mutable_version_files[@]}" "${invariant_version_files[@]}"; do
  mkdir -p "$(dirname "$prepare_seed/$relative")"
  cp "$root/$relative" "$prepare_seed/$relative"
done
mkdir -p "$prepare_seed/scripts" "$work/fake-bin"
cp "$root/scripts/prepare-release.sh" "$prepare_seed/scripts/prepare-release.sh"

prepare_root="$work/prepare"
stale_root="$work/stale"
duplicate_root="$work/duplicate"
cp -R "$prepare_seed" "$prepare_root"
cp -R "$prepare_seed" "$stale_root"
cp -R "$prepare_seed" "$duplicate_root"
cat > "$work/fake-bin/cargo" <<'EOF'
#!/bin/sh
test "$#" = 3
test "$1" = check
test "$2" = --workspace
test "$3" = --locked
EOF
chmod 0700 "$work/fake-bin/cargo"

if PATH="$work/fake-bin:$PATH" \
  bash "$prepare_root/scripts/prepare-release.sh" "$current_version" >/dev/null 2>&1; then
  echo "prepare-release accepted the current stale version" >&2
  exit 1
fi
test "$(tr -d '[:space:]' < "$prepare_root/VERSION")" = "$current_version"
if PATH="$work/fake-bin:$PATH" \
  bash "$prepare_root/scripts/prepare-release.sh" invalid >/dev/null 2>&1; then
  echo "prepare-release accepted an invalid semantic version" >&2
  exit 1
fi

python3 - "$stale_root/protocol/test-vectors/ego-browser-bridge-v1.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text())
value["capability"]["remote_wrapper_version"] = "0.0.0-stale"
path.write_text(json.dumps(value, indent=2) + "\n")
PY
if PATH="$work/fake-bin:$PATH" \
  bash "$stale_root/scripts/prepare-release.sh" "$prepare_version" >/dev/null 2>&1; then
  echo "prepare-release accepted a stale repository version source" >&2
  exit 1
fi
test "$(tr -d '[:space:]' < "$stale_root/VERSION")" = "$current_version"

python3 - "$duplicate_root/CHANGELOG.md" "$prepare_version" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
path.write_text(source.replace("## Unreleased\n", f"## Unreleased\n\n## {sys.argv[2]} - 2000-01-01\n", 1))
PY
if PATH="$work/fake-bin:$PATH" \
  bash "$duplicate_root/scripts/prepare-release.sh" "$prepare_version" >/dev/null 2>&1; then
  echo "prepare-release accepted a duplicate changelog version" >&2
  exit 1
fi

PATH="$work/fake-bin:$PATH" \
  bash "$prepare_root/scripts/prepare-release.sh" "$prepare_version"
python3 - "$prepare_seed" "$prepare_root" "$current_version" "$prepare_version" <<'PY'
import json
import re
import sys
import tomllib
from pathlib import Path

before = Path(sys.argv[1])
after = Path(sys.argv[2])
old = sys.argv[3]
new = sys.argv[4]
repository_packages = {
    "ego-browser-bridge",
    "ego-browser-bridge-protocol",
    "ego-browser-device",
    "ego-browser-remote",
}
text_targets = (
    "README.md",
    "README.zh-CN.md",
    "docs/operations.md",
    "docs/operations.zh-CN.md",
    "docs/release.md",
    "docs/release.zh-CN.md",
)
invariants = (
    "protocol/schemas/bridge-capability.schema.json",
    "protocol/schemas/release-manifest.schema.json",
    "installer/install-macos.sh",
    ".github/workflows/ci.yml",
    ".github/workflows/prepare-release.yml",
    ".github/workflows/release.yml",
)

assert (after / "VERSION").read_text() == new + "\n"
before_cargo = tomllib.loads((before / "Cargo.toml").read_text())
after_cargo = tomllib.loads((after / "Cargo.toml").read_text())
assert after_cargo["workspace"]["package"]["version"] == new
assert before_cargo["workspace"]["dependencies"] == after_cargo["workspace"]["dependencies"]

before_lock = tomllib.loads((before / "Cargo.lock").read_text())
after_lock = tomllib.loads((after / "Cargo.lock").read_text())
for package in after_lock["package"]:
    if package["name"] in repository_packages:
        assert package["version"] == new
before_dependencies = sorted(
    (package["name"], package["version"], package.get("source"), package.get("checksum"))
    for package in before_lock["package"]
    if "source" in package
)
after_dependencies = sorted(
    (package["name"], package["version"], package.get("source"), package.get("checksum"))
    for package in after_lock["package"]
    if "source" in package
)
assert before_dependencies == after_dependencies

for relative in text_targets:
    content = (after / relative).read_text()
    assert old not in content, relative
    assert new in content, relative

before_vector = json.loads(
    (before / "protocol/test-vectors/ego-browser-bridge-v1.json").read_text()
)
after_vector = json.loads(
    (after / "protocol/test-vectors/ego-browser-bridge-v1.json").read_text()
)
assert after_vector["capability"]["remote_wrapper_version"] == new
assert after_vector["capability"]["skill_version"] == before_vector["capability"]["skill_version"]
assert after_vector["capability"]["local_ego_browser_runtime_version"] == before_vector["capability"]["local_ego_browser_runtime_version"]

changelog = (after / "CHANGELOG.md").read_text()
assert len(re.findall(rf"(?m)^## {re.escape(new)} - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$", changelog)) == 1
for relative in invariants:
    assert (after / relative).read_bytes() == (before / relative).read_bytes(), relative
PY

bash -n "$root"/scripts/*.sh "$root"/installer/*.sh
bash "$root/installer/install-macos.sh" --help >/dev/null
bash "$root/installer/uninstall-macos.sh" --help >/dev/null
bash "$root/installer/rollback-macos.sh" --help >/dev/null

inventory_root="$work/inventory-package"
inventory_bin="$work/inventory-bin"
inventory_archive="$work/agent-remote-ego-browser-macos-universal-${current_version}.tar.gz"
inventory_manifest="$work/inventory-manifest.json"
inventory_error="$work/inventory-error.txt"
inventory_certificate=$(printf 'a%.0s' {1..64})
mkdir -p "$inventory_root/bin" "$inventory_root/installer" "$inventory_root/support" "$inventory_bin"
for relative in \
  bin/ego-browser-bridge \
  bin/ego-browser-device \
  installer/install-macos.sh \
  installer/uninstall-macos.sh \
  installer/rollback-macos.sh \
  support/clear_verified_quarantine.py \
  support/release_manifest.py \
  support/release-manifest.schema.json \
  support/verify-community-release.sh \
  SIGNING-EVIDENCE.json \
  VERSION \
  LICENSE; do
  printf 'fixture\n' >"$inventory_root/$relative"
done
printf 'unexpected\n' >"$inventory_root/unexpected.txt"
tar -C "$inventory_root" -czf "$inventory_archive" \
  bin installer support SIGNING-EVIDENCE.json VERSION LICENSE unexpected.txt
inventory_digest=$(shasum -a 256 "$inventory_archive" | awk '{print $1}')
python3 - "$inventory_manifest" "$(basename "$inventory_archive")" \
  "$inventory_digest" "$inventory_certificate" "$current_version" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "version": sys.argv[5],
    "signer_certificate_sha256": sys.argv[4],
    "artifacts": [{
        "name": sys.argv[2],
        "kind": "macos_local_components",
        "sha256": sys.argv[3],
    }],
}))
PY
printf 'raise SystemExit(0)\n' >"$work/inventory-verifier.py"
printf '#!/bin/sh\nprintf "Darwin\\n"\n' >"$inventory_bin/uname"
printf '#!/bin/sh\nprintf "501\\n"\n' >"$inventory_bin/id"
printf '#!/bin/sh\nexit 0\n' >"$inventory_bin/cosign"
chmod 0700 "$inventory_bin/uname" "$inventory_bin/id" "$inventory_bin/cosign"
: >"$work/inventory-manifest.sigstore.json"
: >"$work/inventory-archive.sigstore.json"
if PATH="$inventory_bin:$PATH" \
  RELEASE_MANIFEST_VERIFIER="$work/inventory-verifier.py" \
  bash "$root/installer/install-macos.sh" \
    --archive "$inventory_archive" \
    --archive-sigstore-bundle "$work/inventory-archive.sigstore.json" \
    --manifest "$inventory_manifest" \
    --manifest-sigstore-bundle "$work/inventory-manifest.sigstore.json" \
    --certificate-sha256 "$inventory_certificate" \
    --confirm-local-trust --no-start >/dev/null 2>"$inventory_error"; then
  echo "installer accepted an archive with an extra inventory entry" >&2
  exit 1
fi
grep -q "archive contains an unexpected or duplicate path" "$inventory_error"

uninstall_work=$(mktemp -d "$HOME/.ego-browser-uninstall-test.XXXXXX")
install_root="$uninstall_work/bridge"
launch_agents="$uninstall_work/launch-agents"
standalone_runtime="$uninstall_work/ego-lite/bin/ego-browser"
fake_system="$uninstall_work/system-bin"
mkdir -p \
  "$install_root/releases/$current_version/bin" \
  "$install_root/state" \
  "$install_root/logs" \
  "$launch_agents" \
  "$(dirname "$standalone_runtime")" \
  "$fake_system"

# Exercise the installer against the real ego lite probe format.  The package
# and verification commands are deliberately local fixtures; this keeps the
# test deterministic while still running the complete version-discovery path.
probe_root="$work/probe-package"
probe_archive="$work/agent-remote-ego-browser-macos-universal-${current_version}-probe.tar.gz"
probe_manifest="$work/probe-manifest.json"
probe_launch_agents="$uninstall_work/probe-launch-agents"
probe_install_root="$uninstall_work/probe-install"
probe_runtime="$work/probe-runtime"
probe_bin="$work/probe-bin"
mkdir -p "$probe_root/bin" "$probe_root/installer" "$probe_root/support" \
  "$probe_bin" "$probe_launch_agents"
for relative in \
  bin/ego-browser-bridge \
  bin/ego-browser-device \
  installer/install-macos.sh \
  installer/uninstall-macos.sh \
  installer/rollback-macos.sh \
  support/clear_verified_quarantine.py \
  support/release_manifest.py \
  support/release-manifest.schema.json \
  support/verify-community-release.sh \
  SIGNING-EVIDENCE.json \
  VERSION \
  LICENSE; do
  mkdir -p "$(dirname "$probe_root/$relative")"
done
printf '#!/bin/sh\nexit 0\n' >"$probe_root/support/verify-community-release.sh"
printf 'raise SystemExit(0)\n' >"$probe_root/support/clear_verified_quarantine.py"
printf 'raise SystemExit(0)\n' >"$probe_root/support/release_manifest.py"
printf '{}\n' >"$probe_root/support/release-manifest.schema.json"
printf '{"production_ready":false,"readiness_blockers":["learning_bundle_signing_private_key_unavailable"],"learning_bundle_digest":null}\n' \
  >"$probe_root/SIGNING-EVIDENCE.json"
printf '%s\n' "$current_version" >"$probe_root/VERSION"
printf 'fixture\n' >"$probe_root/LICENSE"
printf 'fixture\n' >"$probe_root/bin/ego-browser-bridge"
printf 'fixture\n' >"$probe_root/bin/ego-browser-device"
printf 'fixture\n' >"$probe_root/installer/install-macos.sh"
printf 'fixture\n' >"$probe_root/installer/uninstall-macos.sh"
printf 'fixture\n' >"$probe_root/installer/rollback-macos.sh"
chmod 0700 "$probe_root/bin/ego-browser-bridge" "$probe_root/bin/ego-browser-device" \
  "$probe_root/support/verify-community-release.sh"
COPYFILE_DISABLE=1 tar -C "$probe_root" -czf "$probe_archive" \
  bin installer support SIGNING-EVIDENCE.json VERSION LICENSE
probe_digest=$(shasum -a 256 "$probe_archive" | awk '{print $1}')
python3 - "$probe_manifest" "$(basename "$probe_archive")" \
  "$probe_digest" "$inventory_certificate" "$current_version" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "version": sys.argv[5],
    "signer_certificate_sha256": sys.argv[4],
    "artifacts": [{
        "name": sys.argv[2],
        "kind": "macos_local_components",
        "sha256": sys.argv[3],
    }],
}))
PY
printf '#!/bin/sh\nexit 0\n' >"$probe_bin/cosign"
printf '%s\n' '#!/bin/sh' \
  'if [ "${1:-}" = "--version" ]; then' \
  '  printf "%s\n" "ego-browser 0.4.7.4"' \
  '  printf "%s\n" "  chromium 150.0.7871.101"' \
  '  printf "%s\n" "  node v24.18.0"' \
  '  exit 0' \
  'fi' \
  'exit 64' >"$probe_runtime"
chmod 0700 "$probe_bin/cosign" "$probe_runtime"
: >"$work/probe-manifest.sigstore.json"
: >"$work/probe-archive.sigstore.json"
probe_output=$(PATH="$fake_system:$probe_bin:/usr/bin:/bin" \
  RELEASE_MANIFEST_VERIFIER="$probe_root/support/release_manifest.py" \
  EGO_BROWSER_INSTALL_ROOT="$probe_install_root" \
  EGO_BROWSER_LAUNCH_AGENTS_DIR="$probe_launch_agents" \
  bash "$root/installer/install-macos.sh" \
    --archive "$probe_archive" \
    --archive-sigstore-bundle "$work/probe-archive.sigstore.json" \
    --manifest "$probe_manifest" \
    --manifest-sigstore-bundle "$work/probe-manifest.sigstore.json" \
    --certificate-sha256 "$inventory_certificate" \
    --ego-browser "$probe_runtime" \
    --confirm-local-trust --no-start)
grep -q "installed ego-browser Bridge $current_version" <<<"$probe_output"
grep -q "production_ready=false" <<<"$probe_output"
test -L "$probe_install_root/current"
test -x "$probe_install_root/current/bin/ego-browser-bridge"

printf '#!/bin/sh\nprintf "%%s\\n" "ego-browser-independent-runtime"\n' \
  >"$standalone_runtime"
chmod 0700 "$standalone_runtime"
runtime_digest=$(shasum -a 256 "$standalone_runtime" | awk '{print $1}')
test "$("$standalone_runtime")" = "ego-browser-independent-runtime"
printf '#!/bin/sh\nprintf "Darwin\\n"\n' >"$fake_system/uname"
printf '#!/bin/sh\nprintf "501\\n"\n' >"$fake_system/id"
printf '#!/bin/sh\nexit 0\n' >"$fake_system/launchctl"
chmod 0700 "$fake_system/uname" "$fake_system/id" "$fake_system/launchctl"
printf 'bridge\n' >"$install_root/releases/$current_version/bin/ego-browser-bridge"
ln -s "$install_root/releases/$current_version" "$install_root/current"
printf 'plist\n' >"$launch_agents/dev.agentremote.ego-browser.bridge.plist"
printf 'plist\n' >"$launch_agents/dev.agentremote.ego-browser.device.plist"
PATH="$fake_system:/usr/bin:/bin" \
EGO_BROWSER_INSTALL_ROOT="$install_root" \
EGO_BROWSER_LAUNCH_AGENTS_DIR="$launch_agents" \
  bash "$root/installer/uninstall-macos.sh" >/dev/null
test ! -e "$install_root/current"
test ! -e "$launch_agents/dev.agentremote.ego-browser.bridge.plist"
test ! -e "$launch_agents/dev.agentremote.ego-browser.device.plist"
test -d "$install_root/releases/$current_version"
test "$(shasum -a 256 "$standalone_runtime" | awk '{print $1}')" = "$runtime_digest"
test "$("$standalone_runtime")" = "ego-browser-independent-runtime"

PATH="$fake_system:/usr/bin:/bin" \
EGO_BROWSER_INSTALL_ROOT="$install_root" \
EGO_BROWSER_LAUNCH_AGENTS_DIR="$launch_agents" \
  bash "$root/installer/uninstall-macos.sh" --remove-releases >/dev/null
test ! -e "$install_root/releases"
test "$(shasum -a 256 "$standalone_runtime" | awk '{print $1}')" = "$runtime_digest"
test "$("$standalone_runtime")" = "ego-browser-independent-runtime"

python3 -m json.tool "$root/protocol/schemas/release-manifest.schema.json" >/dev/null
python3 - "$root/installer/install-macos.sh" "$root/installer/rollback-macos.sh" <<'PY'
import sys
from pathlib import Path

install = Path(sys.argv[1]).read_text()
rollback = Path(sys.argv[2]).read_text()
for source in (install, rollback):
    for invariant in (
        'metadata.st_uid != os.getuid()',
        'metadata.st_nlink != 1',
        'stat.S_IMODE(metadata.st_mode) != 0o400',
    ):
        if invariant not in source:
            raise SystemExit(f"certificate-pin invariant is missing: {invariant}")
if rollback.index('for plist in "$device_plist" "$bridge_plist"') > rollback.index(
    'mv -fh "$next" "$current"'
):
    raise SystemExit("rollback switches current before validating launch-agent definitions")
PY

forbidden='agent-remote-'device
if rg -n "$forbidden" "$root" \
  --glob '!target/**' --glob '!tests/release_scripts_test.sh' >/dev/null; then
  echo "forbidden cross-product dependency or reference found" >&2
  exit 1
fi
