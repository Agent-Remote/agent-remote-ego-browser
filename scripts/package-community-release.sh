#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${VERSION:-$(tr -d '[:space:]' < "$repo_root/VERSION")}
package_root=${PACKAGE_ROOT:-$repo_root/dist/community-release/package}
out_dir=${OUT_DIR:-$repo_root/dist/release}

for required in \
  bin/ego-browser-bridge \
  bin/ego-browser-device \
  installer/install-macos.sh \
  installer/uninstall-macos.sh \
  installer/rollback-macos.sh \
  support/clear_verified_quarantine.py \
  support/release_manifest.py \
  support/verify-community-release.sh \
  support/verify-learning-bundle.sh \
  support/release-manifest.schema.json \
  SIGNING-EVIDENCE.json \
  VERSION; do
  if [ ! -f "$package_root/$required" ] || [ -L "$package_root/$required" ]; then
    echo "community package is missing $required" >&2
    exit 1
  fi
done
if [ "$(tr -d '[:space:]' < "$package_root/VERSION")" != "$version" ]; then
  echo "community package version mismatch" >&2
  exit 1
fi

mkdir -p "$out_dir"
archive="$out_dir/agent-remote-ego-browser-macos-universal-${version}.tar.gz"
rm -f -- "$archive"
entries=(bin installer support SIGNING-EVIDENCE.json VERSION LICENSE)
if [ -d "$package_root/learning-bundle" ] && [ ! -L "$package_root/learning-bundle" ]; then
  entries+=(learning-bundle)
fi
COPYFILE_DISABLE=1 tar -C "$package_root" -czf "$archive" "${entries[@]}"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
else
  (cd "$(dirname "$archive")" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
fi
printf '%s\n' "$archive"
