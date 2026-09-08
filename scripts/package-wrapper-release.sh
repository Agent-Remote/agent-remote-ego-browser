#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${VERSION:-$(tr -d '[:space:]' < "$repo_root/VERSION")}
label=${LABEL:-}
target=${TARGET:-}
build_tool=${BUILD_TOOL:-cargo}
out_dir=${OUT_DIR:-$repo_root/dist/release}
binary_path=${BINARY_PATH:-}

case "$label" in
  linux-amd64-glibc) expected_target=x86_64-unknown-linux-gnu ;;
  linux-arm64-glibc) expected_target=aarch64-unknown-linux-gnu ;;
  linux-amd64-musl) expected_target=x86_64-unknown-linux-musl ;;
  linux-arm64-musl) expected_target=aarch64-unknown-linux-musl ;;
  *) echo "LABEL must identify a supported Linux architecture and libc" >&2; exit 2 ;;
esac
if [ -z "$target" ]; then
  target=$expected_target
elif [ "$target" != "$expected_target" ]; then
  echo "TARGET does not match LABEL" >&2
  exit 2
fi
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version" >&2
  exit 2
fi
if [ "$version" != "$(tr -d '[:space:]' < "$repo_root/VERSION")" ]; then
  echo "VERSION does not match the immutable source version" >&2
  exit 1
fi

if [ -z "$binary_path" ]; then
  "$build_tool" build --locked --release --target "$target" -p ego-browser-remote
  binary_path="$repo_root/target/$target/release/ego-browser"
fi
if [ ! -f "$binary_path" ] || [ -L "$binary_path" ] || [ ! -x "$binary_path" ]; then
  echo "wrapper build did not produce a regular executable" >&2
  exit 1
fi

staging=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-wrapper.XXXXXX")
cleanup() {
  rm -rf -- "$staging"
}
trap cleanup EXIT

install -m 0555 "$binary_path" "$staging/ego-browser"
printf '%s\n' "$version" > "$staging/VERSION"
chmod 0444 "$staging/VERSION"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$staging" && sha256sum ego-browser VERSION > SHA256SUMS)
else
  (cd "$staging" && shasum -a 256 ego-browser VERSION > SHA256SUMS)
fi
chmod 0444 "$staging/SHA256SUMS"

mkdir -p "$out_dir"
archive="$out_dir/agent-remote-ego-browser-wrapper-${label}-${version}.tar.gz"
rm -f -- "$archive"
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -C "$staging" -czf "$archive" ego-browser VERSION SHA256SUMS
else
  COPYFILE_DISABLE=1 tar -C "$staging" -czf "$archive" ego-browser VERSION SHA256SUMS
fi
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
else
  (cd "$(dirname "$archive")" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
fi
printf '%s\n' "$archive"
