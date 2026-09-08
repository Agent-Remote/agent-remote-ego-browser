#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/ego-browser-learning-test.XXXXXX")
work=$(cd "$work" && pwd -P)
cleanup() {
  chmod -R u+rwX "$work" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT

bundle="$work/bundle"
mkdir -p "$bundle"
cp -R "$root/examples/unsigned-learning-bundle/learnings" "$bundle/learnings"
private_key="$work/test-private-key"
public_key="$work/test-public-key"
install -m 0600 "$root/tests/fixtures/learning-test-private-key.txt" "$private_key"

tool=(cargo run --quiet --locked --bin ego-browser-learning-bundle --)
"${tool[@]}" manifest \
  --bundle "$bundle" \
  --bundle-version 2026.09.test \
  --signing-key-id test-only > "$work/manifest-one.json"
"${tool[@]}" manifest \
  --bundle "$bundle" \
  --bundle-version 2026.09.test \
  --signing-key-id test-only > "$work/manifest-two.json"
cmp "$work/manifest-one.json" "$work/manifest-two.json"

digest=$("${tool[@]}" sign \
  --bundle "$bundle" \
  --bundle-version 2026.09.test \
  --signing-key-id test-only \
  --private-key-file "$private_key" \
  --public-key-output "$public_key")
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
test "$("${tool[@]}" verify --bundle "$bundle" --public-key-file "$public_key")" = "$digest"
if "${tool[@]}" verify --bundle "$bundle" >/dev/null 2>&1; then
  echo "test-signed bundle unexpectedly matched the embedded production trust anchor" >&2
  exit 1
fi

chmod u+w "$bundle" "$bundle/learnings" "$bundle/learnings/example" \
  "$bundle/learnings/example/notes"
printf 'unsigned drift\n' > "$bundle/learnings/example/notes/unlisted.md"
chmod a-w "$bundle/learnings/example/notes/unlisted.md" "$bundle/learnings/example/notes" \
  "$bundle/learnings/example" "$bundle/learnings" "$bundle"
if "${tool[@]}" verify --bundle "$bundle" --public-key-file "$public_key" >/dev/null 2>&1; then
  echo "unlisted learning payload was not rejected" >&2
  exit 1
fi
