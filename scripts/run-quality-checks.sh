#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash tests/learning_bundle_cli_test.sh
bash tests/release_scripts_test.sh
bash tests/install_script_test.sh
bash integration-tests/fake-relay-e2e.sh
for schema in protocol/schemas/*.json; do
  python3 -m json.tool "$schema" >/dev/null
done
git diff --check
