#!/usr/bin/env bash
set -euo pipefail

version=${1:?release version is required}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

python3 - "$root" "$version" <<'PY'
import datetime
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
version = sys.argv[2]
semver_pattern = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
repository_packages = (
    "ego-browser-bridge",
    "ego-browser-bridge-protocol",
    "ego-browser-device",
    "ego-browser-remote",
)
text_version_files = (
    "README.md",
    "README.zh-CN.md",
    "docs/operations.md",
    "docs/operations.zh-CN.md",
    "docs/release.md",
    "docs/release.zh-CN.md",
    "protocol/test-vectors/ego-browser-bridge-v1.json",
)


def parse_semver(value: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None]:
    match = semver_pattern.fullmatch(value)
    if match is None:
        raise SystemExit(f"invalid semantic version: {value}")
    prerelease = match.group(4)
    identifiers = None if prerelease is None else tuple(prerelease.split("."))
    if identifiers is not None and any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in identifiers
    ):
        raise SystemExit(f"invalid semantic version: {value}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))), identifiers


def compare_semver(left: str, right: str) -> int:
    left_core, left_pre = parse_semver(left)
    right_core, right_pre = parse_semver(right)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if left_pre is None or right_pre is None:
        if left_pre == right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_item) > int(right_item) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_item > right_item else -1
    if len(left_pre) == len(right_pre):
        return 0
    return 1 if len(left_pre) > len(right_pre) else -1


def read_source(relative: str) -> tuple[Path, str]:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"release version source is missing or unsafe: {relative}")
    return path, path.read_text(encoding="utf-8")


def replace_exact(text: str, pattern: re.Pattern[str], replacement: str, label: str) -> str:
    updated, count = pattern.subn(replacement, text)
    if count != 1:
        raise SystemExit(f"{label} is stale, duplicated, or missing")
    return updated


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"protocol capability vector has duplicate key: {key}")
        result[key] = value
    return result


def generated_release_notes() -> str:
    previous_tag = ""
    try:
        tags = subprocess.run(
            ["git", "tag", "--list", "v[0-9]*", "--sort=-v:refname"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        previous_tag = next(
            (tag for tag in tags if tag != f"v{version}"),
            "",
        )
        revision = f"{previous_tag}..HEAD" if previous_tag else "HEAD"
        notes = subprocess.run(
            [
                "git",
                "log",
                "--no-merges",
                "--pretty=format:- %s (%h)",
                revision,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        notes = ""
    if notes:
        return notes
    baseline = previous_tag or "the initial source"
    return (
        f"- release: prepare {version} from {baseline} with repository-owned "
        "version metadata only."
    )


version_path, version_source = read_source("VERSION")
current_version = version_source.strip()
parse_semver(current_version)
if version_source != current_version + "\n":
    raise SystemExit("VERSION must contain exactly one canonical semantic version")
if compare_semver(version, current_version) <= 0:
    raise SystemExit(
        f"release version must be newer than current VERSION ({current_version})"
    )

updates: dict[Path, str] = {}

cargo_path, cargo = read_source("Cargo.toml")
tomllib.loads(cargo)
cargo_pattern = re.compile(
    rf'(?m)^(\[workspace\.package\]\nversion = "){re.escape(current_version)}("$)'
)
updates[cargo_path] = replace_exact(
    cargo,
    cargo_pattern,
    rf"\g<1>{version}\g<2>",
    "workspace package version",
)

lock_path, lock = read_source("Cargo.lock")
tomllib.loads(lock)
updated_lock = lock
for package in repository_packages:
    lock_pattern = re.compile(
        rf'(\[\[package\]\]\nname = "{re.escape(package)}"\nversion = ")'
        rf'{re.escape(current_version)}("\n)'
    )
    updated_lock = replace_exact(
        updated_lock,
        lock_pattern,
        rf"\g<1>{version}\g<2>",
        f"Cargo.lock package {package}",
    )
tomllib.loads(updated_lock)
updates[lock_path] = updated_lock

for relative in text_version_files:
    path, source = read_source(relative)
    count = source.count(current_version)
    if count == 0:
        raise SystemExit(f"release version source is stale or missing: {relative}")
    updated = source.replace(current_version, version)
    if current_version in updated:
        raise SystemExit(f"release version source remained stale: {relative}")
    updates[path] = updated

vector_path = root / "protocol/test-vectors/ego-browser-bridge-v1.json"
vector_before = json.loads(
    vector_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
)
if vector_before.get("capability", {}).get("remote_wrapper_version") != current_version:
    raise SystemExit("protocol capability vector version is stale or missing")
vector_after = json.loads(updates[vector_path], object_pairs_hook=reject_duplicate_pairs)
if vector_after.get("capability", {}).get("remote_wrapper_version") != version:
    raise SystemExit("protocol capability vector version was not updated")

changelog_path, changelog = read_source("CHANGELOG.md")
if re.search(rf"(?m)^## {re.escape(version)}(?:\s+-|\s*$)", changelog):
    raise SystemExit("release already appears in the changelog")
heading = f"## {version} - {datetime.date.today().isoformat()}"
pending_sections = list(re.finditer(r"(?m)^## Unreleased[ \t]*$", changelog))
if len(pending_sections) > 1:
    raise SystemExit("changelog contains multiple Unreleased sections")
if pending_sections:
    unreleased = re.search(
        r"(?ms)^## Unreleased[ \t]*\n(?P<body>.*?)(?=^## |\Z)",
        changelog,
    )
    if unreleased is None:
        raise SystemExit("changelog Unreleased section is malformed")
    notes = unreleased.group("body").strip() or generated_release_notes()
    release_section = f"{heading}\n\n{notes}\n\n"
    updates[changelog_path] = (
        changelog[: unreleased.start()]
        + release_section
        + changelog[unreleased.end() :]
    )
else:
    notes = generated_release_notes()
    release_section = f"{heading}\n\n{notes}\n\n"
    first_heading = re.search(r"(?m)^## ", changelog)
    if first_heading is None:
        separator = "" if changelog.endswith("\n\n") else "\n\n"
        updates[changelog_path] = changelog + separator + release_section
    else:
        updates[changelog_path] = (
            changelog[: first_heading.start()]
            + release_section
            + changelog[first_heading.start() :]
        )
updates[version_path] = version + "\n"

for path, content in updates.items():
    temporary = path.with_name(f".{path.name}.prepare-release-{os.getpid()}")
    try:
        with temporary.open("x", encoding="utf-8", newline="") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
PY

cd "$root"
cargo check --workspace --locked
