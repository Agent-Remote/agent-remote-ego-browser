#!/usr/bin/env python3
"""Clear and then independently verify quarantine on a fixed release tree."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

QUARANTINE_ATTRIBUTE = "com.apple.quarantine"
MAX_RELEASE_ENTRIES = 4_096


class QuarantineError(RuntimeError):
    """The release tree or one of its extended attributes is unsafe."""


def release_tree(root: Path) -> list[Path]:
    """Return a bounded tree containing only directories and regular files."""
    if not root.is_absolute():
        raise QuarantineError("release root must be absolute")
    try:
        metadata = root.lstat()
        canonical = root.resolve(strict=True)
    except OSError as error:
        raise QuarantineError("release root is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or canonical != root:
        raise QuarantineError("release root is invalid")

    pending = [root]
    paths: list[Path] = []
    while pending:
        path = pending.pop()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise QuarantineError("release entry is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            raise QuarantineError("release tree contains an unsafe entry")
        paths.append(path)
        if len(paths) > MAX_RELEASE_ENTRIES:
            raise QuarantineError("release tree contains too many entries")
        if stat.S_ISDIR(metadata.st_mode):
            try:
                children = sorted(path.iterdir(), key=lambda child: child.name, reverse=True)
            except OSError as error:
                raise QuarantineError("release directory cannot be inspected") from error
            pending.extend(children)
    return paths


def attributes(path: Path) -> list[str]:
    """Read one entry's extended-attribute names without following links."""
    try:
        result = subprocess.run(
            ["/usr/bin/xattr", os.fspath(path)],
            check=False,
            capture_output=True,
        )
        names = result.stdout.decode("utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as error:
        raise QuarantineError("release attributes cannot be inspected") from error
    if result.returncode != 0:
        raise QuarantineError("release attributes cannot be inspected")
    return names


def clear_verified_quarantine(root: Path) -> None:
    """Remove quarantine and fail if the complete second traversal finds any."""
    for path in release_tree(root):
        if QUARANTINE_ATTRIBUTE not in attributes(path):
            continue
        try:
            result = subprocess.run(
                ["/usr/bin/xattr", "-d", QUARANTINE_ATTRIBUTE, os.fspath(path)],
                check=False,
                capture_output=True,
            )
        except OSError as error:
            raise QuarantineError("release quarantine cannot be removed") from error
        if result.returncode != 0:
            raise QuarantineError("release quarantine cannot be removed")

    for path in release_tree(root):
        if QUARANTINE_ATTRIBUTE in attributes(path):
            raise QuarantineError("release quarantine remains after removal")


def main() -> int:
    """Run the fail-closed quarantine operation for one absolute release root."""
    if len(sys.argv) != 2:
        print("usage: clear_verified_quarantine.py ABSOLUTE_RELEASE_ROOT", file=sys.stderr)
        return 2
    try:
        clear_verified_quarantine(Path(sys.argv[1]))
    except QuarantineError as error:
        print(f"release quarantine verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
