#!/usr/bin/env python3
"""Decode and safely extract a protected Site Learning bundle archive."""

from __future__ import annotations

import argparse
import base64
import io
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 4096
ROOT_NAME = "learning-bundle"


def regular_file(path: Path, label: str) -> None:
    """Require a non-symlink regular file."""

    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular file")


def archive_bytes(path: Path | None, base64_stdin: bool) -> bytes:
    """Read and bound either an archive file or its base64 stdin form."""

    if base64_stdin:
        encoded = sys.stdin.buffer.read(MAX_ARCHIVE_BYTES * 2)
        if len(encoded) >= MAX_ARCHIVE_BYTES * 2:
            raise ValueError("base64 learning bundle archive is too large")
        try:
            # Secrets are commonly wrapped at 76 columns; only ASCII base64
            # whitespace is accepted so hidden control characters are rejected.
            compact = b"".join(encoded.split())
            decoded = base64.b64decode(compact, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("learning bundle archive is not valid base64") from exc
    else:
        if path is None:
            raise ValueError("learning bundle archive is required")
        regular_file(path, "learning bundle archive")
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("learning bundle archive is too large")
        decoded = path.read_bytes()
    if not decoded or len(decoded) > MAX_ARCHIVE_BYTES:
        raise ValueError("learning bundle archive size is invalid")
    return decoded


def member_path(name: str) -> tuple[str, ...]:
    """Return a strict relative path below the required archive root."""

    if not name or "\x00" in name or "\\" in name:
        raise ValueError("learning bundle archive contains an unsafe path")
    trimmed = name[:-1] if name.endswith("/") else name
    parsed = PurePosixPath(trimmed)
    parts = parsed.parts
    if (
        not parts
        or parts[0] != ROOT_NAME
        or any(part in {"", ".", ".."} for part in parts)
        or "/".join(parts) != trimmed
    ):
        raise ValueError("learning bundle archive contains an unsafe path")
    return parts


def validate_members(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, tuple[str, ...]]]:
    """Validate member types, names, count, and expanded size before writing."""

    members: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []
    seen: set[tuple[str, ...]] = set()
    expanded = 0
    for member in archive.getmembers():
        if len(members) >= MAX_MEMBERS:
            raise ValueError("learning bundle archive has too many members")
        parts = member_path(member.name)
        if parts in seen:
            raise ValueError("learning bundle archive contains a duplicate path")
        seen.add(parts)
        if not (member.isdir() or member.isfile()):
            raise ValueError("learning bundle archive contains a link or special file")
        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
            raise ValueError("learning bundle archive contains an oversized member")
        expanded += member.size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("learning bundle archive expands beyond its limit")
        members.append((member, parts))
    required = {
        (ROOT_NAME, "manifest.json"),
        (ROOT_NAME, "learnings"),
    }
    if not required.issubset(seen):
        raise ValueError("learning bundle archive is missing its required tree")
    if any(
        parts == (ROOT_NAME, "manifest.json") and not member.isfile()
        for member, parts in members
    ):
        raise ValueError("learning bundle manifest must be a regular file")
    if any(
        parts == (ROOT_NAME, "learnings") and not member.isdir()
        for member, parts in members
    ):
        raise ValueError("learning bundle learnings entry must be a directory")
    return members


def ensure_directory(path: Path) -> None:
    """Create one extracted directory while extraction is in progress."""

    if path.exists() or path.is_symlink():
        if not path.is_dir() or path.is_symlink():
            raise ValueError("learning bundle archive collides with a file")
        return
    path.mkdir(mode=0o700)


def extract_member(archive: tarfile.TarFile, member: tarfile.TarInfo, parts: tuple[str, ...], output: Path) -> None:
    """Extract one previously validated regular member without tar extraction."""

    destination = output.joinpath(*parts[1:])
    relative_parent = parts[1:-1]
    cursor = output
    for component in relative_parent:
        cursor = cursor / component
        ensure_directory(cursor)
    if member.isdir():
        ensure_directory(destination)
        return
    if destination.exists() or destination.is_symlink():
        raise ValueError("learning bundle archive contains a duplicate destination")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o444,
    )
    try:
        source = archive.extractfile(member)
        if source is None:
            raise ValueError("learning bundle archive member cannot be read")
        with source, os.fdopen(descriptor, "wb") as target:
            descriptor = -1
            remaining = member.size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("learning bundle archive member is truncated")
                target.write(chunk)
                remaining -= len(chunk)
            target.flush()
            os.fsync(target.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    destination.chmod(0o444)


def verify_tree(output: Path, *, require_read_only: bool = True) -> None:
    """Verify the extracted tree has no links, special files, or write bits."""

    required = (output / "manifest.json", output / "learnings")
    if not required[0].is_file() or required[0].is_symlink() or not required[1].is_dir() or required[1].is_symlink():
        raise ValueError("learning bundle archive is incomplete")
    count = 0
    for path in (output, *output.rglob("*")):
        count += 1
        if count > MAX_MEMBERS or path.is_symlink():
            raise ValueError("learning bundle extraction contains an unsafe entry")
        mode = path.stat().st_mode
        if stat.S_ISREG(mode):
            if require_read_only and mode & 0o222:
                raise ValueError("learning bundle extraction is writable")
        elif stat.S_ISDIR(mode):
            if require_read_only and mode & 0o222:
                raise ValueError("learning bundle extraction is writable")
        else:
            raise ValueError("learning bundle extraction contains a special file")


def extract(archive_data: bytes, output: Path) -> None:
    """Validate and extract archive_data into a newly created output directory."""

    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("learning bundle output must be a new absolute path")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("learning bundle output parent is unsafe")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
            members = validate_members(archive)
            output.mkdir(mode=0o700)
            try:
                for member, parts in members:
                    extract_member(archive, member, parts, output)
                verify_tree(output, require_read_only=False)
                for path in (output, *output.rglob("*")):
                    path.chmod(0o555 if path.is_dir() else 0o444)
                verify_tree(output)
            except Exception:
                shutil.rmtree(output, ignore_errors=True)
                raise
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("learning bundle archive is invalid") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--base64-stdin", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        extract(archive_bytes(args.archive, args.base64_stdin), args.output.resolve())
    except (OSError, ValueError) as exc:
        parser.exit(2, f"learning bundle extraction failed: {exc}\n")
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
