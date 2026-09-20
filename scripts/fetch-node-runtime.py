#!/usr/bin/env python3
"""Fetch the release-pinned Node executable without extracting untrusted paths."""

import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / "assets/node-runtime.json").read_text())
    platform, destination = sys.argv[1:]
    version = manifest["version"]
    if platform not in {"darwin-arm64", "darwin-x64"} or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("unsupported Node runtime")
    prefix = f"node-v{version}-{platform}"
    url = f"https://nodejs.org/dist/v{version}/{prefix}.tar.gz"
    archive = subprocess.run(
        ["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
         "--max-time", "120", "--max-filesize", str(100 * 1024 * 1024), url],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    if len(archive) > 100 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != manifest[platform]:
        raise SystemExit("Node archive checksum mismatch")
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        for source, output in [("bin/node", "node"), ("LICENSE", "NODE-LICENSE")]:
            members = [item for item in package.getmembers() if item.name == f"{prefix}/{source}"]
            if len(members) != 1 or not members[0].isfile() or members[0].size > 150 * 1024 * 1024:
                raise SystemExit("invalid Node archive member")
            with package.extractfile(members[0]) as data, (target / output).open("xb") as sink:
                sink.write(data.read())
            (target / output).chmod(0o555 if output == "node" else 0o444)


if __name__ == "__main__":
    main()
