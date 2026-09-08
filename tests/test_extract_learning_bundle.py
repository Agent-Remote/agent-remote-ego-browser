from __future__ import annotations

import base64
import io
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "extract-learning-bundle.py"


def archive_with_members(members: list[tarfile.TarInfo | tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for member in members:
            if isinstance(member, tuple):
                name, payload = member
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(payload))
            else:
                archive.addfile(member)
    return output.getvalue()


def valid_members() -> list[tarfile.TarInfo | tuple[str, bytes]]:
    root = tarfile.TarInfo("learning-bundle")
    root.type = tarfile.DIRTYPE
    learnings = tarfile.TarInfo("learning-bundle/learnings")
    learnings.type = tarfile.DIRTYPE
    return [
        root,
        ("learning-bundle/manifest.json", b'{"signing_key_id":"test"}\n'),
        learnings,
        ("learning-bundle/learnings/example.txt", b"signed learning\n"),
    ]


class ExtractLearningBundleTests(unittest.TestCase):
    def run_extractor(self, payload: bytes, output: Path) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(payload)
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--base64-stdin",
                "--output",
                str(output),
            ],
            input=encoded,
            capture_output=True,
            check=False,
        )

    def test_valid_bundle_is_extracted_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bundle"
            result = self.run_extractor(archive_with_members(valid_members()), output)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(
                (output / "manifest.json").read_text(encoding="utf-8"),
                '{"signing_key_id":"test"}\n',
            )
            for path in (output, *output.rglob("*")):
                self.assertFalse(path.is_symlink())
                self.assertFalse(path.stat().st_mode & 0o222)
            self.assertTrue((output / "learnings").is_dir())
            self.make_writable(output)

    def test_unsafe_members_are_rejected_without_writing_outside_output(self) -> None:
        cases: list[tarfile.TarInfo | tuple[str, bytes]] = [
            ("learning-bundle/../escape", b"nope"),
            ("outside.txt", b"nope"),
        ]
        link = tarfile.TarInfo("learning-bundle/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp/escape"
        cases.append(link)
        hardlink = tarfile.TarInfo("learning-bundle/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "learning-bundle/manifest.json"
        cases.append(hardlink)
        for unsafe in cases:
            with self.subTest(member=getattr(unsafe, "name", unsafe[0] if isinstance(unsafe, tuple) else "")):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    output = root / "bundle"
                    result = self.run_extractor(
                        archive_with_members(valid_members() + [unsafe]), output
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(output.exists())
                    self.assertFalse((root / "escape").exists())

    def test_duplicate_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            members = valid_members() + [
                ("learning-bundle/manifest.json", b"different\n")
            ]
            result = self.run_extractor(archive_with_members(members), output)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    @staticmethod
    def make_writable(root: Path) -> None:
        for path in (root, *root.rglob("*")):
            mode = stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode | (0o700 if path.is_dir() else 0o600))


if __name__ == "__main__":
    unittest.main()
