from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "clear_verified_quarantine", ROOT / "scripts" / "clear_verified_quarantine.py"
)
assert SPEC is not None and SPEC.loader is not None
quarantine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quarantine)


class QuarantineTests(unittest.TestCase):
    def test_clear_is_recursive_verified_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            nested = root / "support"
            nested.mkdir()
            release_file = nested / "release.txt"
            release_file.write_text("release\n", encoding="utf-8")
            state = {
                root: {quarantine.QUARANTINE_ATTRIBUTE},
                nested: set(),
                release_file: {quarantine.QUARANTINE_ATTRIBUTE},
            }

            def run_xattr(
                command: list[str], *, check: bool, capture_output: bool
            ) -> subprocess.CompletedProcess[bytes]:
                self.assertFalse(check)
                self.assertTrue(capture_output)
                path = Path(command[-1])
                if command[1:3] == ["-d", quarantine.QUARANTINE_ATTRIBUTE]:
                    state[path].remove(quarantine.QUARANTINE_ATTRIBUTE)
                    output = b""
                else:
                    output = ("\n".join(sorted(state[path])) + "\n").encode()
                return subprocess.CompletedProcess(command, 0, output, b"")

            with mock.patch.object(quarantine.subprocess, "run", run_xattr):
                quarantine.clear_verified_quarantine(root)
            self.assertTrue(all(not value for value in state.values()))

            with mock.patch.object(
                quarantine.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1, b"", b"failure"),
            ):
                with self.assertRaisesRegex(
                    quarantine.QuarantineError, "cannot be inspected"
                ):
                    quarantine.clear_verified_quarantine(root)

            link = root / "unexpected-link"
            link.symlink_to(release_file)
            with self.assertRaisesRegex(quarantine.QuarantineError, "unsafe entry"):
                quarantine.release_tree(root)


if __name__ == "__main__":
    unittest.main()
