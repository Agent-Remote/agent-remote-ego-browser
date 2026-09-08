from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ego_browser_release_manifest", ROOT / "scripts" / "release_manifest.py"
)
assert SPEC is not None and SPEC.loader is not None
release_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_manifest)


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.version = (ROOT / "VERSION").read_text().strip()
        for name, _, _, _ in release_manifest.expected_artifacts(self.version):
            (self.directory / name).write_bytes(f"archive:{name}".encode())
            (self.directory / f"{name}.sigstore.json").write_text("{}\n")
            sbom = f"{name.removesuffix('.tar.gz')}.spdx.json"
            (self.directory / sbom).write_text('{"spdxVersion":"SPDX-2.3"}\n')
            (self.directory / f"{sbom}.sigstore.json").write_text("{}\n")
        report = self.directory / f"agent-remote-ego-browser-{self.version}.cargo-audit.json"
        report.write_text('{"vulnerabilities":{}}\n')
        (self.directory / f"{report.name}.sigstore.json").write_text("{}\n")
        self.manifest = release_manifest.generate_manifest(
            self.version, "a" * 64, self.directory
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generated_manifest_is_strict_and_verifies_evidence(self) -> None:
        validated = release_manifest.validate_manifest(self.manifest)
        self.assertFalse(validated["production_ready"])
        self.assertIsNone(validated["learning_bundle_digest"])
        release_manifest.verify_files(validated, self.directory)

    def test_unknown_duplicate_and_false_readiness_claims_are_rejected(self) -> None:
        changed = dict(self.manifest)
        changed["unknown"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            release_manifest.validate_manifest(changed)

        changed = dict(self.manifest)
        changed["production_ready"] = True
        with self.assertRaisesRegex(ValueError, "trust fields"):
            release_manifest.validate_manifest(changed)

        duplicate = '{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            json.loads(duplicate, object_pairs_hook=release_manifest.reject_duplicates)

    def test_artifact_tampering_and_inventory_drift_are_rejected(self) -> None:
        first = self.manifest["artifacts"][0]
        (self.directory / first["name"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            release_manifest.verify_files(self.manifest, self.directory)

        changed = json.loads(json.dumps(self.manifest))
        changed["artifacts"][0]["name"] = "unexpected.tar.gz"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            release_manifest.validate_manifest(changed)


if __name__ == "__main__":
    unittest.main()
