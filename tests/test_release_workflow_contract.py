from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_release_builds_every_wrapper_and_signed_macos_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for value in (
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "macos-universal",
            "cargo audit",
            "anchore/sbom-action",
            "cosign sign-blob",
            "attest-build-provenance",
            "release_manifest.py generate",
            "production-community-release",
            "Run complete tag-bound quality gate",
            "scripts/extract-learning-bundle.py",
            "CERTIFICATE_SHA256: ${{ vars.COMMUNITY_SIGNER_CERTIFICATE_SHA256 }}",
            "LEARNING_BUNDLE_KEY_ID",
            "PRODUCTION_READY",
            "prerelease: ${{ needs.macos.outputs.production-ready != 'true' }}",
        ):
            self.assertIn(value, workflow)
        self.assertNotIn('tar -xzf "$bundle_archive" -C', workflow)

        installer = (ROOT / "installer" / "install-macos.sh").read_text()
        self.assertIn("clear_verified_quarantine.py", installer)
        self.assertNotIn("xattr -dr com.apple.quarantine", installer)

    def test_release_contract_keeps_readiness_false_without_learning_key(self) -> None:
        manifest_tool = (ROOT / "scripts/release_manifest.py").read_text()
        build_script = (ROOT / "scripts/build-community-release.sh").read_text()
        for content in (manifest_tool, build_script):
            self.assertIn("learning_bundle_signing_private_key_unavailable", content)
            self.assertRegex(content, r'production_ready["\']?:?\s*(False|false)')

    def test_repository_has_no_forbidden_product_reference(self) -> None:
        forbidden = "agent-remote-" + "device"
        for path in ROOT.rglob("*"):
            if not path.is_file() or "target" in path.parts or path == Path(__file__):
                continue
            try:
                content = path.read_text()
            except UnicodeDecodeError:
                continue
            self.assertNotIn(forbidden, content, str(path))

    def test_operations_document_the_packaged_installer_and_false_readiness(self) -> None:
        for name in ("operations.md", "operations.zh-CN.md"):
            content = (ROOT / "docs" / name).read_text()
            self.assertIn("./installer/install-macos.sh", content)
            self.assertNotIn("\n./install-macos.sh", content)
            self.assertIn("production_ready", content)
            self.assertRegex(content, r"production_ready.{0,32}(false|保持 false)")

        for stem in ("architecture", "security", "operations", "release"):
            self.assertTrue((ROOT / "docs" / f"{stem}.md").is_file())
            self.assertTrue((ROOT / "docs" / f"{stem}.zh-CN.md").is_file())


if __name__ == "__main__":
    unittest.main()
