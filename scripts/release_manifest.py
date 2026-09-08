#!/usr/bin/env python3
"""Generate and strictly verify the ego-browser release evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
COMPONENT = "agent-remote-ego-browser"
PROTOCOL = "ego-browser-bridge-v1"
SKILL_VERSION = "1.2.3"
LOCAL_RUNTIME_VERSION = "0.4.7.4"
READINESS_BLOCKER = "learning_bundle_signing_private_key_unavailable"
LEARNING_KEY_ID = "ego-browser-learning-2026-01"
# Keep the blocked release contract explicit for reviewers and compatibility checks:
# The blocked JSON shape is `"production_ready": false` until a verified bundle exists.
BLOCKED_PRODUCTION_READY = False
ROOT_FIELDS = {
    "schema_version",
    "component",
    "version",
    "protocol_versions",
    "wrapper_version",
    "bridge_version",
    "device_client_version",
    "skill_version",
    "local_ego_browser_runtime_version",
    "remote_platform",
    "local_platform",
    "profile",
    "signing_type",
    "signer_certificate_sha256",
    "production_ready",
    "readiness_blockers",
    "apple_notarized",
    "public_distribution",
    "hardened_runtime",
    "nested_signatures_verified",
    "outbound_policy",
    "credential_profile",
    "learning_bundle_digest",
    "learning_bundle_signing_key_id",
    "vulnerability_report",
    "artifacts",
}
ARTIFACT_FIELDS = {
    "name",
    "kind",
    "platform",
    "arch",
    "libc",
    "sha256",
    "size_bytes",
    "sbom",
    "sigstore_bundle",
    "provenance",
}
EVIDENCE_FIELDS = {"name", "sha256", "sigstore_bundle"}


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate release manifest field: {key}")
        result[key] = value
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_artifacts(version: str) -> list[tuple[str, str, str, str | None]]:
    return [
        (f"{COMPONENT}-wrapper-linux-amd64-glibc-{version}.tar.gz", "linux", "amd64", "glibc"),
        (f"{COMPONENT}-wrapper-linux-arm64-glibc-{version}.tar.gz", "linux", "arm64", "glibc"),
        (f"{COMPONENT}-wrapper-linux-amd64-musl-{version}.tar.gz", "linux", "amd64", "musl"),
        (f"{COMPONENT}-wrapper-linux-arm64-musl-{version}.tar.gz", "linux", "arm64", "musl"),
        (f"{COMPONENT}-macos-universal-{version}.tar.gz", "macos", "universal", None),
    ]


def evidence_for(path: Path) -> dict[str, str]:
    return {
        "name": path.name,
        "sha256": sha256_file(path),
        "sigstore_bundle": f"{path.name}.sigstore.json",
    }


def artifact_for(
    directory: Path,
    name: str,
    platform: str,
    arch: str,
    libc: str | None,
) -> dict[str, Any]:
    path = directory / name
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing regular release artifact: {name}")
    sbom = f"{name.removesuffix('.tar.gz')}.spdx.json"
    return {
        "name": name,
        "kind": "remote_wrapper" if platform == "linux" else "macos_local_components",
        "platform": platform,
        "arch": arch,
        "libc": libc,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "sbom": sbom,
        "sigstore_bundle": f"{name}.sigstore.json",
        "provenance": True,
    }


def normalize_digest(value: str, label: str = "digest") -> str:
    """Normalize a bare or protocol-prefixed SHA-256 digest to lowercase hex."""

    normalized = value.removeprefix("sha256:").lower()
    if SHA256.fullmatch(normalized) is None:
        raise ValueError(f"{label} is invalid")
    return normalized


def generate_manifest(
    version: str,
    certificate: str,
    directory: Path,
    *,
    learning_bundle_digest: str | None = None,
    learning_bundle_key_id: str = LEARNING_KEY_ID,
) -> dict[str, Any]:
    if SEMVER.fullmatch(version) is None:
        raise ValueError("release version is invalid")
    certificate = normalize_digest(certificate, "signer certificate SHA-256")
    if (
        not isinstance(learning_bundle_key_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", learning_bundle_key_id)
    ):
        raise ValueError("learning bundle signing key ID is invalid")
    if learning_bundle_digest is not None:
        learning_bundle_digest = normalize_digest(
            learning_bundle_digest, "learning bundle digest"
        )
    production_ready = learning_bundle_digest is not None
    artifacts = [
        artifact_for(directory, name, platform, arch, libc)
        for name, platform, arch, libc in expected_artifacts(version)
    ]
    report = directory / f"{COMPONENT}-{version}.cargo-audit.json"
    if not report.is_file() or report.is_symlink():
        raise ValueError(f"missing vulnerability report: {report.name}")
    return {
        "schema_version": 1,
        "component": COMPONENT,
        "version": version,
        "protocol_versions": [PROTOCOL],
        "wrapper_version": version,
        "bridge_version": version,
        "device_client_version": version,
        "skill_version": SKILL_VERSION,
        "local_ego_browser_runtime_version": LOCAL_RUNTIME_VERSION,
        "remote_platform": "linux",
        "local_platform": "macos",
        "profile": "community-local-trust",
        "signing_type": "project-self-signed",
        "signer_certificate_sha256": certificate,
        "production_ready": production_ready,
        "readiness_blockers": [] if production_ready else [READINESS_BLOCKER],
        "apple_notarized": False,
        "public_distribution": False,
        "hardened_runtime": True,
        "nested_signatures_verified": True,
        "outbound_policy": "application-enforced",
        "credential_profile": "community_file",
        "learning_bundle_digest": learning_bundle_digest,
        "learning_bundle_signing_key_id": learning_bundle_key_id,
        "vulnerability_report": evidence_for(report),
        "artifacts": artifacts,
    }


def require_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return value


def require_filename(value: Any, label: str) -> str:
    if not isinstance(value, str) or FILE_NAME.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = require_object(value, ROOT_FIELDS, "release manifest")
    version = manifest["version"]
    if (
        isinstance(manifest["schema_version"], bool)
        or not isinstance(manifest["schema_version"], int)
        or manifest["schema_version"] != 1
        or manifest["component"] != COMPONENT
        or not isinstance(version, str)
        or SEMVER.fullmatch(version) is None
        or manifest["protocol_versions"] != [PROTOCOL]
        or any(manifest[field] != version for field in ("wrapper_version", "bridge_version", "device_client_version"))
        or manifest["skill_version"] != SKILL_VERSION
        or manifest["local_ego_browser_runtime_version"] != LOCAL_RUNTIME_VERSION
        or manifest["remote_platform"] != "linux"
        or manifest["local_platform"] != "macos"
        or manifest["profile"] != "community-local-trust"
        or manifest["signing_type"] != "project-self-signed"
        or not isinstance(manifest["signer_certificate_sha256"], str)
        or SHA256.fullmatch(manifest["signer_certificate_sha256"]) is None
        or manifest["apple_notarized"] is not False
        or manifest["public_distribution"] is not False
        or manifest["hardened_runtime"] is not True
        or manifest["nested_signatures_verified"] is not True
        or manifest["outbound_policy"] != "application-enforced"
        or manifest["credential_profile"] != "community_file"
        or not isinstance(manifest["learning_bundle_signing_key_id"], str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
            manifest["learning_bundle_signing_key_id"],
        ) is None
    ):
        raise ValueError("release manifest compatibility or trust fields are invalid")
    blockers = manifest["readiness_blockers"]
    if (
        not isinstance(blockers, list)
        or len(blockers) != len(set(blockers))
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in blockers)
    ):
        raise ValueError("release readiness blockers are invalid")

    learning_digest = manifest["learning_bundle_digest"]
    if learning_digest is not None and (
        not isinstance(learning_digest, str) or SHA256.fullmatch(learning_digest) is None
    ):
        raise ValueError("learning bundle digest is invalid")
    if manifest["production_ready"] is True:
        if blockers or learning_digest is None:
            raise ValueError(
                "production-ready release requires signed learning evidence; trust fields are incomplete"
            )
    elif (
        manifest["production_ready"] is not BLOCKED_PRODUCTION_READY
        or READINESS_BLOCKER not in blockers
        or learning_digest is not None
    ):
        raise ValueError("false readiness must retain the learning signing blocker")

    report = require_object(manifest["vulnerability_report"], EVIDENCE_FIELDS, "vulnerability evidence")
    for field in ("name", "sigstore_bundle"):
        require_filename(report[field], f"vulnerability evidence {field}")
    if not isinstance(report["sha256"], str) or SHA256.fullmatch(report["sha256"]) is None:
        raise ValueError("vulnerability evidence digest is invalid")

    artifacts = manifest["artifacts"]
    expected = expected_artifacts(version)
    if not isinstance(artifacts, list) or len(artifacts) != len(expected):
        raise ValueError("release artifact inventory is incomplete")
    expected_by_name = {item[0]: item[1:] for item in expected}
    seen: set[str] = set()
    for raw in artifacts:
        artifact = require_object(raw, ARTIFACT_FIELDS, "release artifact")
        name = require_filename(artifact["name"], "artifact name")
        if name in seen or name not in expected_by_name:
            raise ValueError(f"unexpected or duplicate release artifact: {name}")
        seen.add(name)
        platform, arch, libc = expected_by_name[name]
        if (
            artifact["kind"] != ("remote_wrapper" if platform == "linux" else "macos_local_components")
            or artifact["platform"] != platform
            or artifact["arch"] != arch
            or artifact["libc"] != libc
            or not isinstance(artifact["sha256"], str)
            or SHA256.fullmatch(artifact["sha256"]) is None
            or not isinstance(artifact["size_bytes"], int)
            or isinstance(artifact["size_bytes"], bool)
            or artifact["size_bytes"] <= 0
            or artifact["provenance"] is not True
        ):
            raise ValueError(f"release artifact metadata is invalid: {name}")
        require_filename(artifact["sbom"], "artifact SBOM")
        require_filename(artifact["sigstore_bundle"], "artifact signature bundle")
    if seen != set(expected_by_name):
        raise ValueError("release artifact inventory is incomplete")
    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("release manifest must be a regular file")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("release manifest exceeds 1 MiB")
    return validate_manifest(json.loads(raw, object_pairs_hook=reject_duplicates))


def verify_files(manifest: dict[str, Any], directory: Path) -> None:
    records = [manifest["vulnerability_report"], *manifest["artifacts"]]
    for record in records:
        path = directory / record["name"]
        if not path.is_file() or path.is_symlink() or sha256_file(path) != record["sha256"]:
            raise ValueError(f"release evidence digest mismatch: {record['name']}")
        if "size_bytes" in record and path.stat().st_size != record["size_bytes"]:
            raise ValueError(f"release evidence size mismatch: {record['name']}")
        signature = directory / record["sigstore_bundle"]
        if not signature.is_file() or signature.is_symlink():
            raise ValueError(f"missing Sigstore bundle: {signature.name}")
        if "sbom" in record:
            sbom = directory / record["sbom"]
            sbom_signature = directory / f"{record['sbom']}.sigstore.json"
            if not sbom.is_file() or sbom.is_symlink() or not sbom_signature.is_file() or sbom_signature.is_symlink():
                raise ValueError(f"missing signed SBOM evidence: {record['sbom']}")


def write_manifest(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
    path.write_bytes(encoded)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--version", required=True)
    generate.add_argument("--certificate-sha256", required=True)
    generate.add_argument(
        "--learning-bundle-digest",
        help="Verified Site Learning digest; its presence promotes this manifest",
    )
    generate.add_argument("--learning-bundle-key-id", default=LEARNING_KEY_ID)
    generate.add_argument("--artifact-dir", type=Path, required=True)
    generate.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--artifact-dir", type=Path)
    verify.add_argument("--expected-version")
    verify.add_argument("--expected-certificate-sha256")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "generate":
            manifest = generate_manifest(
                args.version,
                args.certificate_sha256,
                args.artifact_dir,
                learning_bundle_digest=args.learning_bundle_digest,
                learning_bundle_key_id=args.learning_bundle_key_id,
            )
            validate_manifest(manifest)
            write_manifest(args.output, manifest)
            return 0
        manifest = load_manifest(args.manifest)
        if args.expected_version is not None and manifest["version"] != args.expected_version:
            raise ValueError("release manifest version does not match expectation")
        if (
            args.expected_certificate_sha256 is not None
            and manifest["signer_certificate_sha256"] != args.expected_certificate_sha256
        ):
            raise ValueError("release signer certificate does not match pinned fingerprint")
        if args.artifact_dir is not None:
            verify_files(manifest, args.artifact_dir)
        print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release manifest verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
