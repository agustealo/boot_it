from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.release_index import (
    INDEX_CHECKSUM_NAME,
    INDEX_NAME,
    SUPPORTED_PLATFORMS,
    build_release_index,
    verify_release_payload,
    write_index_checksum,
    write_release_index,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bundle(tmp_path: Path) -> tuple[Path, str]:
    source_sha = "a" * 40
    (tmp_path / "release-contract.json").write_text(
        json.dumps(
            {
                "version": "0.2.0",
                "tag": "v0.2.0",
                "source_sha": source_sha,
                "source_ref": "refs/heads/main",
                "prerelease": True,
            }
        ),
        encoding="utf-8",
    )
    for platform, suffix in (("linux-x86_64", ""), ("windows-x86_64", ".exe")):
        binary = tmp_path / f"Boot-It-0.2.0-{platform}{suffix}"
        binary.write_bytes(platform.encode("utf-8"))
        digest = _sha(binary)
        (tmp_path / f"{binary.name}.sha256").write_text(
            f"{digest}  {binary.name}\n", encoding="utf-8"
        )
        (tmp_path / f"{binary.name}.json").write_text(
            json.dumps(
                {
                    "artifact": binary.name,
                    "sha256": digest,
                    "size": binary.stat().st_size,
                    "version": "0.2.0",
                    "build_platform": platform,
                    "source_sha": source_sha,
                    "source_ref": "refs/heads/main",
                    "github_attestation_expected": True,
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / f"{binary.name}.spdx.json").write_text(
            json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8"
        )
    (tmp_path / "SHA256SUMS").write_text("aggregate\n", encoding="utf-8")
    return tmp_path, source_sha


def _manifest(bundle: Path, platform: str) -> Path:
    suffix = ".exe" if platform == "windows-x86_64" else ""
    return bundle / f"Boot-It-0.2.0-{platform}{suffix}.json"


def _rewrite_manifest(path: Path, **changes: object) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.update(changes)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _indexed_bundle(tmp_path: Path) -> tuple[Path, str]:
    bundle, source_sha = _bundle(tmp_path)
    payload = build_release_index(
        bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha
    )
    index_path = bundle / INDEX_NAME
    write_release_index(payload, index_path)
    write_index_checksum(index_path, bundle / INDEX_CHECKSUM_NAME)
    return bundle, source_sha


def test_release_index_binds_contract_platforms_and_all_files(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    payload = build_release_index(
        bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha
    )
    assert payload["schema"] == "boot-it-release-index-v1"
    assert payload["source_sha"] == source_sha
    assert payload["platforms"] == sorted(SUPPORTED_PLATFORMS)
    names = {entry["name"] for entry in payload["files"]}
    assert "release-contract.json" in names
    assert "SHA256SUMS" in names
    assert any(name.endswith("linux-x86_64") for name in names)
    assert any(name.endswith("windows-x86_64.exe") for name in names)


def test_release_index_rejects_contract_mismatch(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    with pytest.raises(ValueError, match="contract 'version' mismatch"):
        build_release_index(bundle, version="9.9.9", tag="v0.2.0", source_sha=source_sha)


def test_release_index_rejects_tampered_binary(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    binary = bundle / "Boot-It-0.2.0-linux-x86_64"
    binary.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Checksum mismatch"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_requires_exact_supported_platform_set(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    for path in list(bundle.iterdir()):
        if "windows-x86_64" in path.name:
            path.unlink()
    with pytest.raises(ValueError, match="exactly one manifest"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_rejects_duplicate_platform_manifest(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    _rewrite_manifest(_manifest(bundle, "windows-x86_64"), build_platform="linux-x86_64")
    with pytest.raises(ValueError, match="Duplicate release platform"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_rejects_manifest_source_mismatch(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    _rewrite_manifest(_manifest(bundle, "linux-x86_64"), source_sha="b" * 40)
    with pytest.raises(ValueError, match="source SHA mismatch"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_rejects_manifest_digest_mismatch(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    _rewrite_manifest(_manifest(bundle, "linux-x86_64"), sha256="0" * 64)
    with pytest.raises(ValueError, match="artifact checksum mismatch"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_rejects_manifest_size_mismatch(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    _rewrite_manifest(_manifest(bundle, "linux-x86_64"), size=999999)
    with pytest.raises(ValueError, match="artifact size mismatch"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_requires_attestation_expectation(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    _rewrite_manifest(
        _manifest(bundle, "windows-x86_64"), github_attestation_expected=False
    )
    with pytest.raises(ValueError, match="must require GitHub attestation"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_index_requires_matching_sbom(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    sbom = bundle / "Boot-It-0.2.0-linux-x86_64.spdx.json"
    sbom.unlink()
    with pytest.raises(ValueError, match="exactly one SPDX SBOM"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)


def test_release_payload_verifier_accepts_exact_indexed_set(tmp_path: Path) -> None:
    bundle, _source_sha = _indexed_bundle(tmp_path)
    verify_release_payload(bundle)


def test_release_payload_verifier_rejects_mutated_index(tmp_path: Path) -> None:
    bundle, _source_sha = _indexed_bundle(tmp_path)
    index_path = bundle / INDEX_NAME
    index_path.write_text(index_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="index checksum mismatch"):
        verify_release_payload(bundle)


def test_release_payload_verifier_rejects_mutated_indexed_file(tmp_path: Path) -> None:
    bundle, _source_sha = _indexed_bundle(tmp_path)
    target = bundle / "Boot-It-0.2.0-linux-x86_64.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match=r"Release index (?:size|checksum) mismatch"):
        verify_release_payload(bundle)


def test_release_payload_verifier_rejects_unindexed_extra_file(tmp_path: Path) -> None:
    bundle, _source_sha = _indexed_bundle(tmp_path)
    (bundle / "surprise.bin").write_bytes(b"not indexed")
    with pytest.raises(ValueError, match="unindexed extra files"):
        verify_release_payload(bundle)


def test_release_payload_verifier_rejects_missing_index_checksum(tmp_path: Path) -> None:
    bundle, _source_sha = _indexed_bundle(tmp_path)
    (bundle / INDEX_CHECKSUM_NAME).unlink()
    with pytest.raises(ValueError, match="missing from the release payload"):
        verify_release_payload(bundle)
