from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.release_index import build_release_index


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
        (tmp_path / f"{binary.name}.sha256").write_text(
            f"{_sha(binary)}  {binary.name}\n", encoding="utf-8"
        )
        (tmp_path / f"{binary.name}.json").write_text(
            json.dumps({"artifact": binary.name}), encoding="utf-8"
        )
        (tmp_path / f"{binary.name}.spdx.json").write_text(
            json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8"
        )
    (tmp_path / "SHA256SUMS").write_text("aggregate\n", encoding="utf-8")
    return tmp_path, source_sha


def test_release_index_binds_contract_and_all_files(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    payload = build_release_index(
        bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha
    )
    assert payload["schema"] == "boot-it-release-index-v1"
    assert payload["source_sha"] == source_sha
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


def test_release_index_requires_both_platform_evidence(tmp_path: Path) -> None:
    bundle, source_sha = _bundle(tmp_path)
    for path in list(bundle.iterdir()):
        if "windows-x86_64" in path.name:
            path.unlink()
    with pytest.raises(ValueError, match="platform manifests"):
        build_release_index(bundle, version="0.2.0", tag="v0.2.0", source_sha=source_sha)
