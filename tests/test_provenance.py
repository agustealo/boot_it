from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from boot_it_provenance import parse_sha256_manifest, verify_sha256_manifest


def _image(tmp_path: Path, name: str = "system.iso") -> tuple[Path, str]:
    image = tmp_path / name
    image.write_bytes(b"boot-it-provenance" * 1000)
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    return image, digest


def test_coreutils_sha256sums_matches_exact_filename(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{digest}  {image.name}\n", encoding="utf-8")

    result = verify_sha256_manifest(image, manifest)
    assert result.status == "verified"
    assert result.expected_digest == digest
    assert result.authenticity == "unverified_manifest"
    assert "not been independently verified" in result.message


def test_binary_marker_coreutils_format_is_supported(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "checksums.txt"
    manifest.write_text(f"{digest} *{image.name}\n", encoding="utf-8")
    assert verify_sha256_manifest(image, manifest).is_match


def test_bsd_sha256_format_is_supported(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "checksums.txt"
    manifest.write_text(f"SHA256 ({image.name}) = {digest}\n", encoding="utf-8")
    assert verify_sha256_manifest(image, manifest).is_match


def test_single_bare_digest_requires_single_entry_manifest(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "digest.sha256"
    manifest.write_text(f"{digest}\n", encoding="utf-8")
    assert verify_sha256_manifest(image, manifest).is_match


def test_manifest_mismatch_is_distinct_from_authenticity(tmp_path: Path) -> None:
    image, _digest = _image(tmp_path)
    wrong = "0" * 64
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{wrong}  {image.name}\n", encoding="utf-8")

    result = verify_sha256_manifest(image, manifest)
    assert result.status == "mismatch"
    assert not result.is_match
    assert result.authenticity == "unverified_manifest"


def test_manifest_not_listing_filename_does_not_fallback_to_another_entry(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{digest}  different.iso\n", encoding="utf-8")
    assert verify_sha256_manifest(image, manifest).status == "not_listed"


def test_conflicting_same_basename_is_ambiguous(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(
        f"{digest}  releases/{image.name}\n{'f' * 64}  archive/{image.name}\n",
        encoding="utf-8",
    )
    assert verify_sha256_manifest(image, manifest).status == "ambiguous"


def test_identical_duplicate_entries_are_not_ambiguous(tmp_path: Path) -> None:
    image, digest = _image(tmp_path)
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(
        f"{digest}  releases/{image.name}\n{digest}  archive/{image.name}\n",
        encoding="utf-8",
    )
    assert verify_sha256_manifest(image, manifest).is_match


def test_empty_or_unparseable_manifest_is_rejected(tmp_path: Path) -> None:
    image, _digest = _image(tmp_path)
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text("not a checksum manifest\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No SHA-256 entries"):
        verify_sha256_manifest(image, manifest)


def test_parser_ignores_comments_and_rejects_escaped_coreutils_filename() -> None:
    digest = "a" * 64
    entries = parse_sha256_manifest(
        f"# publisher checksums\n\\{digest}  file\\nname.iso\n{digest}  safe.iso\n"
    )
    assert len(entries) == 1
    assert entries[0].filename == "safe.iso"
