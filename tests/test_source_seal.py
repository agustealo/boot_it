from __future__ import annotations

import os
from pathlib import Path

import pytest

from boot_it_source import seal_source, verify_source_seal


def test_source_seal_accepts_unchanged_bytes(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * 8192)
    approved = seal_source(str(image))
    current = verify_source_seal(str(image), approved.sha256, approved.identity)
    assert current == approved


def test_source_seal_rejects_byte_change_with_same_size_and_restored_mtime(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * 8192)
    approved = seal_source(str(image))
    original_stat = image.stat()

    image.write_bytes(b"B" * 8192)
    os.utime(image, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    stat = image.stat()
    assert stat.st_size == approved.identity.size
    assert stat.st_mtime_ns == approved.identity.mtime_ns
    with pytest.raises(RuntimeError, match="bytes changed"):
        verify_source_seal(str(image), approved.sha256, approved.identity)


def test_source_seal_rejects_replaced_file_even_when_digest_matches(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"same bytes" * 1024)
    approved = seal_source(str(image))

    replacement = tmp_path / "replacement.img"
    replacement.write_bytes(image.read_bytes())
    os.replace(replacement, image)

    if image.stat().st_ino == approved.identity.inode and image.stat().st_dev == approved.identity.device:
        pytest.skip("Filesystem reused the same file identity for replacement.")
    with pytest.raises(RuntimeError, match="file identity changed"):
        verify_source_seal(str(image), approved.sha256, approved.identity)


def test_source_seal_detects_change_during_hash(monkeypatch, tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * (5 * 1024 * 1024))

    original_fstat = os.fstat
    calls = 0

    def changing_fstat(fd: int):
        nonlocal calls
        calls += 1
        result = original_fstat(fd)
        if calls == 1:
            image.write_bytes(b"B" * image.stat().st_size)
        return result

    monkeypatch.setattr(os, "fstat", changing_fstat)
    with pytest.raises(RuntimeError, match="changed while Boot It was hashing"):
        seal_source(str(image))
