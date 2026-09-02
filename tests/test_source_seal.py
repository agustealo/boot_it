from __future__ import annotations

import os
from pathlib import Path

import pytest

from boot_it_source import seal_source, snapshot_verified_source, verify_source_seal


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


def test_snapshot_preserves_authorized_bytes_after_original_is_replaced(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    authorized = b"AUTHORIZED" * 4096
    image.write_bytes(authorized)
    approved = seal_source(str(image))

    snapshot = snapshot_verified_source(str(image), approved.sha256, approved.identity)
    try:
        replacement = tmp_path / "replacement.img"
        replacement.write_bytes(b"MUTATED!!!" * 4096)
        os.replace(replacement, image)
        snapshot.rewind()
        assert snapshot.handle.read() == authorized
        assert snapshot.size == len(authorized)
        assert snapshot.sha256 == approved.sha256
    finally:
        snapshot.close()


def test_snapshot_rejects_changed_source_before_target_phase(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * 16384)
    approved = seal_source(str(image))
    image.write_bytes(b"B" * 16384)

    with pytest.raises(RuntimeError, match="bytes changed after approval"):
        snapshot_verified_source(str(image), approved.sha256, None)


def test_snapshot_rejects_short_or_malformed_digest(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * 8192)
    with pytest.raises(ValueError, match="full 64-hex"):
        snapshot_verified_source(str(image), "deadbeef")


def test_snapshot_copy_can_be_cancelled_before_target_mutation(tmp_path: Path) -> None:
    image = tmp_path / "image.img"
    image.write_bytes(b"A" * (5 * 1024 * 1024))
    approved = seal_source(str(image))
    checks = 0

    def cancel() -> None:
        nonlocal checks
        checks += 1
        if checks >= 2:
            raise RuntimeError("cancelled")

    with pytest.raises(RuntimeError, match="cancelled"):
        snapshot_verified_source(
            str(image),
            approved.sha256,
            approved.identity,
            cancel_check=cancel,
        )
