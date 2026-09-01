from __future__ import annotations

from pathlib import Path

import boot_it
from boot_it_image import ISO_SECTOR_SIZE
from boot_it_runtime import install_runtime_patches


def _minimal_iso(path: Path) -> None:
    payload = bytearray(40 * ISO_SECTOR_SIZE)
    primary = bytearray(ISO_SECTOR_SIZE)
    primary[0] = 1
    primary[1:6] = b"CD001"
    primary[6] = 1
    payload[16 * ISO_SECTOR_SIZE : 17 * ISO_SECTOR_SIZE] = primary
    terminator = bytearray(ISO_SECTOR_SIZE)
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1
    payload[17 * ISO_SECTOR_SIZE : 18 * ISO_SECTOR_SIZE] = terminator
    path.write_bytes(payload)


def test_runtime_accepts_structurally_valid_iso(tmp_path: Path) -> None:
    image = tmp_path / "valid.iso"
    _minimal_iso(image)
    original_validate = boot_it.validate_image
    original_hash_ready = boot_it.BootItWindow._hash_ready
    original_linux_write = boot_it.linux_write
    try:
        install_runtime_patches(boot_it)
        assert boot_it.validate_image(str(image)) == (True, "")
    finally:
        boot_it.validate_image = original_validate
        boot_it.BootItWindow._hash_ready = original_hash_ready
        boot_it.linux_write = original_linux_write


def test_runtime_rejects_iso_extension_with_no_optical_structure(tmp_path: Path) -> None:
    image = tmp_path / "renamed.iso"
    image.write_bytes(b"not-an-iso" * 200000)
    original_validate = boot_it.validate_image
    original_hash_ready = boot_it.BootItWindow._hash_ready
    original_linux_write = boot_it.linux_write
    try:
        install_runtime_patches(boot_it)
        valid, reason = boot_it.validate_image(str(image))
        assert not valid
        assert "structure check failed" in reason.lower()
        assert "iso9660/udf" in reason.lower()
    finally:
        boot_it.validate_image = original_validate
        boot_it.BootItWindow._hash_ready = original_hash_ready
        boot_it.linux_write = original_linux_write


def test_runtime_keeps_unknown_raw_img_permissive(tmp_path: Path) -> None:
    image = tmp_path / "custom.img"
    image.write_bytes(b"R" * (2 * 1024 * 1024))
    original_validate = boot_it.validate_image
    original_hash_ready = boot_it.BootItWindow._hash_ready
    original_linux_write = boot_it.linux_write
    try:
        install_runtime_patches(boot_it)
        assert boot_it.validate_image(str(image)) == (True, "")
    finally:
        boot_it.validate_image = original_validate
        boot_it.BootItWindow._hash_ready = original_hash_ready
        boot_it.linux_write = original_linux_write
