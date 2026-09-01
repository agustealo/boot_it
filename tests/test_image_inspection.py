from __future__ import annotations

import struct
import zlib
from pathlib import Path

from boot_it_image import ISO_SECTOR_SIZE, inspect_image


def _write_minimal_iso(path: Path, *, el_torito: bool = False) -> None:
    image = bytearray(40 * ISO_SECTOR_SIZE)
    if el_torito:
        boot = bytearray(ISO_SECTOR_SIZE)
        boot[0] = 0
        boot[1:6] = b"CD001"
        boot[6] = 1
        boot[7 : 7 + len(b"EL TORITO SPECIFICATION")] = b"EL TORITO SPECIFICATION"
        image[16 * ISO_SECTOR_SIZE : 17 * ISO_SECTOR_SIZE] = boot
        primary_sector = 17
    else:
        primary_sector = 16
    primary = bytearray(ISO_SECTOR_SIZE)
    primary[0] = 1
    primary[1:6] = b"CD001"
    primary[6] = 1
    image[primary_sector * ISO_SECTOR_SIZE : (primary_sector + 1) * ISO_SECTOR_SIZE] = primary
    terminator = bytearray(ISO_SECTOR_SIZE)
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1
    image[(primary_sector + 1) * ISO_SECTOR_SIZE : (primary_sector + 2) * ISO_SECTOR_SIZE] = terminator
    path.write_bytes(image)


def _write_mbr(path: Path, *, partition_sectors: int) -> None:
    image = bytearray(8 * 1024 * 1024)
    entry = bytearray(16)
    entry[4] = 0x0C
    entry[8:12] = (2048).to_bytes(4, "little")
    entry[12:16] = partition_sectors.to_bytes(4, "little")
    image[446:462] = entry
    image[510:512] = b"\x55\xaa"
    path.write_bytes(image)


def _write_gpt(path: Path, *, corrupt_header_crc: bool = False) -> None:
    sector_size = 512
    total_lbas = 32768
    image = bytearray(total_lbas * sector_size)

    # Protective MBR.
    image[446 + 4] = 0xEE
    image[446 + 8 : 446 + 12] = (1).to_bytes(4, "little")
    image[446 + 12 : 446 + 16] = (total_lbas - 1).to_bytes(4, "little")
    image[510:512] = b"\x55\xaa"

    entry_count = 128
    entry_size = 128
    entries = bytearray(entry_count * entry_size)
    # One EFI-system-style non-empty entry. The parser only validates the
    # array CRC and bounds, not partition GUID semantics.
    entries[0:16] = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    entries[16:32] = bytes.fromhex("00112233445566778899aabbccddeeff")
    struct.pack_into("<QQQ", entries, 32, 2048, 4095, 0)
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    image[2 * sector_size : 2 * sector_size + len(entries)] = entries

    header = bytearray(sector_size)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<Q", header, 24, 1)
    struct.pack_into("<Q", header, 32, total_lbas - 1)
    struct.pack_into("<Q", header, 40, 34)
    struct.pack_into("<Q", header, 48, total_lbas - 34)
    header[56:72] = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    struct.pack_into("<Q", header, 72, 2)
    struct.pack_into("<I", header, 80, entry_count)
    struct.pack_into("<I", header, 84, entry_size)
    struct.pack_into("<I", header, 88, entries_crc)
    header_crc = zlib.crc32(header[:92]) & 0xFFFFFFFF
    if corrupt_header_crc:
        header_crc ^= 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)
    image[sector_size : 2 * sector_size] = header
    path.write_bytes(image)


def test_iso9660_and_el_torito_are_detected(tmp_path: Path) -> None:
    image = tmp_path / "boot.iso"
    _write_minimal_iso(image, el_torito=True)
    inspection = inspect_image(str(image))
    assert inspection.iso9660
    assert inspection.el_torito
    assert inspection.fatal_reason == ""
    assert "El Torito boot" in inspection.summary


def test_iso_extension_without_optical_descriptor_is_rejected(tmp_path: Path) -> None:
    image = tmp_path / "fake.iso"
    image.write_bytes(b"X" * (2 * 1024 * 1024))
    inspection = inspect_image(str(image))
    assert "no recognizable ISO9660/UDF" in inspection.fatal_reason


def test_valid_mbr_disk_image_is_classified(tmp_path: Path) -> None:
    image = tmp_path / "disk.img"
    _write_mbr(image, partition_sectors=8192)
    inspection = inspect_image(str(image))
    assert inspection.partition_scheme == "mbr"
    assert inspection.fatal_reason == ""


def test_out_of_bounds_mbr_partition_is_rejected(tmp_path: Path) -> None:
    image = tmp_path / "broken.img"
    _write_mbr(image, partition_sectors=50000)
    inspection = inspect_image(str(image))
    assert "invalid MBR" in inspection.fatal_reason


def test_valid_gpt_header_and_entry_array_are_verified(tmp_path: Path) -> None:
    image = tmp_path / "gpt.img"
    _write_gpt(image)
    inspection = inspect_image(str(image))
    assert inspection.partition_scheme == "gpt"
    assert inspection.gpt_header_valid is True
    assert inspection.fatal_reason == ""


def test_corrupt_gpt_header_crc_is_rejected(tmp_path: Path) -> None:
    image = tmp_path / "broken-gpt.img"
    _write_gpt(image, corrupt_header_crc=True)
    inspection = inspect_image(str(image))
    assert inspection.gpt_header_valid is False
    assert inspection.fatal_reason == "GPT header CRC mismatch"
