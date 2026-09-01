from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

SECTOR_SIZE = 512
ISO_SECTOR_SIZE = 2048
ISO_DESCRIPTOR_START = 16
ISO_DESCRIPTOR_LIMIT = 64
GPT_SIGNATURE = b"EFI PART"
ISO_SIGNATURE = b"CD001"
UDF_SIGNATURES = {b"BEA01", b"NSR02", b"NSR03"}
EL_TORITO_ID = b"EL TORITO SPECIFICATION"


@dataclass(frozen=True)
class ImageInspection:
    path: str
    size: int
    extension: str
    format: str
    partition_scheme: str
    iso9660: bool = False
    udf: bool = False
    el_torito: bool = False
    mbr_signature: bool = False
    gpt_signature: bool = False
    gpt_header_valid: bool | None = None
    filesystem_hint: str = ""
    fatal_reason: str = ""
    warning: str = ""

    @property
    def summary(self) -> str:
        parts: list[str] = []
        if self.iso9660:
            parts.append("ISO9660")
        if self.udf:
            parts.append("UDF")
        if self.el_torito:
            parts.append("El Torito boot")
        if self.partition_scheme != "none":
            parts.append(self.partition_scheme.upper())
        if self.filesystem_hint:
            parts.append(self.filesystem_hint)
        if not parts:
            parts.append(self.format)
        if self.warning:
            parts.append(f"warning: {self.warning}")
        return " · ".join(parts)


def _read_at(handle, offset: int, size: int) -> bytes:
    handle.seek(offset)
    return handle.read(size)


def _has_valid_mbr_partition_table(first_sector: bytes, image_size: int) -> bool:
    if len(first_sector) < SECTOR_SIZE or first_sector[510:512] != b"\x55\xaa":
        return False
    total_sectors = image_size // SECTOR_SIZE
    for index in range(4):
        entry = first_sector[446 + index * 16 : 462 + index * 16]
        if len(entry) != 16:
            continue
        partition_type = entry[4]
        start_lba = int.from_bytes(entry[8:12], "little")
        sectors = int.from_bytes(entry[12:16], "little")
        if partition_type == 0 or sectors == 0:
            continue
        if start_lba >= total_sectors:
            return False
        # Protective GPT entries may describe the whole virtual disk and are
        # allowed to end exactly at the image boundary.
        if partition_type != 0xEE and start_lba + sectors > total_sectors:
            return False
    return True


def _inspect_gpt(handle, image_size: int) -> tuple[bool, str]:
    """Return (valid, reason) for a 512-byte-sector GPT header and entry array."""
    header_sector = _read_at(handle, SECTOR_SIZE, SECTOR_SIZE)
    if len(header_sector) < 92 or header_sector[:8] != GPT_SIGNATURE:
        return False, "missing GPT header"

    revision, header_size, header_crc = struct.unpack_from("<III", header_sector, 8)
    if revision not in {0x00010000, 0x00010200}:
        return False, f"unsupported GPT revision 0x{revision:08x}"
    if header_size < 92 or header_size > SECTOR_SIZE:
        return False, "invalid GPT header size"

    header_for_crc = bytearray(header_sector[:header_size])
    header_for_crc[16:20] = b"\0\0\0\0"
    if zlib.crc32(header_for_crc) & 0xFFFFFFFF != header_crc:
        return False, "GPT header CRC mismatch"

    current_lba = struct.unpack_from("<Q", header_sector, 24)[0]
    backup_lba = struct.unpack_from("<Q", header_sector, 32)[0]
    first_usable = struct.unpack_from("<Q", header_sector, 40)[0]
    last_usable = struct.unpack_from("<Q", header_sector, 48)[0]
    entries_lba = struct.unpack_from("<Q", header_sector, 72)[0]
    entry_count, entry_size, entries_crc = struct.unpack_from("<III", header_sector, 80)
    total_lbas = image_size // SECTOR_SIZE

    if current_lba != 1:
        return False, "primary GPT header is not at LBA 1"
    if not (2 <= first_usable <= last_usable < total_lbas):
        return False, "GPT usable-LBA range is outside the image"
    if backup_lba >= total_lbas:
        return False, "GPT backup header is outside the image"
    if entry_count == 0 or entry_count > 4096:
        return False, "invalid GPT partition-entry count"
    if entry_size < 128 or entry_size > 4096 or entry_size % 8:
        return False, "invalid GPT partition-entry size"

    array_size = entry_count * entry_size
    if array_size > 16 * 1024 * 1024:
        return False, "GPT partition array is unexpectedly large"
    array_offset = entries_lba * SECTOR_SIZE
    if array_offset + array_size > image_size:
        return False, "GPT partition array extends beyond the image"
    entries = _read_at(handle, array_offset, array_size)
    if len(entries) != array_size:
        return False, "truncated GPT partition array"
    if zlib.crc32(entries) & 0xFFFFFFFF != entries_crc:
        return False, "GPT partition-array CRC mismatch"
    return True, ""


def _inspect_optical_descriptors(handle, image_size: int) -> tuple[bool, bool, bool]:
    iso9660 = False
    udf = False
    el_torito = False
    for sector in range(ISO_DESCRIPTOR_START, ISO_DESCRIPTOR_LIMIT):
        offset = sector * ISO_SECTOR_SIZE
        if offset + ISO_SECTOR_SIZE > image_size:
            break
        descriptor = _read_at(handle, offset, ISO_SECTOR_SIZE)
        if len(descriptor) < 7:
            break
        identifier = descriptor[1:6]
        if identifier == ISO_SIGNATURE:
            iso9660 = True
            if descriptor[0] == 0 and EL_TORITO_ID in descriptor[:80].upper():
                el_torito = True
            if descriptor[0] == 255:
                break
        elif identifier in UDF_SIGNATURES:
            udf = True
        # UDF volume-recognition descriptors also store the five-byte ID at
        # byte 1. Keep scanning because hybrid ISO/UDF images are common.
    return iso9660, udf, el_torito


def _filesystem_hint(first_4096: bytes) -> str:
    if first_4096[3:11] == b"NTFS    ":
        return "NTFS"
    if first_4096[3:11] == b"EXFAT   ":
        return "exFAT"
    if first_4096[54:62] == b"FAT16   " or first_4096[82:90] == b"FAT32   ":
        return "FAT"
    # ext2/3/4 superblock magic is 0xEF53 at byte 56 of the superblock,
    # which starts 1024 bytes from the beginning of a filesystem image.
    if len(first_4096) >= 1082 and first_4096[1080:1082] == b"\x53\xef":
        return "ext filesystem"
    return ""


def inspect_image(path: str) -> ImageInspection:
    image = Path(path)
    size = image.stat().st_size
    extension = image.suffix.lower()
    with image.open("rb") as handle:
        first_4096 = _read_at(handle, 0, min(4096, size))
        first_sector = first_4096[:SECTOR_SIZE]
        mbr_signature = len(first_sector) >= SECTOR_SIZE and first_sector[510:512] == b"\x55\xaa"
        mbr_valid = _has_valid_mbr_partition_table(first_sector, size) if mbr_signature else False
        gpt_signature = _read_at(handle, SECTOR_SIZE, 8) == GPT_SIGNATURE if size >= 2 * SECTOR_SIZE else False
        gpt_valid: bool | None = None
        fatal_reason = ""
        if gpt_signature:
            gpt_valid, gpt_reason = _inspect_gpt(handle, size)
            if not gpt_valid:
                fatal_reason = gpt_reason
        iso9660, udf, el_torito = _inspect_optical_descriptors(handle, size)

    filesystem_hint = _filesystem_hint(first_4096)
    if gpt_signature:
        partition_scheme = "gpt"
    elif mbr_valid:
        partition_scheme = "mbr"
    else:
        partition_scheme = "none"

    if iso9660 or udf:
        image_format = "optical image"
    elif partition_scheme != "none":
        image_format = "disk image"
    elif filesystem_hint:
        image_format = "filesystem image"
    else:
        image_format = "raw image"

    warning = ""
    if extension == ".iso" and not (iso9660 or udf):
        fatal_reason = fatal_reason or "The .iso file has no recognizable ISO9660/UDF volume descriptor."
    elif extension == ".img" and image_format == "raw image":
        warning = "no recognized partition table or filesystem signature"
    if mbr_signature and not mbr_valid and not gpt_signature:
        fatal_reason = fatal_reason or "The image has an invalid MBR partition table."

    return ImageInspection(
        path=str(image),
        size=size,
        extension=extension,
        format=image_format,
        partition_scheme=partition_scheme,
        iso9660=iso9660,
        udf=udf,
        el_torito=el_torito,
        mbr_signature=mbr_signature,
        gpt_signature=gpt_signature,
        gpt_header_valid=gpt_valid,
        filesystem_hint=filesystem_hint,
        fatal_reason=fatal_reason,
        warning=warning,
    )
