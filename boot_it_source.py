from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

CHUNK_SIZE = 4 * 1024 * 1024


@dataclass(frozen=True)
class SourceIdentity:
    size: int
    mtime_ns: int
    device: int | None
    inode: int | None


@dataclass(frozen=True)
class SourceSeal:
    path: str
    sha256: str
    identity: SourceIdentity


def _identity_from_stat(stat: os.stat_result) -> SourceIdentity:
    return SourceIdentity(
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        device=getattr(stat, "st_dev", None),
        inode=getattr(stat, "st_ino", None),
    )


def seal_source(path: str) -> SourceSeal:
    source = Path(path)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        before = _identity_from_stat(os.fstat(handle.fileno()))
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
        after = _identity_from_stat(os.fstat(handle.fileno()))
    if before != after:
        raise RuntimeError("Source image changed while Boot It was hashing it.")
    return SourceSeal(path=str(source), sha256=digest.hexdigest(), identity=after)


def verify_source_seal(
    path: str,
    expected_sha256: str,
    expected_identity: SourceIdentity | None = None,
) -> SourceSeal:
    seal = seal_source(path)
    if seal.sha256.casefold() != expected_sha256.strip().casefold():
        raise RuntimeError(
            "Source image bytes changed after verification. No destructive write will start from this image."
        )
    if expected_identity is not None and seal.identity != expected_identity:
        raise RuntimeError(
            "Source image file identity changed after verification even though its digest matched. Re-select and verify it."
        )
    return seal
