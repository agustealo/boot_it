from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

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


@dataclass
class SourceSnapshot:
    """Anonymous private copy of the exact bytes authorized for destructive use."""

    handle: BinaryIO
    sha256: str
    size: int

    def rewind(self) -> None:
        self.handle.seek(0)

    def close(self) -> None:
        self.handle.close()


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


def snapshot_verified_source(
    path: str,
    expected_sha256: str,
    expected_identity: SourceIdentity | None = None,
) -> SourceSnapshot:
    """Copy verified source bytes into an anonymous temporary file before target mutation.

    The returned handle, not the original pathname, becomes the authoritative byte
    stream for both write and post-write verification. The snapshot is private to
    this process and is removed automatically when closed.
    """

    source = Path(path)
    expected = expected_sha256.strip().casefold()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError("Expected source SHA-256 must be a full 64-hex digest.")

    snapshot = tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    try:
        with source.open("rb") as source_handle:
            before = _identity_from_stat(os.fstat(source_handle.fileno()))
            if expected_identity is not None and before != expected_identity:
                raise RuntimeError("Source image file identity changed before snapshot creation.")
            while chunk := source_handle.read(CHUNK_SIZE):
                snapshot.write(chunk)
                digest.update(chunk)
            after = _identity_from_stat(os.fstat(source_handle.fileno()))

        if before != after:
            raise RuntimeError("Source image changed while Boot It was sealing the write snapshot.")
        actual = digest.hexdigest()
        if actual.casefold() != expected:
            raise RuntimeError(
                "Source image bytes changed after approval. No target was modified."
            )
        snapshot.flush()
        os.fsync(snapshot.fileno())
        size = snapshot.tell()
        if size != after.size:
            raise RuntimeError("Sealed snapshot size does not match the approved source size.")
        snapshot.seek(0)
        return SourceSnapshot(handle=snapshot, sha256=actual, size=size)
    except Exception:
        snapshot.close()
        raise
