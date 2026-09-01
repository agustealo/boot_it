from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_MANIFEST_SIZE = 8 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
COREUTILS_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([ *])(.+)$")
BSD_RE = re.compile(r"^SHA256[ \t]*\((.+)\)[ \t]*=[ \t]*([0-9a-fA-F]{64})$", re.IGNORECASE)
OPENSSL_RE = re.compile(r"^SHA2?-?256[ \t]*\((.+)\)[ \t]*=[ \t]*([0-9a-fA-F]{64})$", re.IGNORECASE)


@dataclass(frozen=True)
class ChecksumEntry:
    digest: str
    filename: str | None
    line_number: int


@dataclass(frozen=True)
class ProvenanceResult:
    status: str
    manifest: str
    image: str
    actual_digest: str
    expected_digest: str = ""
    matched_filename: str = ""
    authenticity: str = "unverified_manifest"
    message: str = ""

    @property
    def is_match(self) -> bool:
        return self.status == "verified"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_manifest_filename(value: str) -> str:
    value = value.strip()
    if value.startswith("./"):
        value = value[2:]
    return value.replace("\\", "/")


def parse_sha256_manifest(text: str) -> list[ChecksumEntry]:
    entries: list[ChecksumEntry] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = BSD_RE.match(line) or OPENSSL_RE.match(line)
        if match:
            filename, digest = match.groups()
            entries.append(
                ChecksumEntry(
                    digest=digest.lower(),
                    filename=_normalize_manifest_filename(filename),
                    line_number=line_number,
                )
            )
            continue

        match = COREUTILS_RE.match(line)
        if match:
            digest, _mode, filename = match.groups()
            # GNU coreutils prefixes escaped filenames with a backslash before
            # the digest line. Correctly decoding every escape is subtle, so
            # reject that syntax rather than bind a checksum to the wrong file.
            if raw_line.startswith("\\"):
                continue
            entries.append(
                ChecksumEntry(
                    digest=digest.lower(),
                    filename=_normalize_manifest_filename(filename),
                    line_number=line_number,
                )
            )
            continue

        if SHA256_RE.fullmatch(line):
            entries.append(ChecksumEntry(digest=line.lower(), filename=None, line_number=line_number))

    return entries


def read_sha256_manifest(path: str | Path) -> list[ChecksumEntry]:
    manifest = Path(path)
    if not manifest.is_file():
        raise FileNotFoundError(manifest)
    size = manifest.stat().st_size
    if size == 0:
        raise ValueError("Checksum manifest is empty.")
    if size > MAX_MANIFEST_SIZE:
        raise ValueError("Checksum manifest is unexpectedly large.")
    text = manifest.read_text(encoding="utf-8", errors="strict")
    entries = parse_sha256_manifest(text)
    if not entries:
        raise ValueError("No SHA-256 entries were found in the selected manifest.")
    return entries


def _candidate_entries(image: Path, entries: list[ChecksumEntry]) -> list[ChecksumEntry]:
    image_name = image.name
    exact = [entry for entry in entries if entry.filename in {image_name, f"./{image_name}"}]
    if exact:
        return exact

    basename_matches = [
        entry
        for entry in entries
        if entry.filename is not None and PurePosixPath(entry.filename).name == image_name
    ]
    if basename_matches:
        # A manifest containing two different paths with the same basename is
        # intentionally ambiguous. The caller will reject conflicting hashes.
        return basename_matches

    bare = [entry for entry in entries if entry.filename is None]
    if len(entries) == 1 and len(bare) == 1:
        return bare
    return []


def verify_sha256_manifest(
    image_path: str | Path,
    manifest_path: str | Path,
    *,
    actual_digest: str | None = None,
) -> ProvenanceResult:
    image = Path(image_path)
    manifest = Path(manifest_path)
    if not image.is_file():
        raise FileNotFoundError(image)

    entries = read_sha256_manifest(manifest)
    candidates = _candidate_entries(image, entries)
    actual = (actual_digest or sha256_file(image)).lower()
    if not SHA256_RE.fullmatch(actual):
        raise ValueError("Actual image digest is not a valid SHA-256 value.")

    if not candidates:
        return ProvenanceResult(
            status="not_listed",
            manifest=str(manifest),
            image=str(image),
            actual_digest=actual,
            message="The selected image filename is not listed in this checksum manifest.",
        )

    expected_values = {entry.digest for entry in candidates}
    if len(expected_values) != 1:
        return ProvenanceResult(
            status="ambiguous",
            manifest=str(manifest),
            image=str(image),
            actual_digest=actual,
            message="The checksum manifest contains conflicting SHA-256 values for this image filename.",
        )

    expected = next(iter(expected_values))
    matched_names = sorted({entry.filename or "<single bare digest>" for entry in candidates})
    matched = ", ".join(matched_names)
    if actual == expected:
        return ProvenanceResult(
            status="verified",
            manifest=str(manifest),
            image=str(image),
            actual_digest=actual,
            expected_digest=expected,
            matched_filename=matched,
            message=(
                "Image SHA-256 matches the selected manifest. "
                "Manifest authenticity has not been independently verified."
            ),
        )

    return ProvenanceResult(
        status="mismatch",
        manifest=str(manifest),
        image=str(image),
        actual_digest=actual,
        expected_digest=expected,
        matched_filename=matched,
        message="Image SHA-256 does not match the selected checksum manifest.",
    )
