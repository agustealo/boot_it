from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.package_artifact import load_signing_report


def _write_report(path: Path, digest: str, *, signed: bool = True) -> None:
    payload = {
        "signed": signed,
        "signature_status": "verified" if signed else "unsigned",
        "binary_sha256": digest,
        "signer_thumbprint": "A" * 40 if signed else None,
        "signer_subject": "CN=Boot It" if signed else None,
        "timestamped": signed,
        "timestamp_subject": "CN=Timestamp" if signed else None,
        "timestamp_thumbprint": "B" * 40 if signed else None,
        "digest_algorithm": "SHA256" if signed else None,
        "timestamp_digest_algorithm": "SHA256" if signed else None,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_signing_report_accepts_exact_binary_digest(tmp_path: Path) -> None:
    digest = "ab" * 32
    report = tmp_path / "signing-report.json"
    _write_report(report, digest)
    payload = load_signing_report(report, digest)
    assert payload["binary_sha256"] == digest
    assert payload["signed"] is True


def test_signing_report_rejects_stale_binary_digest(tmp_path: Path) -> None:
    report = tmp_path / "signing-report.json"
    _write_report(report, "ab" * 32)
    with pytest.raises(ValueError, match="exact executable"):
        load_signing_report(report, "cd" * 32)


def test_signing_report_rejects_missing_or_short_binary_digest(tmp_path: Path) -> None:
    report = tmp_path / "signing-report.json"
    _write_report(report, "deadbeef")
    with pytest.raises(ValueError, match="64-hex"):
        load_signing_report(report, "ab" * 32)


def test_unsigned_default_is_bound_to_packaged_binary() -> None:
    digest = "12" * 32
    payload = load_signing_report(None, digest)
    assert payload["signed"] is False
    assert payload["binary_sha256"] == digest
