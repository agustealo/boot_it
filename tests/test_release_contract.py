from __future__ import annotations

import json
from pathlib import Path

import pytest

from boot_it_meta import __version__
from scripts.release_contract import validate_release_contract, write_contract

SHA = "a" * 40


def test_release_contract_accepts_main_and_exact_version() -> None:
    contract = validate_release_contract(__version__, "refs/heads/main", SHA)
    assert contract.version == __version__
    assert contract.tag == f"v{__version__}"
    assert contract.source_sha == SHA
    assert contract.prerelease is True


def test_release_contract_can_mark_final_release() -> None:
    contract = validate_release_contract(
        __version__, "refs/heads/main", SHA, prerelease=False
    )
    assert contract.prerelease is False


def test_release_contract_rejects_version_drift() -> None:
    with pytest.raises(ValueError, match="does not match source version"):
        validate_release_contract("9.9.9", "refs/heads/main", SHA)


def test_release_contract_rejects_leading_v_and_bad_semver() -> None:
    with pytest.raises(ValueError, match="semantic version"):
        validate_release_contract(f"v{__version__}", "refs/heads/main", SHA)


def test_release_contract_rejects_non_main_dispatch() -> None:
    with pytest.raises(ValueError, match="refs/heads/main"):
        validate_release_contract(__version__, "refs/heads/release-test", SHA)


def test_release_contract_requires_full_commit_sha() -> None:
    with pytest.raises(ValueError, match="40-character"):
        validate_release_contract(__version__, "refs/heads/main", "abc123")


def test_release_contract_json_is_machine_readable(tmp_path: Path) -> None:
    destination = tmp_path / "release-contract.json"
    contract = validate_release_contract(__version__, "refs/heads/main", SHA)
    write_contract(contract, destination)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["tag"] == f"v{__version__}"
    assert payload["source_ref"] == "refs/heads/main"
    assert payload["source_sha"] == SHA
