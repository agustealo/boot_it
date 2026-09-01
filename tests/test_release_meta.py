from __future__ import annotations

import json
from pathlib import Path

from boot_it_meta import __version__, diagnostics, write_self_test


def test_version_is_semver_triplet() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_diagnostics_has_release_identity() -> None:
    payload = diagnostics()
    assert payload["app"] == "Boot It"
    assert payload["version"] == __version__
    assert payload["platform"]
    assert payload["python"]
    assert isinstance(payload["commands"], dict)


def test_write_self_test_is_atomic_machine_readable_json(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "self-test.json"
    write_self_test(str(destination))
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["self_test"] == "ok"
    assert payload["version"] == __version__
    assert not destination.with_suffix(".json.tmp").exists()
