from __future__ import annotations

import pytest

from scripts.release_publication import validate_published_release


SOURCE_SHA = "a" * 40


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "tagName": "v0.2.0",
        "targetCommitish": SOURCE_SHA,
        "isPrerelease": True,
    }
    payload.update(overrides)
    return payload


def test_published_release_metadata_accepts_exact_contract() -> None:
    validate_published_release(
        _payload(),
        expected_tag="v0.2.0",
        expected_source_sha=SOURCE_SHA,
        expected_prerelease=True,
    )


def test_published_release_metadata_rejects_wrong_tag() -> None:
    with pytest.raises(ValueError, match="tag mismatch"):
        validate_published_release(
            _payload(tagName="v9.9.9"),
            expected_tag="v0.2.0",
            expected_source_sha=SOURCE_SHA,
            expected_prerelease=True,
        )


def test_published_release_metadata_rejects_wrong_source_sha() -> None:
    with pytest.raises(ValueError, match="source mismatch"):
        validate_published_release(
            _payload(targetCommitish="b" * 40),
            expected_tag="v0.2.0",
            expected_source_sha=SOURCE_SHA,
            expected_prerelease=True,
        )


def test_published_release_metadata_rejects_wrong_release_state() -> None:
    with pytest.raises(ValueError, match="prerelease state mismatch"):
        validate_published_release(
            _payload(isPrerelease=False),
            expected_tag="v0.2.0",
            expected_source_sha=SOURCE_SHA,
            expected_prerelease=True,
        )


def test_published_release_metadata_requires_full_expected_sha() -> None:
    with pytest.raises(ValueError, match="full 40-character"):
        validate_published_release(
            _payload(),
            expected_tag="v0.2.0",
            expected_source_sha="deadbeef",
            expected_prerelease=True,
        )
