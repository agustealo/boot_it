from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def validate_published_release(
    payload: dict[str, object],
    *,
    expected_tag: str,
    expected_source_sha: str,
    expected_prerelease: bool,
) -> None:
    if not SHA_RE.fullmatch(expected_source_sha):
        raise ValueError("Expected source SHA must be a full 40-character Git commit SHA.")

    tag = payload.get("tagName")
    target = payload.get("targetCommitish")
    prerelease = payload.get("isPrerelease")

    if tag != expected_tag:
        raise ValueError(
            f"Published release tag mismatch: expected {expected_tag!r}, got {tag!r}."
        )
    if not isinstance(target, str) or target.lower() != expected_source_sha.lower():
        raise ValueError(
            "Published release source mismatch: "
            f"expected {expected_source_sha.lower()!r}, got {target!r}."
        )
    if prerelease is not expected_prerelease:
        raise ValueError(
            "Published release prerelease state mismatch: "
            f"expected {expected_prerelease!r}, got {prerelease!r}."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify GitHub's published release metadata against the approved release contract."
    )
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--prerelease", choices=("true", "false"), required=True)
    args = parser.parse_args()

    payload = json.loads(args.metadata.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Published release metadata must contain a JSON object.")
    validate_published_release(
        payload,
        expected_tag=args.tag,
        expected_source_sha=args.source_sha,
        expected_prerelease=args.prerelease == "true",
    )
    print("published release metadata verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
