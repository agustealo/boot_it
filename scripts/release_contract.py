from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boot_it_meta import __version__

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")


@dataclass(frozen=True)
class ReleaseContract:
    version: str
    tag: str
    source_sha: str
    source_ref: str
    prerelease: bool


def validate_release_contract(
    requested_version: str,
    source_ref: str,
    source_sha: str,
    *,
    current_version: str = __version__,
    prerelease: bool = True,
) -> ReleaseContract:
    requested = requested_version.strip()
    if not SEMVER_RE.fullmatch(requested):
        raise ValueError("Release version must be a valid semantic version without a leading 'v'.")
    if requested != current_version:
        raise ValueError(
            f"Requested release version {requested!r} does not match source version {current_version!r}."
        )
    if source_ref != "refs/heads/main":
        raise ValueError(f"Releases must be dispatched from refs/heads/main, not {source_ref!r}.")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise ValueError("Source SHA must be a full 40-character Git commit SHA.")
    return ReleaseContract(
        version=requested,
        tag=f"v{requested}",
        source_sha=source_sha.lower(),
        source_ref=source_ref,
        prerelease=prerelease,
    )


def write_contract(contract: ReleaseContract, path: Path) -> None:
    payload = {
        "version": contract.version,
        "tag": contract.tag,
        "source_sha": contract.source_sha,
        "source_ref": contract.source_ref,
        "prerelease": contract.prerelease,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Boot It release provenance inputs.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--source-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--final", action="store_true", help="Mark the release as non-prerelease.")
    args = parser.parse_args()

    contract = validate_release_contract(
        args.version,
        args.source_ref,
        args.source_sha,
        prerelease=not args.final,
    )
    if args.output:
        write_contract(contract, args.output)
    print(contract.tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
