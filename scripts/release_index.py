from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
INDEX_NAME = "release-index.json"
INDEX_CHECKSUM_NAME = f"{INDEX_NAME}.sha256"
SUPPORTED_PLATFORMS = frozenset({"linux-x86_64", "windows-x86_64"})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return payload


def _validate_contract(contract: dict[str, object], version: str, tag: str, source_sha: str) -> None:
    expected = {
        "version": version,
        "tag": tag,
        "source_sha": source_sha.lower(),
        "source_ref": "refs/heads/main",
    }
    for key, value in expected.items():
        actual = contract.get(key)
        if actual != value:
            raise ValueError(
                f"Release contract {key!r} mismatch: expected {value!r}, got {actual!r}."
            )


def _parse_checksum(path: Path) -> tuple[str, str]:
    line = path.read_text(encoding="utf-8").strip()
    parts = line.split(None, 1)
    if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
        raise ValueError(f"Malformed checksum file: {path.name}")
    filename = parts[1].lstrip("*").strip()
    if not filename or Path(filename).name != filename:
        raise ValueError(f"Checksum file {path.name} must reference one local filename.")
    return parts[0].lower(), filename


def _validate_platform_manifests(
    manifests: list[Path],
    by_name: dict[str, Path],
    *,
    version: str,
    source_sha: str,
) -> None:
    seen_platforms: set[str] = set()
    for manifest_path in manifests:
        manifest = _load_json(manifest_path)
        artifact = manifest.get("artifact")
        if not isinstance(artifact, str) or not artifact or Path(artifact).name != artifact:
            raise ValueError(f"Platform manifest {manifest_path.name} has an invalid artifact filename.")
        if manifest_path.name != f"{artifact}.json":
            raise ValueError(
                f"Platform manifest {manifest_path.name} does not match artifact {artifact!r}."
            )

        platform_name = manifest.get("build_platform")
        if platform_name not in SUPPORTED_PLATFORMS:
            raise ValueError(
                f"Platform manifest {manifest_path.name} has unsupported build_platform {platform_name!r}."
            )
        assert isinstance(platform_name, str)
        if platform_name in seen_platforms:
            raise ValueError(f"Duplicate release platform manifest for {platform_name!r}.")
        seen_platforms.add(platform_name)

        if manifest.get("version") != version:
            raise ValueError(f"Platform manifest {manifest_path.name} version mismatch.")
        manifest_source_sha = str(manifest.get("source_sha") or "").lower()
        if manifest_source_sha != source_sha.lower():
            raise ValueError(f"Platform manifest {manifest_path.name} source SHA mismatch.")
        if manifest.get("source_ref") != "refs/heads/main":
            raise ValueError(f"Platform manifest {manifest_path.name} source ref mismatch.")
        if manifest.get("github_attestation_expected") is not True:
            raise ValueError(
                f"Platform manifest {manifest_path.name} must require GitHub attestation for a release candidate."
            )

        target = by_name.get(artifact)
        if target is None or not target.is_file():
            raise ValueError(f"Platform manifest {manifest_path.name} references missing artifact {artifact!r}.")
        digest = manifest.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"Platform manifest {manifest_path.name} has invalid artifact SHA-256.")
        actual_digest = sha256_file(target)
        if digest.lower() != actual_digest:
            raise ValueError(f"Platform manifest {manifest_path.name} artifact checksum mismatch.")
        size = manifest.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"Platform manifest {manifest_path.name} has invalid artifact size.")
        if size != target.stat().st_size:
            raise ValueError(f"Platform manifest {manifest_path.name} artifact size mismatch.")

        checksum_name = f"{artifact}.sha256"
        if checksum_name not in by_name:
            raise ValueError(f"Platform manifest {manifest_path.name} is missing checksum {checksum_name!r}.")
        sbom_name = f"{artifact}.spdx.json"
        if sbom_name not in by_name:
            raise ValueError(f"Platform manifest {manifest_path.name} is missing SBOM {sbom_name!r}.")

    missing_platforms = sorted(SUPPORTED_PLATFORMS - seen_platforms)
    extra_platforms = sorted(seen_platforms - SUPPORTED_PLATFORMS)
    if missing_platforms or extra_platforms:
        details: list[str] = []
        if missing_platforms:
            details.append("missing " + ", ".join(missing_platforms))
        if extra_platforms:
            details.append("unexpected " + ", ".join(extra_platforms))
        raise ValueError("Release platform manifest set mismatch: " + "; ".join(details))


def build_release_index(
    bundle_dir: Path,
    *,
    version: str,
    tag: str,
    source_sha: str,
) -> dict[str, object]:
    if not bundle_dir.is_dir():
        raise FileNotFoundError(bundle_dir)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise ValueError("Source SHA must be a full 40-character Git commit SHA.")

    contract_path = bundle_dir / "release-contract.json"
    if not contract_path.is_file():
        raise ValueError("release-contract.json is missing from the release bundle.")
    contract = _load_json(contract_path)
    _validate_contract(contract, version, tag, source_sha)

    files = sorted(
        path
        for path in bundle_dir.iterdir()
        if path.is_file() and path.name not in {INDEX_NAME, INDEX_CHECKSUM_NAME}
    )
    names = [path.name for path in files]
    if len(names) != len(set(names)):
        raise ValueError("Release bundle contains duplicate filenames.")

    manifests = [
        path
        for path in files
        if path.name.startswith("Boot-It-")
        and path.suffix == ".json"
        and not path.name.endswith(".spdx.json")
    ]
    sboms = [path for path in files if path.name.endswith(".spdx.json")]
    checksums = [path for path in files if path.name.endswith(".sha256")]
    if len(manifests) != len(SUPPORTED_PLATFORMS):
        raise ValueError("Release bundle must contain exactly one manifest for each supported package lane.")
    if len(sboms) != len(SUPPORTED_PLATFORMS):
        raise ValueError("Release bundle must contain exactly one SPDX SBOM for each supported package lane.")
    if len(checksums) != len(SUPPORTED_PLATFORMS):
        raise ValueError("Release bundle must contain exactly one checksum sidecar for each supported package lane.")

    by_name = {path.name: path for path in files}
    for checksum_path in checksums:
        expected_digest, filename = _parse_checksum(checksum_path)
        target = by_name.get(filename)
        if target is None:
            raise ValueError(f"Checksum {checksum_path.name} references missing file {filename!r}.")
        actual_digest = sha256_file(target)
        if actual_digest != expected_digest:
            raise ValueError(f"Checksum mismatch for {filename!r} while building release index.")

    _validate_platform_manifests(
        manifests,
        by_name,
        version=version,
        source_sha=source_sha,
    )

    entries = [
        {
            "name": path.name,
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in files
    ]
    return {
        "schema": "boot-it-release-index-v1",
        "version": version,
        "tag": tag,
        "source_sha": source_sha.lower(),
        "source_ref": "refs/heads/main",
        "prerelease": bool(contract.get("prerelease")),
        "platforms": sorted(SUPPORTED_PLATFORMS),
        "files": entries,
        "verification": {
            "checksums": "Verify SHA256SUMS and individual .sha256 sidecars before execution.",
            "release_index": f"Verify {INDEX_CHECKSUM_NAME}, then require every published payload file to match this index exactly.",
            "manifests": "Require one supported-platform manifest per executable and cross-check its source identity, size, digest, SBOM, checksum sidecar, and attestation expectation.",
            "attestations": "Verify GitHub artifact attestations for each executable and its SPDX SBOM.",
            "windows_authenticode": "When signed, verify the Windows executable Authenticode signature and timestamp independently.",
        },
    }


def write_release_index(payload: dict[str, object], output: Path) -> None:
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_index_checksum(index_path: Path, checksum_path: Path) -> None:
    checksum_path.write_text(
        f"{sha256_file(index_path)}  {index_path.name}\n",
        encoding="utf-8",
    )


def verify_release_payload(bundle_dir: Path, *, index_name: str = INDEX_NAME) -> None:
    index_path = bundle_dir / index_name
    checksum_path = bundle_dir / f"{index_name}.sha256"
    if not index_path.is_file():
        raise ValueError(f"{index_name} is missing from the release payload.")
    if not checksum_path.is_file():
        raise ValueError(f"{checksum_path.name} is missing from the release payload.")

    expected_index_digest, referenced_name = _parse_checksum(checksum_path)
    if referenced_name != index_path.name:
        raise ValueError(f"{checksum_path.name} must reference {index_path.name!r}.")
    actual_index_digest = sha256_file(index_path)
    if actual_index_digest != expected_index_digest:
        raise ValueError("Release index checksum mismatch.")

    index = _load_json(index_path)
    if index.get("schema") != "boot-it-release-index-v1":
        raise ValueError("Unsupported release index schema.")
    if index.get("platforms") != sorted(SUPPORTED_PLATFORMS):
        raise ValueError("Release index supported platform set mismatch.")
    entries = index.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Release index must contain a non-empty files list.")

    expected_names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Release index file entry must be a JSON object.")
        name = entry.get("name")
        digest = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise ValueError("Release index contains an invalid local filename.")
        if name in {index_path.name, checksum_path.name}:
            raise ValueError("Release index must not recursively include itself or its detached checksum.")
        if name in expected_names:
            raise ValueError(f"Release index contains duplicate filename {name!r}.")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"Release index has invalid SHA-256 for {name!r}.")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"Release index has invalid size for {name!r}.")

        target = bundle_dir / name
        if not target.is_file():
            raise ValueError(f"Release index references missing file {name!r}.")
        if target.stat().st_size != size:
            raise ValueError(f"Release index size mismatch for {name!r}.")
        if sha256_file(target) != digest.lower():
            raise ValueError(f"Release index checksum mismatch for {name!r}.")
        expected_names.add(name)

    actual_names = {path.name for path in bundle_dir.iterdir() if path.is_file()}
    required_names = expected_names | {index_path.name, checksum_path.name}
    missing = sorted(required_names - actual_names)
    extra = sorted(actual_names - required_names)
    if missing:
        raise ValueError("Release payload is missing indexed files: " + ", ".join(missing))
    if extra:
        raise ValueError("Release payload contains unindexed extra files: " + ", ".join(extra))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or verify the machine-readable Boot It release index.")
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--version")
    parser.add_argument("--tag")
    parser.add_argument("--source-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    if args.verify:
        verify_release_payload(args.bundle_dir)
        print("release payload verified")
        return 0

    if not all((args.version, args.tag, args.source_sha, args.output)):
        parser.error("--version, --tag, --source-sha, and --output are required when building an index")
    payload = build_release_index(
        args.bundle_dir,
        version=args.version,
        tag=args.tag,
        source_sha=args.source_sha,
    )
    write_release_index(payload, args.output)
    write_index_checksum(args.output, args.bundle_dir / INDEX_CHECKSUM_NAME)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
