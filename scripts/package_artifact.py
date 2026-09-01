from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from boot_it_meta import __version__


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_platform_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower().replace("amd64", "x86_64")
    return f"{system}-{machine}"


def smoke_binary(binary: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="boot-it-smoke-") as temp_dir:
        result_path = Path(temp_dir) / "self-test.json"
        subprocess.run(
            [str(binary.resolve()), "--self-test", str(result_path)],
            check=True,
            timeout=30,
        )
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    if payload.get("self_test") != "ok":
        raise RuntimeError("Packaged self-test did not report success.")
    if payload.get("version") != __version__:
        raise RuntimeError(
            f"Packaged version mismatch: expected {__version__}, got {payload.get('version')!r}."
        )
    if payload.get("frozen") is not True:
        raise RuntimeError("Self-test did not execute from a frozen application.")
    return payload


def package(binary: Path, output_dir: Path) -> tuple[Path, Path, Path]:
    if not binary.is_file():
        raise FileNotFoundError(binary)
    payload = smoke_binary(binary)
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = binary.suffix
    artifact_name = f"Boot-It-{__version__}-{normalized_platform_name()}{suffix}"
    artifact = output_dir / artifact_name
    shutil.copy2(binary, artifact)
    digest = sha256_file(artifact)

    checksum = output_dir / f"{artifact_name}.sha256"
    checksum.write_text(f"{digest}  {artifact_name}\n", encoding="utf-8")

    manifest = output_dir / f"{artifact_name}.json"
    manifest_payload = {
        "artifact": artifact_name,
        "sha256": digest,
        "size": artifact.stat().st_size,
        "version": __version__,
        "build_platform": normalized_platform_name(),
        "self_test": payload,
        "signed": False,
        "signature_status": "unsigned release candidate",
    }
    manifest.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact, checksum, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test and package a Boot It binary.")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    artifact, checksum, manifest = package(args.binary, args.output_dir)
    print(artifact)
    print(checksum)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
