from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boot_it_meta import __version__

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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
        subprocess.run([str(binary.resolve()), "--self-test", str(result_path)], check=True, timeout=30)
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    if payload.get("self_test") != "ok":
        raise RuntimeError("Packaged self-test did not report success.")
    if payload.get("version") != __version__:
        raise RuntimeError(f"Packaged version mismatch: expected {__version__}, got {payload.get('version')!r}.")
    if payload.get("frozen") is not True:
        raise RuntimeError("Self-test did not execute from a frozen application.")
    return payload


def build_provenance() -> dict[str, str | None]:
    return {"source_sha": os.environ.get("GITHUB_SHA") or None,"source_ref": os.environ.get("GITHUB_REF") or None,"workflow_run_id": os.environ.get("GITHUB_RUN_ID") or None,"workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT") or None,"repository": os.environ.get("GITHUB_REPOSITORY") or None}


def load_signing_report(path: Path | None, expected_binary_sha256: str) -> dict[str, object]:
    if path is None:
        return {"signed": False,"signature_status": "unsigned release candidate","binary_sha256": expected_binary_sha256,"signer_thumbprint": None,"signer_subject": None,"timestamped": False,"timestamp_subject": None,"timestamp_thumbprint": None,"digest_algorithm": None,"timestamp_digest_algorithm": None}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("signed"), bool):
        raise ValueError("Signing report must contain boolean 'signed'.")
    report_digest = str(payload.get("binary_sha256") or "").strip()
    if not SHA256_RE.fullmatch(report_digest):
        raise ValueError("Signing report must contain a full 64-hex binary_sha256 digest.")
    if report_digest.casefold() != expected_binary_sha256.casefold():
        raise ValueError("Signing report does not describe the exact executable being packaged.")
    if payload["signed"]:
        required = ("signature_status", "signer_thumbprint", "timestamped", "digest_algorithm", "timestamp_digest_algorithm")
        missing = [name for name in required if not payload.get(name)]
        if missing:
            raise ValueError("Verified signing report is incomplete: " + ", ".join(missing))
        if payload.get("timestamped") is not True:
            raise ValueError("Verified signing report must require a timestamp.")
    return payload


def package(binary: Path, output_dir: Path, signing_report: Path | None = None) -> tuple[Path, Path, Path]:
    if not binary.is_file():
        raise FileNotFoundError(binary)
    payload = smoke_binary(binary)
    source_digest = sha256_file(binary)
    signing = load_signing_report(signing_report, source_digest)
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = binary.suffix
    artifact_name = f"Boot-It-{__version__}-{normalized_platform_name()}{suffix}"
    artifact = output_dir / artifact_name
    shutil.copy2(binary, artifact)
    digest = sha256_file(artifact)
    if digest != source_digest:
        raise RuntimeError("Packaged executable bytes changed while copying into the release bundle.")
    checksum = output_dir / f"{artifact_name}.sha256"
    checksum.write_text(f"{digest}  {artifact_name}\n", encoding="utf-8")
    manifest = output_dir / f"{artifact_name}.json"
    manifest_payload = {"artifact": artifact_name,"sha256": digest,"size": artifact.stat().st_size,"version": __version__,"build_platform": normalized_platform_name(),"self_test": payload,**signing,"github_attestation_expected": bool(os.environ.get("GITHUB_ACTIONS")),**build_provenance()}
    manifest.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact, checksum, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test and package a Boot It binary.")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--signing-report", type=Path)
    args = parser.parse_args()
    artifact, checksum, manifest = package(args.binary, args.output_dir, args.signing_report)
    print(artifact); print(checksum); print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
