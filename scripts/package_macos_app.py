from __future__ import annotations

import argparse
import json
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boot_it_meta import __version__
from scripts.package_artifact import build_provenance, normalized_platform_name, sha256_file, smoke_binary

EXPECTED_BUNDLE_IDENTIFIER = "com.agustealo.bootit"


def _bundle_executable(app: Path) -> Path:
    plist_path = app / "Contents" / "Info.plist"
    if not plist_path.is_file():
        raise FileNotFoundError(f"macOS bundle is missing Info.plist: {plist_path}")
    payload = plistlib.loads(plist_path.read_bytes())
    if not isinstance(payload, dict):
        raise RuntimeError("macOS Info.plist did not contain a dictionary.")
    identifier = str(payload.get("CFBundleIdentifier") or "")
    if identifier != EXPECTED_BUNDLE_IDENTIFIER:
        raise RuntimeError(
            f"Unexpected bundle identifier {identifier!r}; expected {EXPECTED_BUNDLE_IDENTIFIER!r}."
        )
    executable_name = str(payload.get("CFBundleExecutable") or "Boot-It")
    executable = app / "Contents" / "MacOS" / executable_name
    if not executable.is_file():
        raise FileNotFoundError(f"macOS bundle executable is missing: {executable}")
    return executable


def _verify_bundle_signature(app: Path) -> None:
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _architectures(executable: Path) -> list[str]:
    result = subprocess.run(
        ["/usr/bin/lipo", "-archs", str(executable)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    values = [value.strip() for value in result.stdout.split() if value.strip()]
    if not values:
        raise RuntimeError("Unable to determine architecture of packaged macOS executable.")
    return values


def _archive_app(app: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()
    subprocess.run(
        [
            "/usr/bin/ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app),
            str(archive),
        ],
        check=True,
    )


def package_macos_app(app: Path, output_dir: Path) -> tuple[Path, Path, Path]:
    if platform.system() != "Darwin":
        raise RuntimeError("macOS application packaging must run on macOS.")
    if not app.is_dir() or app.suffix != ".app":
        raise FileNotFoundError(f"Expected a macOS .app bundle: {app}")

    executable = _bundle_executable(app)
    self_test = smoke_binary(executable)
    _verify_bundle_signature(app)
    architectures = _architectures(executable)

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = f"Boot-It-{__version__}-{normalized_platform_name()}.app.zip"
    artifact = output_dir / artifact_name
    _archive_app(app, artifact)

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
        "architectures": architectures,
        "self_test": self_test,
        "bundle_identifier": EXPECTED_BUNDLE_IDENTIFIER,
        "bundle_signature": "ad-hoc qualification signature",
        "distribution_signed": False,
        "notarized": False,
        "release_eligible": False,
        **build_provenance(),
    }
    manifest.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact, checksum, manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke-test and package a macOS Boot It .app qualification bundle."
    )
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    artifact, checksum, manifest = package_macos_app(args.app, args.output_dir)
    print(artifact)
    print(checksum)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
