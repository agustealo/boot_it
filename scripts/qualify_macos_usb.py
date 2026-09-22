from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boot_it_macos import (
    discover_macos_drives,
    macos_eject,
    macos_unmount,
    macos_verify_stream,
    macos_write_stream,
)
from boot_it_models import DriveInfo, OperationCancelled

QUALIFICATION_IMAGE_BYTES = 128 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024


def _drive_payload(drive: DriveInfo) -> dict[str, object]:
    return {
        "device": drive.device,
        "model": drive.model,
        "size": drive.size,
        "size_gib": round(drive.size_gib, 3),
        "bus": drive.bus,
        "external": drive.external,
        "removable": drive.removable,
        "virtual": drive.virtual,
        "writable": drive.writable,
        "safe": drive.safe,
        "reason": drive.reason,
        "hardware_id": drive.hardware_id,
        "identity": list(drive.identity),
    }


def _discover_exact(device: str) -> DriveInfo:
    candidates = discover_macos_drives()
    matches = [drive for drive in candidates if drive.device == device]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one current macOS target for {device!r}; found {len(matches)}."
        )
    drive = matches[0]
    if not drive.safe:
        raise RuntimeError(f"Target {device} is blocked: {drive.reason or 'safety policy'}.")
    if not drive.external or drive.virtual or not drive.writable:
        raise RuntimeError("Target failed the external physical writable-device qualification contract.")
    return drive


def _revalidate(expected: DriveInfo) -> DriveInfo:
    current = _discover_exact(expected.device)
    if current.identity != expected.identity:
        raise RuntimeError(
            "Target identity changed after confirmation. No qualification write will be attempted."
        )
    return current


def _build_pattern_image(path: Path, size: int) -> str:
    """Create a deterministic non-secret qualification payload and return SHA-256."""
    digest = hashlib.sha256()
    remaining = size
    counter = 0
    with path.open("wb") as handle:
        while remaining:
            seed = hashlib.sha256(f"boot-it-macos-qualification:{counter}".encode("utf-8")).digest()
            chunk = (seed * ((min(CHUNK_SIZE, remaining) + len(seed) - 1) // len(seed)))[
                : min(CHUNK_SIZE, remaining)
            ]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
            counter += 1
        handle.flush()
        os.fsync(handle.fileno())
    return digest.hexdigest()


def _progress(label: str):
    last = -1

    def report(done: int, total: int) -> None:
        nonlocal last
        percent = 100 if total <= 0 else min(100, int(done * 100 / total))
        if percent == last and done != total:
            return
        last = percent
        print(f"{label}: {done}/{total} bytes ({percent}%)", flush=True)

    return report


def _perform_cancel_probe(drive: DriveInfo, image: Path, cancel_after_bytes: int) -> None:
    cancel_event = threading.Event()
    observed = 0

    def report(done: int, total: int) -> None:
        nonlocal observed
        observed = done
        _progress("cancel-probe write")(done, total)
        if done >= cancel_after_bytes:
            cancel_event.set()

    with image.open("rb") as source:
        try:
            macos_write_stream(source, image.stat().st_size, drive.device, report, cancel_event)
        except OperationCancelled:
            if observed < cancel_after_bytes:
                raise RuntimeError(
                    f"Cancellation fired before requested threshold: {observed} < {cancel_after_bytes}."
                )
            print("Cancellation probe: PASS (writer reported OperationCancelled).", flush=True)
            return
    raise RuntimeError("Cancellation probe failed: write completed without honoring cancellation.")


def _perform_complete_probe(drive: DriveInfo, image: Path) -> None:
    size = image.stat().st_size
    cancel_event = threading.Event()
    with image.open("rb") as source:
        macos_write_stream(source, size, drive.device, _progress("write"), cancel_event)
    with image.open("rb") as source:
        macos_verify_stream(source, size, drive.device, _progress("verify"), cancel_event)


def qualify(device: str, confirmation: str, *, skip_cancel_probe: bool) -> dict[str, object]:
    if platform.system() != "Darwin":
        raise RuntimeError("macOS physical qualification must run on macOS.")
    expected = _discover_exact(device)
    if confirmation != expected.device:
        raise RuntimeError(
            "Destructive qualification requires --confirm-device to exactly equal the selected device path."
        )
    if expected.size < QUALIFICATION_IMAGE_BYTES:
        raise RuntimeError("Target is too small for the physical qualification payload.")

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="boot-it-qualify-") as temp_dir:
        image = Path(temp_dir) / "boot-it-qualification.img"
        image_digest = _build_pattern_image(image, QUALIFICATION_IMAGE_BYTES)
        current = _revalidate(expected)
        print(json.dumps({"qualified_target": _drive_payload(current)}, indent=2), flush=True)
        print(
            "DESTRUCTIVE QUALIFICATION: the selected target will now be unmounted and overwritten.",
            flush=True,
        )
        macos_unmount(current.device)

        if not skip_cancel_probe:
            _perform_cancel_probe(current, image, 16 * 1024 * 1024)
            current = _revalidate(expected)
            macos_unmount(current.device)

        _perform_complete_probe(current, image)
        macos_eject(current.device)

    elapsed = time.time() - started
    return {
        "status": "pass",
        "platform": platform.platform(),
        "device": expected.device,
        "identity": list(expected.identity),
        "hardware_id": expected.hardware_id,
        "qualification_image_size": QUALIFICATION_IMAGE_BYTES,
        "qualification_image_sha256": image_digest,
        "cancel_probe": "skipped" if skip_cancel_probe else "passed",
        "write_probe": "passed",
        "byte_verification": "passed",
        "eject": "passed",
        "elapsed_seconds": round(elapsed, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify Boot It's real macOS external-disk backend. Inventory mode is non-destructive. "
            "--destructive writes a deterministic 128 MiB payload and ERASES the beginning of the target disk."
        )
    )
    parser.add_argument("--device", help="Exact /dev/diskN target from inventory.")
    parser.add_argument(
        "--destructive",
        action="store_true",
        help="Run cancellation, raw-write, byte-verification, and eject probes. DESTROYS target data.",
    )
    parser.add_argument(
        "--confirm-device",
        help="Required with --destructive and must exactly match --device, for example /dev/disk4.",
    )
    parser.add_argument(
        "--skip-cancel-probe",
        action="store_true",
        help="Skip the intentional partial-write cancellation probe but still perform full write/verify/eject.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Write the qualification result JSON to this path after a successful destructive run.",
    )
    args = parser.parse_args()

    if platform.system() != "Darwin":
        parser.error("This qualification harness is macOS-only.")

    if not args.destructive:
        inventory = [_drive_payload(drive) for drive in discover_macos_drives()]
        print(json.dumps({"platform": platform.platform(), "targets": inventory}, indent=2))
        return 0

    if not args.device:
        parser.error("--destructive requires --device /dev/diskN.")
    if not args.confirm_device:
        parser.error("--destructive requires --confirm-device /dev/diskN.")

    result = qualify(
        args.device,
        args.confirm_device,
        skip_cancel_probe=args.skip_cancel_probe,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
