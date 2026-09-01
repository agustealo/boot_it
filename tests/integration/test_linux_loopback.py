from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

import boot_it as core
from boot_it_runtime import install_runtime_patches

pytestmark = pytest.mark.skipif(
    os.environ.get("BOOT_IT_LOOPBACK_TESTS") != "1",
    reason="destructive loopback tests require BOOT_IT_LOOPBACK_TESTS=1",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture()
def hardened_core():
    original_linux_write = core.linux_write
    original_validate_image = core.validate_image
    original_hash_ready = core.BootItWindow._hash_ready
    install_runtime_patches(core)
    try:
        yield core
    finally:
        core.linux_write = original_linux_write
        core.validate_image = original_validate_image
        core.BootItWindow._hash_ready = original_hash_ready


@pytest.fixture()
def loop_device(tmp_path: Path):
    if os.geteuid() != 0:
        pytest.skip("loopback integration tests must run as root")
    if not shutil.which("losetup"):
        pytest.skip("losetup is unavailable")

    backing = tmp_path / "target.img"
    backing.write_bytes(b"\0" * (96 * 1024 * 1024))

    device = subprocess.check_output(
        ["losetup", "--find", "--show", str(backing)],
        text=True,
    ).strip()
    try:
        yield Path(device), backing
    finally:
        subprocess.run(["losetup", "--detach", device], check=False)


def test_linux_write_and_verify_against_kernel_loop_device(
    tmp_path: Path,
    loop_device,
    hardened_core,
) -> None:
    device, backing = loop_device
    source = tmp_path / "source.img"
    payload = bytearray(40 * 1024 * 1024)
    for offset in range(0, len(payload), 4096):
        payload[offset : offset + 32] = hashlib.sha256(str(offset).encode()).digest()
    source.write_bytes(payload)

    progress: list[tuple[int, int]] = []
    cancel_event = threading.Event()

    hardened_core.linux_write(
        str(source),
        str(device),
        lambda done, total: progress.append((done, total)),
        cancel_event,
    )
    hardened_core.linux_verify(str(source), str(device), cancel_event)

    with backing.open("rb") as handle:
        written = handle.read(source.stat().st_size)
    assert hashlib.sha256(written).hexdigest() == _sha256(source)
    assert progress
    assert progress[-1][0] <= progress[-1][1]


def test_linux_verify_detects_corruption(tmp_path: Path, loop_device, hardened_core) -> None:
    device, backing = loop_device
    source = tmp_path / "source.img"
    source.write_bytes(os.urandom(8 * 1024 * 1024))
    cancel_event = threading.Event()

    hardened_core.linux_write(str(source), str(device), lambda *_: None, cancel_event)

    with backing.open("r+b") as handle:
        handle.seek(1024 * 1024)
        original = handle.read(1)
        handle.seek(1024 * 1024)
        handle.write(bytes([original[0] ^ 0xFF]))
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(subprocess.CalledProcessError):
        hardened_core.linux_verify(str(source), str(device), cancel_event)


def test_linux_write_cancellation_terminates_writer(tmp_path: Path, loop_device, hardened_core) -> None:
    device, _ = loop_device
    source = tmp_path / "source.img"
    source.write_bytes(os.urandom(64 * 1024 * 1024))
    cancel_event = threading.Event()
    outcome: list[BaseException] = []

    def run() -> None:
        try:
            hardened_core.linux_write(str(source), str(device), lambda *_: None, cancel_event)
        except BaseException as exc:  # captured for assertion from worker thread
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    time.sleep(0.05)
    cancel_event.set()
    worker.join(timeout=10)

    assert not worker.is_alive(), "cancelled dd process did not terminate"
    if outcome:
        assert isinstance(outcome[0], hardened_core.OperationCancelled)
