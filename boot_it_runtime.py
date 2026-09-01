from __future__ import annotations

import os
import re
import struct
import subprocess
import time
import threading
from pathlib import Path
from types import ModuleType
from typing import Callable

from boot_it_image import inspect_image


def _fixed_linux_write(
    core: ModuleType,
    image: str,
    device: str,
    progress_callback: Callable[[int, int], None],
    cancel_event: threading.Event,
) -> None:
    """Run dd with a binary nonblocking stderr reader safe on Python 3.10+."""
    command = core._dd_command(image, device)
    total = Path(image).stat().st_size
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        start_new_session=True,
    )
    assert process.stderr is not None
    stderr_fd = process.stderr.fileno()
    os.set_blocking(stderr_fd, False)
    buffered = b""

    def consume(chunk: bytes) -> None:
        nonlocal buffered
        if not chunk:
            return
        buffered += chunk
        matches = re.findall(rb"(\d+)\s+bytes", buffered)
        if matches:
            progress_callback(int(matches[-1]), total)
        buffered = buffered[-512:]

    try:
        while process.poll() is None:
            if cancel_event.is_set():
                core._terminate_process_group(process)
                raise core.OperationCancelled(
                    "Write cancelled. The USB contains a partial image and must be rewritten before use."
                )
            try:
                consume(os.read(stderr_fd, 65536))
            except BlockingIOError:
                pass
            time.sleep(0.05)

        while True:
            try:
                chunk = os.read(stderr_fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            consume(chunk)

        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
    finally:
        if process.poll() is None:
            core._terminate_process_group(process)


def _install_image_intelligence(core: ModuleType) -> None:
    if not hasattr(core, "_boot_it_original_validate_image"):
        core._boot_it_original_validate_image = core.validate_image
    original_validate = core._boot_it_original_validate_image

    def validate_image(path: str) -> tuple[bool, str]:
        valid, reason = original_validate(path)
        if not valid:
            return valid, reason
        try:
            inspection = inspect_image(path)
        except (OSError, ValueError, struct.error) as exc:
            return False, f"Unable to inspect image structure: {exc}"
        if inspection.fatal_reason:
            return False, f"Image structure check failed: {inspection.fatal_reason}"
        return True, ""

    core.validate_image = validate_image

    window_type = getattr(core, "BootItWindow", None)
    if window_type is None:
        return
    if not hasattr(window_type, "_boot_it_original_hash_ready"):
        window_type._boot_it_original_hash_ready = window_type._hash_ready
    original_hash_ready = window_type._boot_it_original_hash_ready

    def hash_ready(self, path: str, digest: str) -> None:
        original_hash_ready(self, path, digest)
        if path != self.image_edit.text():
            return
        try:
            inspection = inspect_image(path)
        except (OSError, ValueError, struct.error):
            return
        digest_text = digest or "unavailable"
        self.hash_label.setText(f"SHA-256: {digest_text}\nImage: {inspection.summary}")
        self.hash_label.setToolTip(inspection.warning)

    window_type._hash_ready = hash_ready


def install_runtime_patches(core: ModuleType) -> None:
    """Install mandatory runtime hardening before the GUI starts."""

    def linux_write(
        image: str,
        device: str,
        progress_callback: Callable[[int, int], None],
        cancel_event: threading.Event,
    ) -> None:
        _fixed_linux_write(core, image, device, progress_callback, cancel_event)

    core.linux_write = linux_write
    _install_image_intelligence(core)
