from __future__ import annotations

import os
import re
import subprocess
import time
import threading
from pathlib import Path
from types import ModuleType
from typing import Callable


def _fixed_linux_write(
    core: ModuleType,
    image: str,
    device: str,
    progress_callback: Callable[[int, int], None],
    cancel_event: threading.Event,
) -> None:
    """Run dd with a binary nonblocking stderr reader safe on Python 3.10+.

    TextIOWrapper cannot safely sit on a nonblocking descriptor because the
    incremental decoder may receive ``None`` when no bytes are available.
    Reading bytes with ``os.read`` keeps EAGAIN separate from decoding and lets
    cancellation polling continue without corrupting decoder state.
    """
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


def install_runtime_patches(core: ModuleType) -> None:
    """Install narrowly-scoped runtime fixes before the GUI starts."""

    def linux_write(
        image: str,
        device: str,
        progress_callback: Callable[[int, int], None],
        cancel_event: threading.Event,
    ) -> None:
        _fixed_linux_write(core, image, device, progress_callback, cancel_event)

    core.linux_write = linux_write
