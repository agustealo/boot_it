from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from types import ModuleType

from boot_it_source import SourceIdentity, SourceSnapshot, snapshot_verified_source


def _identity(path: str) -> SourceIdentity:
    stat = Path(path).stat()
    return SourceIdentity(
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        device=getattr(stat, "st_dev", None),
        inode=getattr(stat, "st_ino", None),
    )


def _linux_target_command(core: ModuleType, device: str) -> list[str]:
    command = ["dd", f"of={device}", "bs=4M", "status=progress", "conv=fsync"]
    if os.geteuid() != 0:
        if not shutil.which("pkexec"):
            raise RuntimeError("pkexec is required to write raw devices without running Boot It as root.")
        command.insert(0, "pkexec")
    return command


def _linux_verify_command(core: ModuleType, device: str, size: int) -> list[str]:
    command = ["cmp", "-n", str(size), "-", device]
    if os.geteuid() != 0:
        if not shutil.which("pkexec"):
            raise RuntimeError("pkexec is required for post-write verification.")
        command.insert(0, "pkexec")
    return command


def _stream_to_process(
    core: ModuleType,
    snapshot: SourceSnapshot,
    command: list[str],
    progress_callback,
    cancel_event: threading.Event,
    *,
    parse_dd_progress: bool,
) -> None:
    snapshot.rewind()
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        start_new_session=True,
    )
    assert process.stdin is not None
    assert process.stderr is not None
    stderr_fd = process.stderr.fileno()
    os.set_blocking(stderr_fd, False)
    buffered = b""
    sent = 0

    try:
        while True:
            if cancel_event.is_set():
                core._terminate_process_group(process)
                raise core.OperationCancelled(
                    "Operation cancelled. The target contains a partial image and must be rewritten before use."
                )
            chunk = snapshot.handle.read(core.CHUNK_SIZE)
            if not chunk:
                break
            try:
                process.stdin.write(chunk)
                process.stdin.flush()
            except BrokenPipeError:
                break
            sent += len(chunk)
            if not parse_dd_progress:
                progress_callback(sent, snapshot.size)
            try:
                stderr_chunk = os.read(stderr_fd, 65536)
            except BlockingIOError:
                stderr_chunk = b""
            if stderr_chunk:
                buffered += stderr_chunk
                if parse_dd_progress:
                    matches = re.findall(rb"(\d+)\s+bytes", buffered)
                    if matches:
                        progress_callback(int(matches[-1]), snapshot.size)
                buffered = buffered[-512:]

        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
        while process.poll() is None:
            if cancel_event.is_set():
                core._terminate_process_group(process)
                raise core.OperationCancelled(
                    "Operation cancelled. Boot It cannot certify this USB; rewrite it before use."
                )
            try:
                stderr_chunk = os.read(stderr_fd, 65536)
            except BlockingIOError:
                stderr_chunk = b""
            if stderr_chunk and parse_dd_progress:
                buffered += stderr_chunk
                matches = re.findall(rb"(\d+)\s+bytes", buffered)
                if matches:
                    progress_callback(int(matches[-1]), snapshot.size)
                buffered = buffered[-512:]
            time.sleep(0.05)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        if sent != snapshot.size:
            raise RuntimeError(
                f"Sealed source stream ended early: sent {sent} of {snapshot.size} bytes."
            )
        progress_callback(snapshot.size, snapshot.size)
    finally:
        if process.poll() is None:
            core._terminate_process_group(process)


def install_source_seal(core: ModuleType) -> None:
    """Bind approved bytes to one anonymous source snapshot per destructive operation."""
    seals: dict[str, tuple[str, SourceIdentity]] = {}
    active = threading.local()
    core._boot_it_source_seals = seals

    window_type = getattr(core, "BootItWindow", None)
    if window_type is not None:
        original_hash_ready = window_type._hash_ready

        def hash_ready(self, path: str, digest: str) -> None:
            original_hash_ready(self, path, digest)
            seals.pop(path, None)
            if not digest or path != self.image_edit.text():
                return
            try:
                seals[path] = (digest, _identity(path))
            except OSError:
                return

        window_type._hash_ready = hash_ready

    worker_type = getattr(core, "WriteWorker", None)
    if worker_type is None:
        return

    original_worker_run = worker_type.run
    original_linux_write = core.linux_write
    original_linux_verify = core.linux_verify
    original_windows_write = core.windows_write
    original_windows_verify = core.windows_verify

    def current_snapshot(image: str) -> SourceSnapshot | None:
        session = getattr(active, "session", None)
        if session is None or session[0] != image:
            return None
        return session[1]

    def worker_run(self) -> None:
        approved = seals.get(self.image)
        if approved is None:
            return original_worker_run(self)
        digest, identity = approved
        self.status.emit("Sealing approved source bytes before touching target…")
        snapshot: SourceSnapshot | None = None
        try:
            snapshot = snapshot_verified_source(
                self.image,
                digest,
                identity,
                cancel_check=lambda: core._check_cancel(self._cancel_event),
            )
            active.session = (self.image, snapshot)
            original_worker_run(self)
        except core.OperationCancelled as exc:
            core.LOGGER.warning("Bootable media operation cancelled while sealing source: %s", exc)
            self.completed.emit(False, True, str(exc))
        except Exception as exc:
            core.LOGGER.exception("Source snapshot preparation failed")
            self.completed.emit(False, False, str(exc))
        finally:
            if hasattr(active, "session"):
                del active.session
            if snapshot is not None:
                snapshot.close()

    def linux_write(image, device, progress_callback, cancel_event):
        snapshot = current_snapshot(image)
        if snapshot is None:
            return original_linux_write(image, device, progress_callback, cancel_event)
        _stream_to_process(
            core,
            snapshot,
            _linux_target_command(core, device),
            progress_callback,
            cancel_event,
            parse_dd_progress=True,
        )

    def linux_verify(image, device, cancel_event):
        snapshot = current_snapshot(image)
        if snapshot is None:
            return original_linux_verify(image, device, cancel_event)
        _stream_to_process(
            core,
            snapshot,
            _linux_verify_command(core, device, snapshot.size),
            lambda _done, _total: None,
            cancel_event,
            parse_dd_progress=False,
        )

    def windows_write(image, device, progress_callback, cancel_event):
        snapshot = current_snapshot(image)
        if snapshot is None:
            return original_windows_write(image, device, progress_callback, cancel_event)
        if not core.is_windows_admin():
            raise PermissionError("Run Boot It as Administrator to write a raw USB device on Windows.")
        snapshot.rewind()
        written = 0
        with open(device, "r+b", buffering=0) as target:
            while True:
                core._check_cancel(cancel_event)
                chunk = snapshot.handle.read(core.CHUNK_SIZE)
                if not chunk:
                    break
                target.write(chunk)
                written += len(chunk)
                progress_callback(written, snapshot.size)
            target.flush()
            os.fsync(target.fileno())
        if written != snapshot.size:
            raise RuntimeError(
                f"Sealed source stream ended early: wrote {written} of {snapshot.size} bytes."
            )

    def windows_verify(image, device, progress_callback, cancel_event):
        snapshot = current_snapshot(image)
        if snapshot is None:
            return original_windows_verify(image, device, progress_callback, cancel_event)
        snapshot.rewind()
        compared = 0
        with open(device, "rb", buffering=0) as target:
            while True:
                core._check_cancel(cancel_event)
                expected = snapshot.handle.read(core.CHUNK_SIZE)
                if not expected:
                    break
                actual = target.read(len(expected))
                if actual != expected:
                    raise IOError(f"Verification failed at byte offset {compared}.")
                compared += len(expected)
                progress_callback(compared, snapshot.size)
        if compared != snapshot.size:
            raise RuntimeError(
                f"Sealed source verification ended early: compared {compared} of {snapshot.size} bytes."
            )

    worker_type.run = worker_run
    core.linux_write = linux_write
    core.linux_verify = linux_verify
    core.windows_write = windows_write
    core.windows_verify = windows_verify
