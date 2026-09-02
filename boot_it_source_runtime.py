from __future__ import annotations

import os
from pathlib import Path
from types import ModuleType

from boot_it_source import SourceIdentity, verify_source_seal


def _identity(path: str) -> SourceIdentity:
    stat = Path(path).stat()
    return SourceIdentity(
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        device=getattr(stat, "st_dev", None),
        inode=getattr(stat, "st_ino", None),
    )


def install_source_seal(core: ModuleType) -> None:
    """Bind the GUI-approved image digest to the destructive write lifecycle."""
    seals: dict[str, tuple[str, SourceIdentity]] = {}
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

    def guard(image: str, phase: str) -> None:
        approved = seals.get(image)
        if approved is None:
            # Lower-level writer functions remain usable by integration tests and
            # embedders. The GUI destructive path always registers an approved seal.
            return
        digest, identity = approved
        try:
            verify_source_seal(image, digest, identity)
        except (OSError, RuntimeError) as exc:
            if phase == "write":
                raise RuntimeError(f"Source image seal rejected destructive write: {exc}") from exc
            raise RuntimeError(
                "Source image changed during the write. Boot It will not certify this USB as verified. "
                f"Details: {exc}"
            ) from exc

    original_linux_write = core.linux_write
    original_linux_verify = core.linux_verify
    original_windows_write = core.windows_write
    original_windows_verify = core.windows_verify

    def linux_write(image, device, progress_callback, cancel_event):
        guard(image, "write")
        return original_linux_write(image, device, progress_callback, cancel_event)

    def linux_verify(image, device, cancel_event):
        guard(image, "verify")
        return original_linux_verify(image, device, cancel_event)

    def windows_write(image, device, progress_callback, cancel_event):
        guard(image, "write")
        return original_windows_write(image, device, progress_callback, cancel_event)

    def windows_verify(image, device, progress_callback, cancel_event):
        guard(image, "verify")
        return original_windows_verify(image, device, progress_callback, cancel_event)

    core.linux_write = linux_write
    core.linux_verify = linux_verify
    core.windows_write = windows_write
    core.windows_verify = windows_verify
