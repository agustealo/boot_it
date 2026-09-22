from __future__ import annotations

import errno
import os
import plistlib
import select
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable, Mapping

from boot_it_models import DriveInfo, OperationCancelled

CHUNK_SIZE = 4 * 1024 * 1024


def _run_plist(command: list[str]) -> dict[str, Any]:
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = plistlib.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected plist dictionary from {' '.join(command)}.")
    return payload


def _is_virtual(info: Mapping[str, Any]) -> bool:
    virtual_or_physical = str(info.get("VirtualOrPhysical") or "").strip().casefold()
    protocol = str(info.get("BusProtocol") or info.get("Protocol") or "").strip().casefold()
    return (
        virtual_or_physical == "virtual"
        or protocol in {"disk image", "virtual"}
        or bool(info.get("SystemImage"))
    )


def _physical_backing_disks(info: Mapping[str, Any], seen: set[str] | None = None) -> set[str]:
    """Resolve a diskutil description to physical whole-disk identifiers.

    APFS volumes and synthesized containers can sit between the root filesystem and
    its physical store. This resolver walks ``APFSPhysicalStores`` and whole-disk
    parent references until a non-virtual whole disk is reached.
    """

    visited = seen if seen is not None else set()
    identifier = str(info.get("DeviceIdentifier") or "").strip()
    if identifier:
        if identifier in visited:
            return set()
        visited.add(identifier)

    stores = info.get("APFSPhysicalStores") or []
    resolved: set[str] = set()
    if isinstance(stores, list):
        for store in stores:
            if isinstance(store, Mapping):
                store_id = str(store.get("APFSPhysicalStore") or "").strip()
            else:
                store_id = str(store or "").strip()
            if not store_id:
                continue
            try:
                store_info = _run_plist(["diskutil", "info", "-plist", store_id])
            except (OSError, subprocess.CalledProcessError, plistlib.InvalidFileException):
                continue
            resolved.update(_physical_backing_disks(store_info, visited))
        if resolved:
            return resolved

    whole = bool(info.get("WholeDisk"))
    if whole and identifier and not _is_virtual(info):
        return {identifier}

    parent = str(
        info.get("ParentWholeDisk")
        or info.get("PartOfWhole")
        or ""
    ).strip()
    if parent and parent != identifier:
        try:
            parent_info = _run_plist(["diskutil", "info", "-plist", parent])
        except (OSError, subprocess.CalledProcessError, plistlib.InvalidFileException):
            return set()
        return _physical_backing_disks(parent_info, visited)

    return set()


def _protected_root_disks() -> tuple[set[str], bool]:
    """Return external physical disks backing the current macOS root filesystem.

    Internal root media is already excluded by the external-disk inventory. When
    macOS itself is booted from external media, however, the external physical
    backing disk must be identified explicitly or discovery fails closed.
    """

    try:
        root_info = _run_plist(["diskutil", "info", "-plist", "/"])
    except (OSError, subprocess.CalledProcessError, plistlib.InvalidFileException):
        return set(), False

    if bool(root_info.get("Internal")):
        return set(), True

    protected = _physical_backing_disks(root_info)
    return protected, bool(protected)


def classify_macos_drive(
    info: Mapping[str, Any],
    *,
    protected_disks: set[str] | frozenset[str] = frozenset(),
    topology_resolved: bool = True,
) -> DriveInfo | None:
    """Convert ``diskutil info -plist`` data into Boot It's canonical target model."""

    identifier = str(info.get("DeviceIdentifier") or "").strip()
    device = str(info.get("DeviceNode") or (f"/dev/{identifier}" if identifier else "")).strip()
    size = int(info.get("TotalSize") or info.get("Size") or info.get("IOKitSize") or 0)
    model = str(
        info.get("MediaName")
        or info.get("IORegistryEntryName")
        or "External disk"
    ).strip()
    bus = str(info.get("BusProtocol") or info.get("Protocol") or "unknown").strip()
    internal = bool(info.get("Internal"))
    external = bool(info.get("RemovableMediaOrExternalDevice")) or not internal
    removable = bool(info.get("RemovableMedia") or info.get("Removable") or info.get("Ejectable"))
    virtual = _is_virtual(info)
    writable = bool(info.get("WritableMedia", info.get("Writable", False)))
    whole = bool(info.get("WholeDisk"))

    if not identifier and not device:
        return None

    reason = ""
    if not topology_resolved:
        reason = "system storage topology unresolved"
    elif not whole:
        reason = "not a whole physical disk"
    elif internal:
        reason = "internal disk"
    elif virtual:
        reason = "virtual disk"
    elif identifier in protected_disks:
        reason = "backs the current system volume"
    elif not external:
        reason = "not an external disk"
    elif not writable:
        reason = "read-only"
    elif not device:
        reason = "missing device path"
    elif size <= 0:
        reason = "invalid capacity"

    hardware_parts = [
        str(info.get("DeviceTreePath") or "").strip(),
        str(info.get("DiskUUID") or info.get("MediaUUID") or "").strip(),
        str(info.get("IORegistryEntryName") or "").strip(),
    ]
    hardware_id = " | ".join(part for part in hardware_parts if part)

    return DriveInfo(
        device=device,
        size=size,
        model=model,
        bus=bus,
        removable=removable,
        safe=not reason,
        reason=reason,
        hardware_id=hardware_id,
        external=external,
        virtual=virtual,
        writable=writable,
        platform="macOS",
    )


def discover_macos_drives() -> list[DriveInfo]:
    """Discover safe-candidate external physical disks using machine-readable diskutil data."""

    inventory = _run_plist(["diskutil", "list", "-plist", "external", "physical"])
    protected, topology_resolved = _protected_root_disks()
    drives: list[DriveInfo] = []

    entries = inventory.get("AllDisksAndPartitions") or []
    if not isinstance(entries, list):
        raise RuntimeError("diskutil returned an invalid external-disk inventory.")

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        identifier = str(entry.get("DeviceIdentifier") or "").strip()
        if not identifier:
            continue
        try:
            info = _run_plist(["diskutil", "info", "-plist", identifier])
        except (OSError, subprocess.CalledProcessError, plistlib.InvalidFileException):
            continue
        drive = classify_macos_drive(
            info,
            protected_disks=protected,
            topology_resolved=topology_resolved,
        )
        if drive is not None:
            drives.append(drive)

    return drives


def macos_raw_device(device: str) -> str:
    """Return the raw whole-disk character-device path used for high-throughput I/O."""

    prefix = "/dev/"
    if not device.startswith(prefix):
        raise ValueError("macOS target must be a /dev/diskN whole-disk path.")
    name = device[len(prefix):]
    if name.startswith("r"):
        name = name[1:]
    if not name.startswith("disk") or not name[4:].isdigit():
        raise ValueError("macOS target must be a /dev/diskN whole-disk path.")
    return f"/dev/r{name}"


def macos_unmount(device: str) -> None:
    subprocess.run(
        ["diskutil", "unmountDisk", device],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def macos_eject(device: str) -> None:
    subprocess.run(
        ["diskutil", "eject", device],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _apple_script_for_command(command: str) -> str:
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    return f'do shell script "{escaped}" with administrator privileges'


def _authorization_error(stderr: str) -> Exception:
    lowered = stderr.casefold()
    if "user canceled" in lowered or "(-128)" in lowered or "cancelled" in lowered:
        return PermissionError("Administrator authorization was cancelled.")
    if "operation not permitted" in lowered:
        return PermissionError(
            "macOS denied raw-disk access. Grant Boot It Full Disk Access in Privacy & Security, then retry."
        )
    return RuntimeError(f"macOS privileged disk operation failed: {stderr.strip() or 'unknown error'}")


def _open_fifo_writer(
    fifo_path: str,
    process: subprocess.Popen,
    cancel_event,
) -> int:
    while True:
        if cancel_event.is_set():
            process.terminate()
            raise OperationCancelled("Operation cancelled before privileged disk access began.")
        try:
            return os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as exc:
            if exc.errno not in {errno.ENXIO, errno.ENOENT}:
                raise
            if process.poll() is not None:
                _stdout, stderr = process.communicate()
                raise _authorization_error(stderr or "")
            time.sleep(0.05)


def _write_nonblocking(fd: int, data: bytes, cancel_event) -> None:
    view = memoryview(data)
    while view:
        if cancel_event.is_set():
            raise OperationCancelled(
                "Operation cancelled. The target may contain a partial image and must be rewritten before use."
            )
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            select.select([], [fd], [], 0.1)
            continue
        if written <= 0:
            raise BrokenPipeError("Privileged macOS disk helper stopped accepting source bytes.")
        view = view[written:]


def _run_privileged_stream(
    source: BinaryIO,
    size: int,
    shell_command_builder: Callable[[str], str],
    progress_callback,
    cancel_event,
    *,
    verification: bool,
) -> None:
    """Stream trusted bytes through a FIFO to a macOS administrator-authorized command.

    The privileged process receives only the byte stream and raw target path. It
    never receives the original image pathname, preserving Boot It's sealed-source
    trust boundary while allowing the native macOS authorization dialog to own
    credential collection.
    """

    source.seek(0)
    with tempfile.TemporaryDirectory(prefix="boot-it-macos-") as workdir:
        os.chmod(workdir, 0o700)
        fifo_path = os.path.join(workdir, "source.fifo")
        os.mkfifo(fifo_path, 0o600)
        shell_command = shell_command_builder(fifo_path)
        script = _apple_script_for_command(shell_command)
        process = subprocess.Popen(
            ["/usr/bin/osascript", "-e", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        fd: int | None = None
        sent = 0
        broken_pipe = False
        try:
            fd = _open_fifo_writer(fifo_path, process, cancel_event)
            while True:
                if cancel_event.is_set():
                    raise OperationCancelled(
                        "Verification cancelled. Boot It cannot certify this USB."
                        if verification
                        else "Write cancelled. The USB contains a partial image and must be rewritten before use."
                    )
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                try:
                    _write_nonblocking(fd, chunk, cancel_event)
                except BrokenPipeError:
                    broken_pipe = True
                    break
                sent += len(chunk)
                progress_callback(sent, size)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        if cancel_event.is_set():
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            raise OperationCancelled(
                "Verification cancelled. Boot It cannot certify this USB."
                if verification
                else "Write cancelled. The USB contains a partial image and must be rewritten before use."
            )

        stdout, stderr = process.communicate()
        del stdout
        if process.returncode != 0:
            if verification:
                raise IOError(
                    "Byte-for-byte verification failed on macOS. "
                    + (stderr.strip() or "The target differs from the approved image.")
                )
            raise _authorization_error(stderr or "")
        if broken_pipe:
            raise RuntimeError("Privileged macOS disk helper ended before the source stream completed.")
        if sent != size:
            raise RuntimeError(f"Source stream ended early: sent {sent} of {size} bytes.")
        progress_callback(size, size)


def macos_write_stream(
    source: BinaryIO,
    size: int,
    device: str,
    progress_callback,
    cancel_event,
) -> None:
    raw_device = macos_raw_device(device)

    def command(fifo_path: str) -> str:
        return (
            f"exec /bin/dd if={shlex.quote(fifo_path)} of={shlex.quote(raw_device)} "
            "bs=4m status=none conv=fsync"
        )

    _run_privileged_stream(
        source,
        size,
        command,
        progress_callback,
        cancel_event,
        verification=False,
    )


def macos_verify_stream(
    source: BinaryIO,
    size: int,
    device: str,
    progress_callback,
    cancel_event,
) -> None:
    raw_device = macos_raw_device(device)

    def command(fifo_path: str) -> str:
        return (
            f"exec /usr/bin/cmp -n {size} {shlex.quote(fifo_path)} {shlex.quote(raw_device)}"
        )

    _run_privileged_stream(
        source,
        size,
        command,
        progress_callback,
        cancel_event,
        verification=True,
    )


def macos_write(
    image: str,
    device: str,
    progress_callback,
    cancel_event,
) -> None:
    size = Path(image).stat().st_size
    with open(image, "rb") as source:
        macos_write_stream(source, size, device, progress_callback, cancel_event)


def macos_verify(
    image: str,
    device: str,
    progress_callback,
    cancel_event,
) -> None:
    size = Path(image).stat().st_size
    with open(image, "rb") as source:
        macos_verify_stream(source, size, device, progress_callback, cancel_event)
