from __future__ import annotations

import json
import subprocess
from types import ModuleType

from boot_it_topology import CRITICAL_MOUNTS, analyze_linux_topology, system_backing_disks


def _mount_sources(core: ModuleType) -> dict[str, str]:
    sources: dict[str, str] = {}
    for mountpoint in CRITICAL_MOUNTS:
        try:
            value = core._run_text(["findmnt", "-rn", "-o", "SOURCE", mountpoint]).strip()
        except (OSError, subprocess.CalledProcessError):
            if mountpoint == "/":
                raise
            continue
        if value:
            sources[mountpoint] = value.splitlines()[0].strip()
    return sources


def _normalize_source(core: ModuleType, source: str) -> str:
    try:
        output = core._run_text(["lsblk", "-no", "PATH", source]).strip()
    except (OSError, subprocess.CalledProcessError):
        return source
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[0] if len(lines) == 1 else source


def install_linux_topology(core: ModuleType) -> None:
    """Replace Linux target discovery with graph-aware system-storage protection."""

    def discover_linux_drives():
        payload_text = core._run_text(
            [
                "lsblk",
                "--json",
                "--bytes",
                "--paths",
                "--output",
                "NAME,PATH,SIZE,MODEL,TRAN,RM,TYPE,RO,SERIAL,WWN,PKNAME",
            ]
        )
        payload = json.loads(payload_text)
        try:
            mounts = _mount_sources(core)
            topology = analyze_linux_topology(
                payload,
                mounts,
                normalize_source=lambda source: _normalize_source(core, source),
            )
        except (OSError, subprocess.CalledProcessError, ValueError, TypeError) as exc:
            core.LOGGER.exception("Unable to resolve Linux system storage topology")
            topology = analyze_linux_topology(payload, {})
            unresolved_reason = f"system storage topology unresolved: {exc}"
        else:
            unresolved_reason = f"system storage topology unresolved: {topology.reason}" if not topology.resolved else ""

        protected_disks = system_backing_disks(topology) if topology.resolved else frozenset()
        drives = []
        for item in topology.records:
            if str(item.get("type") or "").casefold() != "disk":
                continue
            removable = bool(item.get("rm")) or str(item.get("tran") or "").casefold() == "usb"
            if not removable:
                continue
            device = str(item.get("path") or "")
            read_only = bool(item.get("ro"))
            reason = ""
            if not topology.resolved:
                reason = unresolved_reason or "system storage topology unresolved"
            elif device in protected_disks:
                reason = "backs a critical system mount"
            elif read_only:
                reason = "read-only"
            elif not device:
                reason = "missing device path"
            serial = str(item.get("serial") or "").strip()
            wwn = str(item.get("wwn") or "").strip()
            drives.append(
                core.DriveInfo(
                    device=device,
                    size=int(item.get("size") or 0),
                    model=str(item.get("model") or "USB drive").strip(),
                    bus=str(item.get("tran") or "unknown"),
                    removable=removable,
                    safe=not reason,
                    reason=reason,
                    hardware_id=wwn or serial,
                )
            )
        return drives

    core.discover_linux_drives = discover_linux_drives
