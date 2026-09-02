from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


CRITICAL_MOUNTS = ("/", "/boot", "/boot/efi")


@dataclass(frozen=True)
class LinuxTopology:
    records: tuple[dict[str, Any], ...]
    parents: dict[str, frozenset[str]]
    protected_devices: frozenset[str]
    resolved: bool
    reason: str = ""


def _device_path(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("/dev/"):
        return text
    return f"/dev/{text}"


def _flatten(
    nodes: list[dict[str, Any]],
    *,
    parent: str = "",
    records: list[dict[str, Any]] | None = None,
    parents: dict[str, set[str]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    records = records if records is not None else []
    parents = parents if parents is not None else {}
    for node in nodes:
        path = _device_path(node.get("path") or node.get("name"))
        if not path:
            continue
        records.append(node)
        bucket = parents.setdefault(path, set())
        if parent:
            bucket.add(parent)
        pkname = _device_path(node.get("pkname"))
        if pkname and pkname != path:
            bucket.add(pkname)
        children = node.get("children") or []
        if isinstance(children, list):
            _flatten(children, parent=path, records=records, parents=parents)
    return records, parents


def _ancestors(start: str, parents: dict[str, set[str]]) -> set[str]:
    pending = [start]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if not current or current in seen:
            continue
        seen.add(current)
        pending.extend(parents.get(current, ()))
    return seen


def analyze_linux_topology(
    payload: dict[str, Any],
    mount_sources: dict[str, str],
    *,
    normalize_source: Callable[[str], str] | None = None,
) -> LinuxTopology:
    nodes = payload.get("blockdevices") or []
    if not isinstance(nodes, list):
        return LinuxTopology((), {}, frozenset(), False, "lsblk returned an invalid device graph")

    records, mutable_parents = _flatten(nodes)
    known = {_device_path(record.get("path") or record.get("name")) for record in records}
    known.discard("")
    protected: set[str] = set()
    resolved_mounts = 0

    for mountpoint in CRITICAL_MOUNTS:
        source = str(mount_sources.get(mountpoint) or "").split("[")[0].strip()
        if not source:
            continue
        if not source.startswith("/dev/"):
            if mountpoint == "/":
                return LinuxTopology(
                    tuple(records),
                    {key: frozenset(value) for key, value in mutable_parents.items()},
                    frozenset(),
                    False,
                    f"critical mount {mountpoint} is not backed by a resolvable block device ({source})",
                )
            continue
        if normalize_source is not None:
            source = normalize_source(source)
        if source not in known:
            return LinuxTopology(
                tuple(records),
                {key: frozenset(value) for key, value in mutable_parents.items()},
                frozenset(),
                False,
                f"critical mount {mountpoint} source {source} is absent from the lsblk graph",
            )
        protected.update(_ancestors(source, mutable_parents))
        resolved_mounts += 1

    if resolved_mounts == 0:
        return LinuxTopology(
            tuple(records),
            {key: frozenset(value) for key, value in mutable_parents.items()},
            frozenset(),
            False,
            "no critical Linux mount could be resolved to block storage",
        )

    return LinuxTopology(
        tuple(records),
        {key: frozenset(value) for key, value in mutable_parents.items()},
        frozenset(protected),
        True,
    )


def system_backing_disks(topology: LinuxTopology) -> frozenset[str]:
    disks: set[str] = set()
    for record in topology.records:
        path = _device_path(record.get("path") or record.get("name"))
        if path in topology.protected_devices and str(record.get("type") or "").casefold() == "disk":
            disks.add(path)
    return frozenset(disks)
