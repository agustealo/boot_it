from __future__ import annotations

from boot_it_topology import analyze_linux_topology, system_backing_disks


def _disk(path: str, *, children=None, tran=None, rm=False):
    return {
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "type": "disk",
        "tran": tran,
        "rm": rm,
        "children": children or [],
    }


def _node(path: str, kind: str, *, children=None, pkname=None):
    return {
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "type": kind,
        "pkname": pkname,
        "children": children or [],
    }


def test_simple_partition_root_protects_parent_disk() -> None:
    payload = {"blockdevices": [_disk("/dev/nvme0n1", children=[_node("/dev/nvme0n1p2", "part")])]}
    topology = analyze_linux_topology(payload, {"/": "/dev/nvme0n1p2"})
    assert topology.resolved
    assert system_backing_disks(topology) == frozenset({"/dev/nvme0n1"})


def test_lvm_root_protects_physical_backing_disk() -> None:
    root = _node("/dev/mapper/vg-root", "lvm")
    part = _node("/dev/sda2", "part", children=[root])
    payload = {"blockdevices": [_disk("/dev/sda", children=[part])]}
    topology = analyze_linux_topology(payload, {"/": "/dev/mapper/vg-root"})
    assert system_backing_disks(topology) == frozenset({"/dev/sda"})


def test_mdraid_root_protects_all_member_disks() -> None:
    md = _node("/dev/md0", "raid1")
    member_a = _node("/dev/sda1", "part", children=[md])
    member_b = _node("/dev/sdb1", "part", children=[md])
    payload = {"blockdevices": [_disk("/dev/sda", children=[member_a]), _disk("/dev/sdb", children=[member_b])]}
    topology = analyze_linux_topology(payload, {"/": "/dev/md0"})
    assert system_backing_disks(topology) == frozenset({"/dev/sda", "/dev/sdb"})


def test_separate_boot_disk_is_also_protected() -> None:
    root_disk = _disk("/dev/sda", children=[_node("/dev/sda2", "part")])
    boot_disk = _disk("/dev/sdb", children=[_node("/dev/sdb1", "part")])
    topology = analyze_linux_topology(payload={"blockdevices": [root_disk, boot_disk]}, mount_sources={"/": "/dev/sda2", "/boot": "/dev/sdb1"})
    assert system_backing_disks(topology) == frozenset({"/dev/sda", "/dev/sdb"})


def test_unresolved_root_fails_closed() -> None:
    payload = {"blockdevices": [_disk("/dev/sda")]}
    topology = analyze_linux_topology(payload, {"/": "/dev/mapper/missing"})
    assert not topology.resolved
    assert "absent from the lsblk graph" in topology.reason


def test_non_block_root_fails_closed() -> None:
    payload = {"blockdevices": [_disk("/dev/sda")]}
    topology = analyze_linux_topology(payload, {"/": "overlay"})
    assert not topology.resolved
    assert "not backed by a resolvable block device" in topology.reason
