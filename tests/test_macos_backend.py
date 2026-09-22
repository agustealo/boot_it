from __future__ import annotations

import pytest

import boot_it_macos
from boot_it_macos import classify_macos_drive, discover_macos_drives, macos_raw_device


def _info(**overrides):
    payload = {
        "DeviceIdentifier": "disk4",
        "DeviceNode": "/dev/disk4",
        "WholeDisk": True,
        "Internal": False,
        "RemovableMedia": False,
        "RemovableMediaOrExternalDevice": True,
        "Ejectable": True,
        "Writable": True,
        "WritableMedia": True,
        "VirtualOrPhysical": "Physical",
        "TotalSize": 64 * 1024**3,
        "MediaName": "External NVMe",
        "IORegistryEntryName": "External NVMe Media",
        "BusProtocol": "USB",
        "DeviceTreePath": "IODeviceTree:/PCI0/USB/example",
        "DiskUUID": "AABBCCDD-0000-1111-2222-333344445555",
    }
    payload.update(overrides)
    return payload


def test_external_nonremovable_physical_disk_is_a_safe_candidate() -> None:
    drive = classify_macos_drive(_info(RemovableMedia=False, Removable=False))
    assert drive is not None
    assert drive.safe
    assert drive.external
    assert not drive.removable
    assert not drive.virtual
    assert drive.device == "/dev/disk4"
    assert drive.platform == "macOS"
    assert "DeviceTree" in drive.hardware_id


def test_virtual_disk_image_is_blocked_even_when_external() -> None:
    drive = classify_macos_drive(
        _info(VirtualOrPhysical="Virtual", BusProtocol="Disk Image", Ejectable=True)
    )
    assert drive is not None
    assert not drive.safe
    assert drive.virtual
    assert drive.reason == "virtual disk"


def test_internal_disk_is_blocked() -> None:
    drive = classify_macos_drive(
        _info(Internal=True, RemovableMediaOrExternalDevice=False)
    )
    assert drive is not None
    assert not drive.safe
    assert drive.reason == "internal disk"


def test_read_only_external_disk_is_blocked() -> None:
    drive = classify_macos_drive(_info(Writable=False, WritableMedia=False))
    assert drive is not None
    assert not drive.safe
    assert drive.reason == "read-only"


def test_external_system_backing_disk_is_blocked() -> None:
    drive = classify_macos_drive(
        _info(),
        protected_disks={"disk4"},
        topology_resolved=True,
    )
    assert drive is not None
    assert not drive.safe
    assert drive.reason == "backs the current system volume"


def test_unresolved_system_topology_fails_closed() -> None:
    drive = classify_macos_drive(_info(), topology_resolved=False)
    assert drive is not None
    assert not drive.safe
    assert drive.reason == "system storage topology unresolved"


def test_macos_raw_device_accepts_only_whole_disks() -> None:
    assert macos_raw_device("/dev/disk4") == "/dev/rdisk4"
    assert macos_raw_device("/dev/rdisk12") == "/dev/rdisk12"
    with pytest.raises(ValueError):
        macos_raw_device("/dev/disk4s1")
    with pytest.raises(ValueError):
        macos_raw_device("disk4")


def test_discovery_uses_external_physical_inventory_and_preserves_blocked_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: list[str]):
        key = tuple(command)
        calls.append(key)
        if key == ("diskutil", "list", "-plist", "external", "physical"):
            return {
                "AllDisksAndPartitions": [
                    {"DeviceIdentifier": "disk4"},
                    {"DeviceIdentifier": "disk5"},
                ]
            }
        if key == ("diskutil", "info", "-plist", "/"):
            return {"Internal": True}
        if key == ("diskutil", "info", "-plist", "disk4"):
            return _info(DeviceIdentifier="disk4", DeviceNode="/dev/disk4")
        if key == ("diskutil", "info", "-plist", "disk5"):
            return _info(
                DeviceIdentifier="disk5",
                DeviceNode="/dev/disk5",
                VirtualOrPhysical="Virtual",
                BusProtocol="Disk Image",
            )
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(boot_it_macos, "_run_plist", fake_run)
    drives = discover_macos_drives()

    assert [drive.device for drive in drives] == ["/dev/disk4", "/dev/disk5"]
    assert drives[0].safe
    assert not drives[1].safe
    assert drives[1].reason == "virtual disk"
    assert ("diskutil", "list", "-plist", "external", "physical") in calls


def test_external_root_resolves_apfs_physical_store_and_blocks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str]):
        key = tuple(command)
        if key == ("diskutil", "list", "-plist", "external", "physical"):
            return {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk7"}]}
        if key == ("diskutil", "info", "-plist", "/"):
            return {
                "Internal": False,
                "DeviceIdentifier": "disk9s1",
                "WholeDisk": False,
                "ParentWholeDisk": "disk9",
            }
        if key == ("diskutil", "info", "-plist", "disk9"):
            return {
                "DeviceIdentifier": "disk9",
                "WholeDisk": True,
                "VirtualOrPhysical": "Virtual",
                "APFSPhysicalStores": [{"APFSPhysicalStore": "disk7s2"}],
            }
        if key == ("diskutil", "info", "-plist", "disk7s2"):
            return {
                "DeviceIdentifier": "disk7s2",
                "WholeDisk": False,
                "ParentWholeDisk": "disk7",
            }
        if key == ("diskutil", "info", "-plist", "disk7"):
            return _info(DeviceIdentifier="disk7", DeviceNode="/dev/disk7")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(boot_it_macos, "_run_plist", fake_run)
    drives = discover_macos_drives()

    assert len(drives) == 1
    assert drives[0].device == "/dev/disk7"
    assert not drives[0].safe
    assert drives[0].reason == "backs the current system volume"
