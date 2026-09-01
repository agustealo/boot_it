from pathlib import Path

import pytest

import boot_it
from boot_it import DriveInfo, format_bytes, revalidate_target, validate_image, windows_disk_number


def make_drive(**overrides) -> DriveInfo:
    values = {
        "device": "/dev/sdz",
        "size": 16 * 1024**3,
        "model": "Test USB",
        "bus": "usb",
        "removable": True,
        "safe": True,
        "reason": "",
        "hardware_id": "SERIAL-123",
    }
    values.update(overrides)
    return DriveInfo(**values)


def test_drive_label_marks_blocked_target() -> None:
    drive = make_drive(safe=False, reason="system disk")
    assert "blocked: system disk" in drive.label
    assert "/dev/sdz" in drive.label


def test_drive_identity_includes_hardware_id() -> None:
    first = make_drive(hardware_id="SERIAL-123")
    replacement = make_drive(hardware_id="SERIAL-999")
    assert first.identity != replacement.identity


def test_revalidate_target_accepts_unchanged_safe_device(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = make_drive()
    monkeypatch.setattr(boot_it, "discover_drives", lambda system: [expected])
    assert revalidate_target(expected, "Linux") == expected


def test_revalidate_target_rejects_removed_device(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = make_drive()
    monkeypatch.setattr(boot_it, "discover_drives", lambda system: [])
    with pytest.raises(RuntimeError, match="no longer present"):
        revalidate_target(expected, "Linux")


def test_revalidate_target_rejects_same_path_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = make_drive(hardware_id="SERIAL-123")
    replacement = make_drive(hardware_id="SERIAL-999")
    monkeypatch.setattr(boot_it, "discover_drives", lambda system: [replacement])
    with pytest.raises(RuntimeError, match="identity changed"):
        revalidate_target(expected, "Linux")


def test_revalidate_target_rejects_newly_blocked_device(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = make_drive()
    blocked = make_drive(safe=False, reason="read-only")
    monkeypatch.setattr(boot_it, "discover_drives", lambda system: [blocked])
    with pytest.raises(RuntimeError, match="no longer writable"):
        revalidate_target(expected, "Linux")


def test_validate_image_rejects_missing_file(tmp_path: Path) -> None:
    valid, reason = validate_image(str(tmp_path / "missing.iso"))
    assert not valid
    assert "existing" in reason.lower()


def test_validate_image_rejects_wrong_extension(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"0" * (1024 * 1024 + 1))
    valid, reason = validate_image(str(path))
    assert not valid
    assert ".iso" in reason


def test_validate_image_accepts_iso_and_img(tmp_path: Path) -> None:
    for suffix in (".iso", ".img"):
        path = tmp_path / f"image{suffix}"
        path.write_bytes(b"0" * (1024 * 1024 + 1))
        assert validate_image(str(path)) == (True, "")


def test_windows_disk_number_parses_only_physical_drive_paths() -> None:
    assert windows_disk_number(r"\\.\PhysicalDrive0") == 0
    assert windows_disk_number(r"\\.\PhysicalDrive27") == 27
    with pytest.raises(ValueError):
        windows_disk_number("C:")
    with pytest.raises(ValueError):
        windows_disk_number(r"\\.\C:")


def test_format_bytes_is_human_readable() -> None:
    assert format_bytes(1024) == "1.00 KiB"
    assert format_bytes(1024**3) == "1.00 GiB"
