from __future__ import annotations

from types import SimpleNamespace

import boot_it_source_runtime as runtime


def test_linux_write_command_has_no_source_path(monkeypatch) -> None:
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    command = runtime._linux_target_command(SimpleNamespace(), "/dev/loop9")
    assert command[0] == "dd"
    assert "of=/dev/loop9" in command
    assert not any(part.startswith("if=") for part in command)


def test_linux_verify_reads_authorized_bytes_from_stdin(monkeypatch) -> None:
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    command = runtime._linux_verify_command(SimpleNamespace(), "/dev/loop9", 12345)
    assert command == ["cmp", "-n", "12345", "-", "/dev/loop9"]


def test_non_root_linux_stream_only_elevates_target_process(monkeypatch) -> None:
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/pkexec" if name == "pkexec" else None)
    write_command = runtime._linux_target_command(SimpleNamespace(), "/dev/sdz")
    verify_command = runtime._linux_verify_command(SimpleNamespace(), "/dev/sdz", 4096)
    assert write_command[:2] == ["pkexec", "dd"]
    assert verify_command[:2] == ["pkexec", "cmp"]
    assert not any(part.startswith("if=") for part in write_command)
    assert "-" in verify_command
