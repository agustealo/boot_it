from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import boot_it
from boot_it_meta import __version__

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "boot-it.py"


def _load_launcher_module():
    spec = importlib.util.spec_from_file_location("boot_it_launcher", LAUNCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_canonical_launcher_reports_version_without_qt_startup() -> None:
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == __version__


def test_canonical_launcher_diagnostics_are_machine_readable() -> None:
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--diagnose"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    assert payload["version"] == __version__


def test_canonical_launcher_installs_runtime_hardening_before_main() -> None:
    original_linux_discovery = boot_it.discover_linux_drives
    original_linux_write = boot_it.linux_write
    original_linux_verify = boot_it.linux_verify
    original_windows_write = boot_it.windows_write
    original_windows_verify = boot_it.windows_verify
    original_worker_run = boot_it.WriteWorker.run
    original_validate_image = boot_it.validate_image
    original_build_ui = boot_it.BootItWindow._build_ui
    original_hash_ready = boot_it.BootItWindow._hash_ready
    original_start_write = boot_it.BootItWindow.start_write
    module = _load_launcher_module()
    application_main = module.load_application_main()
    try:
        assert application_main is boot_it.main
        assert boot_it.discover_linux_drives is not original_linux_discovery
        assert boot_it.discover_linux_drives.__module__ == "boot_it_topology_runtime"
        assert boot_it.linux_write is not original_linux_write
        assert boot_it.linux_write.__module__ == "boot_it_source_runtime"
        assert boot_it.linux_verify is not original_linux_verify
        assert boot_it.windows_write is not original_windows_write
        assert boot_it.windows_verify is not original_windows_verify
        assert boot_it.WriteWorker.run is not original_worker_run
        assert boot_it.WriteWorker.run.__module__ == "boot_it_source_runtime"
        assert boot_it.validate_image is not original_validate_image
        assert boot_it.validate_image.__module__ == "boot_it_runtime"
        assert boot_it.BootItWindow._build_ui is not original_build_ui
        assert boot_it.BootItWindow._hash_ready is not original_hash_ready
        assert boot_it.BootItWindow.start_write is not original_start_write
        assert hasattr(boot_it.BootItWindow, "_boot_it_authenticate")
        assert hasattr(boot_it.BootItWindow, "_boot_it_apply_publisher_profile")
        assert hasattr(boot_it.BootItWindow, "_boot_it_selected_publisher_profile")
        assert isinstance(boot_it._boot_it_source_seals, dict)
    finally:
        boot_it.discover_linux_drives = original_linux_discovery
        boot_it.linux_write = original_linux_write
        boot_it.linux_verify = original_linux_verify
        boot_it.windows_write = original_windows_write
        boot_it.windows_verify = original_windows_verify
        boot_it.WriteWorker.run = original_worker_run
        boot_it.validate_image = original_validate_image
        boot_it.BootItWindow._build_ui = original_build_ui
        boot_it.BootItWindow._hash_ready = original_hash_ready
        boot_it.BootItWindow.start_write = original_start_write
