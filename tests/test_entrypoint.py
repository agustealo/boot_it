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
    original = boot_it.linux_write
    module = _load_launcher_module()
    application_main = module.load_application_main()
    try:
        assert application_main is boot_it.main
        assert boot_it.linux_write is not original
        assert boot_it.linux_write.__module__ == "boot_it_runtime"
    finally:
        boot_it.linux_write = original
