from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from pathlib import Path

__version__ = "0.2.0"


def diagnostics() -> dict[str, object]:
    system = platform.system()
    commands: dict[str, bool] = {}
    if system == "Linux":
        for command in ("lsblk", "findmnt", "dd", "cmp"):
            commands[command] = shutil.which(command) is not None
        commands["pkexec"] = shutil.which("pkexec") is not None
        commands["udisksctl"] = shutil.which("udisksctl") is not None
    elif system == "Windows":
        commands["powershell"] = any(
            shutil.which(candidate) is not None
            for candidate in ("powershell.exe", "pwsh.exe", "powershell")
        )

    return {
        "app": "Boot It",
        "version": __version__,
        "platform": system,
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "commands": commands,
    }


def diagnostics_json() -> str:
    return json.dumps(diagnostics(), sort_keys=True)


def write_self_test(path: str) -> None:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = diagnostics()
    payload["self_test"] = "ok"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + os.linesep, encoding="utf-8")
    temporary.replace(destination)
