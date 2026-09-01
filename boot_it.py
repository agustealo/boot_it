from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PySide6 import QtCore, QtGui, QtWidgets

APP_NAME = "Boot It"
CHUNK_SIZE = 4 * 1024 * 1024
MIN_IMAGE_SIZE = 1024 * 1024
LOG_PATH = Path.home() / ".boot_it" / "boot_it.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
LOGGER = logging.getLogger("boot_it")


class OperationCancelled(RuntimeError):
    """Raised when a destructive operation is cancelled intentionally."""


@dataclass(frozen=True)
class DriveInfo:
    device: str
    size: int
    model: str
    bus: str
    removable: bool
    safe: bool
    reason: str = ""
    hardware_id: str = ""

    @property
    def size_gib(self) -> float:
        return self.size / (1024**3)

    @property
    def label(self) -> str:
        suffix = "" if self.safe else f" [blocked: {self.reason}]"
        return f"{self.model or 'USB drive'} · {self.size_gib:.2f} GiB · {self.device}{suffix}"

    @property
    def identity(self) -> tuple[str, int, str, str, str]:
        return (
            self.device,
            self.size,
            self.model.strip().casefold(),
            self.bus.strip().casefold(),
            self.hardware_id.strip().casefold(),
        )


def format_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{value} B"


def validate_image(path: str) -> tuple[bool, str]:
    image = Path(path)
    if not image.is_file():
        return False, "Select an existing image file."
    if image.suffix.lower() not in {".iso", ".img"}:
        return False, "Boot It currently accepts .iso and .img images."
    size = image.stat().st_size
    if size < MIN_IMAGE_SIZE:
        return False, "The selected image is unexpectedly small."
    return True, ""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _run_text(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()


def _linux_root_disk() -> str | None:
    try:
        source = _run_text(["findmnt", "-no", "SOURCE", "/"])
        source = source.split("[")[0]
        parent = _run_text(["lsblk", "-no", "PKNAME", source]).splitlines()
        if parent and parent[0].strip():
            return f"/dev/{parent[0].strip()}"
        if source.startswith("/dev/"):
            return source
    except (OSError, subprocess.CalledProcessError):
        LOGGER.exception("Unable to resolve Linux root disk")
    return None


def discover_linux_drives() -> list[DriveInfo]:
    payload = _run_text(
        [
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,PATH,SIZE,MODEL,TRAN,RM,TYPE,RO,SERIAL,WWN",
        ]
    )
    root_disk = _linux_root_disk()
    drives: list[DriveInfo] = []
    for item in json.loads(payload).get("blockdevices", []):
        if item.get("type") != "disk":
            continue
        removable = bool(item.get("rm")) or str(item.get("tran") or "").lower() == "usb"
        if not removable:
            continue
        device = str(item.get("path") or "")
        read_only = bool(item.get("ro"))
        safe = bool(device) and device != root_disk and not read_only
        reason = ""
        if device == root_disk:
            reason = "system disk"
        elif read_only:
            reason = "read-only"
        elif not device:
            reason = "missing device path"
        serial = str(item.get("serial") or "").strip()
        wwn = str(item.get("wwn") or "").strip()
        drives.append(
            DriveInfo(
                device=device,
                size=int(item.get("size") or 0),
                model=str(item.get("model") or "USB drive").strip(),
                bus=str(item.get("tran") or "unknown"),
                removable=removable,
                safe=safe,
                reason=reason,
                hardware_id=wwn or serial,
            )
        )
    return drives


def _powershell_json(script: str):
    executable = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("powershell")
    if not executable:
        raise RuntimeError("PowerShell is required for Windows device discovery.")
    output = _run_text(
        [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f"$ErrorActionPreference='Stop'; {script}",
        ]
    )
    if not output:
        return []
    return json.loads(output)


def discover_windows_drives() -> list[DriveInfo]:
    data = _powershell_json(
        "@(Get-Disk | Where-Object { $_.BusType -eq 'USB' } | "
        "Select-Object Number,FriendlyName,Size,BusType,IsBoot,IsSystem,IsReadOnly,IsOffline,UniqueId,SerialNumber) | "
        "ConvertTo-Json -Compress"
    )
    if isinstance(data, dict):
        data = [data]
    drives: list[DriveInfo] = []
    for item in data:
        number = int(item["Number"])
        blocked_reason = ""
        if item.get("IsBoot") or item.get("IsSystem"):
            blocked_reason = "system disk"
        elif item.get("IsReadOnly"):
            blocked_reason = "read-only"
        elif item.get("IsOffline"):
            blocked_reason = "offline"
        hardware_id = str(item.get("UniqueId") or item.get("SerialNumber") or "").strip()
        drives.append(
            DriveInfo(
                device=rf"\\.\PhysicalDrive{number}",
                size=int(item.get("Size") or 0),
                model=str(item.get("FriendlyName") or f"USB disk {number}"),
                bus=str(item.get("BusType") or "USB"),
                removable=True,
                safe=not blocked_reason,
                reason=blocked_reason,
                hardware_id=hardware_id,
            )
        )
    return drives


def discover_drives(system: str | None = None) -> list[DriveInfo]:
    detected = system or platform.system()
    if detected == "Linux":
        return discover_linux_drives()
    if detected == "Windows":
        return discover_windows_drives()
    raise RuntimeError(f"Unsupported operating system: {detected}")


def revalidate_target(expected: DriveInfo, system: str) -> DriveInfo:
    """Rediscover and prove that the selected physical target is still the same safe device."""
    candidates = discover_drives(system)
    current = next((drive for drive in candidates if drive.device == expected.device), None)
    if current is None:
        raise RuntimeError("Target USB is no longer present. Refresh the device list and select it again.")
    if not current.safe:
        raise RuntimeError(f"Target is no longer writable: {current.reason or 'safety policy blocked it'}.")
    if current.identity != expected.identity:
        raise RuntimeError(
            "Target identity changed after confirmation. No data was written. "
            "Refresh the device list and confirm the physical USB again."
        )
    return current


def is_windows_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _check_cancel(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise OperationCancelled("Operation cancelled. The target may contain a partial image and should not be booted.")


def linux_unmount(device: str) -> None:
    partitions = _run_text(["lsblk", "-ln", "-o", "PATH", device]).splitlines()[1:]
    for partition in partitions:
        partition = partition.strip()
        if not partition:
            continue
        mounted = subprocess.run(
            ["findmnt", "-rn", partition],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not mounted:
            continue
        if shutil.which("udisksctl"):
            subprocess.run(["udisksctl", "unmount", "-b", partition], check=True)
        else:
            command = ["umount", partition]
            if os.geteuid() != 0:
                if not shutil.which("pkexec"):
                    raise RuntimeError("pkexec is required to unmount this device safely.")
                command.insert(0, "pkexec")
            subprocess.run(command, check=True)


def _dd_command(image: str, device: str) -> list[str]:
    command = [
        "dd",
        f"if={image}",
        f"of={device}",
        "bs=4M",
        "status=progress",
        "conv=fsync",
    ]
    if os.geteuid() != 0:
        if not shutil.which("pkexec"):
            raise RuntimeError("pkexec is required to write raw devices without running Boot It as root.")
        command.insert(0, "pkexec")
    return command


def _terminate_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)


def linux_write(
    image: str,
    device: str,
    progress_callback,
    cancel_event: threading.Event,
) -> None:
    command = _dd_command(image, device)
    total = Path(image).stat().st_size
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    assert process.stderr is not None
    os.set_blocking(process.stderr.fileno(), False)
    buffered = ""
    try:
        while process.poll() is None:
            if cancel_event.is_set():
                _terminate_process_group(process)
                raise OperationCancelled(
                    "Write cancelled. The USB contains a partial image and must be rewritten before use."
                )
            try:
                chunk = process.stderr.read() or ""
            except BlockingIOError:
                chunk = ""
            if chunk:
                buffered += chunk
                matches = re.findall(r"(\d+)\s+bytes", buffered)
                if matches:
                    progress_callback(int(matches[-1]), total)
                buffered = buffered[-256:]
            time.sleep(0.1)
        remainder = process.stderr.read() or ""
        matches = re.findall(r"(\d+)\s+bytes", buffered + remainder)
        if matches:
            progress_callback(int(matches[-1]), total)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
    finally:
        if process.poll() is None:
            _terminate_process_group(process)


def linux_verify(image: str, device: str, cancel_event: threading.Event) -> None:
    size = Path(image).stat().st_size
    command = ["cmp", "-n", str(size), image, device]
    if os.geteuid() != 0:
        if not shutil.which("pkexec"):
            raise RuntimeError("pkexec is required for post-write verification.")
        command.insert(0, "pkexec")
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        while process.poll() is None:
            if cancel_event.is_set():
                _terminate_process_group(process)
                raise OperationCancelled(
                    "Verification cancelled. Boot It cannot certify the USB; rewrite or verify it before use."
                )
            time.sleep(0.1)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
    finally:
        if process.poll() is None:
            _terminate_process_group(process)


def windows_disk_number(device: str) -> int:
    match = re.fullmatch(r"\\\\\.\\PhysicalDrive(\d+)", device, re.IGNORECASE)
    if not match:
        raise ValueError("Invalid Windows physical-drive path.")
    return int(match.group(1))


def windows_dismount(device: str) -> None:
    number = windows_disk_number(device)
    _powershell_json(
        f"Get-Partition -DiskNumber {number} -ErrorAction SilentlyContinue | "
        "Where-Object DriveLetter | ForEach-Object { "
        "$letter = \"$($_.DriveLetter):\"; mountvol $letter /p | Out-Null }; "
        "@() | ConvertTo-Json -Compress"
    )


def windows_write(
    image: str,
    device: str,
    progress_callback,
    cancel_event: threading.Event,
) -> None:
    if not is_windows_admin():
        raise PermissionError("Run Boot It as Administrator to write a raw USB device on Windows.")
    total = Path(image).stat().st_size
    written = 0
    with open(image, "rb") as source, open(device, "r+b", buffering=0) as target:
        while True:
            _check_cancel(cancel_event)
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            target.write(chunk)
            written += len(chunk)
            progress_callback(written, total)
        target.flush()
        os.fsync(target.fileno())


def windows_verify(
    image: str,
    device: str,
    progress_callback,
    cancel_event: threading.Event,
) -> None:
    total = Path(image).stat().st_size
    compared = 0
    with open(image, "rb") as source, open(device, "rb", buffering=0) as target:
        while True:
            _check_cancel(cancel_event)
            expected = source.read(CHUNK_SIZE)
            if not expected:
                break
            actual = target.read(len(expected))
            if actual != expected:
                raise IOError(f"Verification failed at byte offset {compared}.")
            compared += len(expected)
            progress_callback(compared, total)


class WriteWorker(QtCore.QThread):
    status = QtCore.Signal(str)
    progress = QtCore.Signal(int)
    completed = QtCore.Signal(bool, bool, str)

    def __init__(self, image: str, drive: DriveInfo, system: str):
        super().__init__()
        self.image = image
        self.drive = drive
        self.system = system
        self._cancel_event = threading.Event()

    def request_cancel(self) -> None:
        self._cancel_event.set()

    def _emit_progress(self, done: int, total: int) -> None:
        if total:
            self.progress.emit(min(100, int(done * 100 / total)))

    def run(self) -> None:
        started = time.monotonic()
        try:
            self.status.emit("Revalidating target identity…")
            drive = revalidate_target(self.drive, self.system)
            _check_cancel(self._cancel_event)
            if self.system == "Linux":
                self.status.emit("Unmounting target volumes…")
                linux_unmount(drive.device)
                _check_cancel(self._cancel_event)
                self.status.emit("Writing image…")
                linux_write(self.image, drive.device, self._emit_progress, self._cancel_event)
                self.status.emit("Verifying written bytes…")
                linux_verify(self.image, drive.device, self._cancel_event)
                self.progress.emit(100)
            elif self.system == "Windows":
                self.status.emit("Dismounting target volumes…")
                windows_dismount(drive.device)
                _check_cancel(self._cancel_event)
                self.status.emit("Writing image…")
                windows_write(self.image, drive.device, self._emit_progress, self._cancel_event)
                self.status.emit("Verifying written bytes…")
                windows_verify(self.image, drive.device, self._emit_progress, self._cancel_event)
                self.progress.emit(100)
            else:
                raise RuntimeError(f"Unsupported operating system: {self.system}")
            elapsed = time.monotonic() - started
            self.completed.emit(True, False, f"Write and verification completed in {elapsed:.1f} seconds.")
        except OperationCancelled as exc:
            LOGGER.warning("Bootable media operation cancelled: %s", exc)
            self.completed.emit(False, True, str(exc))
        except Exception as exc:
            LOGGER.exception("Bootable media creation failed")
            self.completed.emit(False, False, str(exc))


class HashWorker(QtCore.QThread):
    completed = QtCore.Signal(str, str)

    def __init__(self, image: str):
        super().__init__()
        self.image = image

    def run(self) -> None:
        try:
            digest = sha256_file(self.image)
            self.completed.emit(self.image, digest)
        except Exception:
            LOGGER.exception("Unable to hash image")
            self.completed.emit(self.image, "")


class BootItWindow(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.system = platform.system()
        self.drives: list[DriveInfo] = []
        self.worker: WriteWorker | None = None
        self.hash_worker: HashWorker | None = None
        self._build_ui()
        self.refresh_drives()

    def _build_ui(self) -> None:
        self.setWindowTitle(f"{APP_NAME} · verified boot media")
        self.resize(760, 590)
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        title = QtWidgets.QLabel("Boot It")
        font = title.font()
        font.setPointSize(24)
        font.setBold(True)
        title.setFont(font)
        root.addWidget(title)
        subtitle = QtWidgets.QLabel("Write ISO/IMG media with target safety checks and byte-for-byte verification.")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        image_group = QtWidgets.QGroupBox("1 · Image")
        image_layout = QtWidgets.QVBoxLayout(image_group)
        picker = QtWidgets.QHBoxLayout()
        self.image_edit = QtWidgets.QLineEdit()
        self.image_edit.setPlaceholderText("Select an .iso or .img file")
        self.image_edit.textChanged.connect(self._image_changed)
        picker.addWidget(self.image_edit, 1)
        browse = QtWidgets.QPushButton("Browse…")
        browse.clicked.connect(self.browse_image)
        picker.addWidget(browse)
        image_layout.addLayout(picker)
        self.hash_label = QtWidgets.QLabel("SHA-256: not calculated")
        self.hash_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        image_layout.addWidget(self.hash_label)
        root.addWidget(image_group)

        drive_group = QtWidgets.QGroupBox("2 · Target USB")
        drive_layout = QtWidgets.QHBoxLayout(drive_group)
        self.drive_combo = QtWidgets.QComboBox()
        drive_layout.addWidget(self.drive_combo, 1)
        self.refresh_button = QtWidgets.QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_drives)
        drive_layout.addWidget(self.refresh_button)
        root.addWidget(drive_group)

        self.warning = QtWidgets.QLabel("The selected target will be overwritten. System disks are blocked.")
        self.warning.setWordWrap(True)
        root.addWidget(self.warning)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)
        self.status = QtWidgets.QPlainTextEdit()
        self.status.setReadOnly(True)
        self.status.setMaximumBlockCount(500)
        root.addWidget(self.status, 1)

        actions = QtWidgets.QHBoxLayout()
        self.write_button = QtWidgets.QPushButton("Write and verify")
        button_font = self.write_button.font()
        button_font.setBold(True)
        self.write_button.setFont(button_font)
        self.write_button.clicked.connect(self.start_write)
        actions.addWidget(self.write_button, 1)
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_write)
        actions.addWidget(self.cancel_button)
        root.addLayout(actions)

    def browse_image(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select boot image",
            "",
            "Boot images (*.iso *.img);;All files (*)",
        )
        if path:
            self.image_edit.setText(path)

    def _image_changed(self, path: str) -> None:
        valid, reason = validate_image(path)
        if not valid:
            self.hash_label.setText(f"SHA-256: {reason}" if path else "SHA-256: not calculated")
            return
        self.hash_label.setText("SHA-256: calculating…")
        self.hash_worker = HashWorker(path)
        self.hash_worker.completed.connect(self._hash_ready)
        self.hash_worker.start()

    def _hash_ready(self, path: str, digest: str) -> None:
        if path != self.image_edit.text():
            return
        self.hash_label.setText(f"SHA-256: {digest or 'unavailable'}")

    def refresh_drives(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.drive_combo.clear()
        self.drives = []
        try:
            self.drives = discover_drives(self.system)
            if not self.drives:
                self.drive_combo.addItem("No USB drives found")
            else:
                for drive in self.drives:
                    self.drive_combo.addItem(drive.label)
            self._log(f"Found {len(self.drives)} USB target(s).")
        except Exception as exc:
            LOGGER.exception("Drive discovery failed")
            self.drive_combo.addItem("Drive discovery failed")
            self._log(f"Discovery error: {exc}")

    def _selected_drive(self) -> DriveInfo | None:
        index = self.drive_combo.currentIndex()
        if 0 <= index < len(self.drives):
            return self.drives[index]
        return None

    def start_write(self) -> None:
        image = self.image_edit.text().strip()
        valid, reason = validate_image(image)
        if not valid:
            QtWidgets.QMessageBox.critical(self, APP_NAME, reason)
            return
        drive = self._selected_drive()
        if not drive:
            QtWidgets.QMessageBox.critical(self, APP_NAME, "Select a USB target.")
            return
        if not drive.safe:
            QtWidgets.QMessageBox.critical(self, APP_NAME, f"This target is blocked: {drive.reason}.")
            return
        image_size = Path(image).stat().st_size
        if image_size > drive.size:
            QtWidgets.QMessageBox.critical(
                self,
                APP_NAME,
                f"Image size ({format_bytes(image_size)}) exceeds target capacity ({format_bytes(drive.size)}).",
            )
            return
        if self.system == "Windows" and not is_windows_admin():
            QtWidgets.QMessageBox.critical(
                self,
                APP_NAME,
                "Boot It needs Administrator privileges on Windows before it can open a physical USB device.",
            )
            return
        identity_note = drive.hardware_id or "hardware ID unavailable; model/capacity/path fingerprint will be rechecked"
        confirmation = QtWidgets.QMessageBox.warning(
            self,
            "Confirm destructive write",
            f"Erase and overwrite:\n\n{drive.model}\n{drive.device}\n{drive.size_gib:.2f} GiB\n"
            f"Identity: {identity_note}\n\n"
            "Boot It will rediscover this exact target immediately before writing and verify every written byte.",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.Cancel,
            QtWidgets.QMessageBox.StandardButton.Cancel,
        )
        if confirmation != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        self.progress.setValue(0)
        self.write_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.refresh_button.setEnabled(False)
        self.drive_combo.setEnabled(False)
        self.image_edit.setEnabled(False)
        self._log(f"Starting write: {Path(image).name} → {drive.device}")
        self.worker = WriteWorker(image, drive, self.system)
        self.worker.status.connect(self._log)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.completed.connect(self._write_finished)
        self.worker.start()

    def cancel_write(self) -> None:
        if not self.worker or not self.worker.isRunning():
            return
        self.cancel_button.setEnabled(False)
        self._log("Cancellation requested. Stopping at the next safe interruption point…")
        self.worker.request_cancel()

    @QtCore.Slot(bool, bool, str)
    def _write_finished(self, success: bool, cancelled: bool, message: str) -> None:
        self.write_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        self.drive_combo.setEnabled(True)
        self.image_edit.setEnabled(True)
        self._log(message)
        if success:
            QtWidgets.QMessageBox.information(self, APP_NAME, message)
        elif cancelled:
            QtWidgets.QMessageBox.warning(self, APP_NAME, message)
        else:
            QtWidgets.QMessageBox.critical(self, APP_NAME, f"Write failed:\n{message}\n\nLog: {LOG_PATH}")
        self.worker = None
        self.refresh_drives()

    @QtCore.Slot(str)
    def _log(self, message: str) -> None:
        self.status.appendPlainText(message)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.worker and self.worker.isRunning():
            answer = QtWidgets.QMessageBox.warning(
                self,
                "Write in progress",
                "A USB operation is still running. Cancel it before closing Boot It.",
                QtWidgets.QMessageBox.StandardButton.Ok,
            )
            del answer
            event.ignore()
            return
        super().closeEvent(event)


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv
    app = QtWidgets.QApplication(args)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    window = BootItWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
