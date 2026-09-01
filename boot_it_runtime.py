from __future__ import annotations

import os
import re
import struct
import subprocess
import time
import threading
from pathlib import Path
from types import ModuleType
from typing import Callable

from boot_it_image import inspect_image
from boot_it_provenance import ProvenanceResult, verify_sha256_manifest


def _fixed_linux_write(
    core: ModuleType,
    image: str,
    device: str,
    progress_callback: Callable[[int, int], None],
    cancel_event: threading.Event,
) -> None:
    """Run dd with a binary nonblocking stderr reader safe on Python 3.10+."""
    command = core._dd_command(image, device)
    total = Path(image).stat().st_size
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        start_new_session=True,
    )
    assert process.stderr is not None
    stderr_fd = process.stderr.fileno()
    os.set_blocking(stderr_fd, False)
    buffered = b""

    def consume(chunk: bytes) -> None:
        nonlocal buffered
        if not chunk:
            return
        buffered += chunk
        matches = re.findall(rb"(\d+)\s+bytes", buffered)
        if matches:
            progress_callback(int(matches[-1]), total)
        buffered = buffered[-512:]

    try:
        while process.poll() is None:
            if cancel_event.is_set():
                core._terminate_process_group(process)
                raise core.OperationCancelled(
                    "Write cancelled. The USB contains a partial image and must be rewritten before use."
                )
            try:
                consume(os.read(stderr_fd, 65536))
            except BlockingIOError:
                pass
            time.sleep(0.05)

        while True:
            try:
                chunk = os.read(stderr_fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            consume(chunk)

        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
    finally:
        if process.poll() is None:
            core._terminate_process_group(process)


def _install_image_intelligence(core: ModuleType) -> None:
    if not hasattr(core, "_boot_it_original_validate_image"):
        core._boot_it_original_validate_image = core.validate_image
    original_validate = core._boot_it_original_validate_image

    def validate_image(path: str) -> tuple[bool, str]:
        valid, reason = original_validate(path)
        if not valid:
            return valid, reason
        try:
            inspection = inspect_image(path)
        except (OSError, ValueError, struct.error) as exc:
            return False, f"Unable to inspect image structure: {exc}"
        if inspection.fatal_reason:
            return False, f"Image structure check failed: {inspection.fatal_reason}"
        return True, ""

    core.validate_image = validate_image

    window_type = getattr(core, "BootItWindow", None)
    if window_type is None:
        return
    if not hasattr(window_type, "_boot_it_original_hash_ready"):
        window_type._boot_it_original_hash_ready = window_type._hash_ready
    original_hash_ready = window_type._boot_it_original_hash_ready

    def hash_ready(self, path: str, digest: str) -> None:
        original_hash_ready(self, path, digest)
        if path != self.image_edit.text():
            return
        try:
            inspection = inspect_image(path)
        except (OSError, ValueError, struct.error):
            return
        digest_text = digest or "unavailable"
        self.hash_label.setText(f"SHA-256: {digest_text}\nImage: {inspection.summary}")
        self.hash_label.setToolTip(inspection.warning)

    window_type._hash_ready = hash_ready


def _install_checksum_provenance(core: ModuleType) -> None:
    window_type = getattr(core, "BootItWindow", None)
    if window_type is None:
        return

    if not hasattr(window_type, "_boot_it_provenance_original_build_ui"):
        window_type._boot_it_provenance_original_build_ui = window_type._build_ui
    original_build_ui = window_type._boot_it_provenance_original_build_ui

    if not hasattr(window_type, "_boot_it_provenance_original_hash_ready"):
        window_type._boot_it_provenance_original_hash_ready = window_type._hash_ready
    original_hash_ready = window_type._boot_it_provenance_original_hash_ready

    if not hasattr(window_type, "_boot_it_provenance_original_start_write"):
        window_type._boot_it_provenance_original_start_write = window_type.start_write
    original_start_write = window_type._boot_it_provenance_original_start_write

    def clear_provenance(self) -> None:
        self._boot_it_provenance_result = None
        self._boot_it_image_digest = ""
        self._boot_it_image_stat = None
        if hasattr(self, "provenance_status"):
            self.provenance_status.setText(
                "Checksum: not verified. A manifest match does not authenticate the manifest itself."
            )

    def manifest_changed(self, _text: str) -> None:
        self._boot_it_provenance_result = None
        if hasattr(self, "provenance_status"):
            self.provenance_status.setText(
                "Checksum: manifest selected; waiting for verification."
                if self.provenance_edit.text().strip()
                else "Checksum: optional. Select an official SHA-256 manifest to compare."
            )

    def browse_manifest(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select SHA-256 checksum manifest",
            "",
            "Checksum manifests (*.sha256 *.sha256sum *.checksums *.txt);;All files (*)",
        )
        if path:
            self.provenance_edit.setText(path)
            verify_manifest(self)

    def render_result(self, result: ProvenanceResult) -> None:
        self._boot_it_provenance_result = result
        if result.status == "verified":
            text = (
                "Checksum: MATCH with selected manifest. "
                "Manifest authenticity is not independently verified."
            )
        elif result.status == "mismatch":
            text = "Checksum: MISMATCH. Writing is blocked while this manifest is selected."
        elif result.status == "ambiguous":
            text = "Checksum: AMBIGUOUS manifest entries. Writing is blocked."
        elif result.status == "not_listed":
            text = "Checksum: image filename is not listed in the selected manifest. Writing is blocked."
        else:
            text = f"Checksum: {result.status}. {result.message}"
        self.provenance_status.setText(text)
        self.provenance_status.setToolTip(result.message)

    def verify_manifest(self) -> None:
        image = self.image_edit.text().strip()
        manifest = self.provenance_edit.text().strip()
        if not manifest:
            self._boot_it_provenance_result = None
            self.provenance_status.setText(
                "Checksum: optional. Select an official SHA-256 manifest to compare."
            )
            return
        valid, reason = core.validate_image(image)
        if not valid:
            self._boot_it_provenance_result = None
            self.provenance_status.setText(f"Checksum: image is not ready for verification: {reason}")
            return
        digest = getattr(self, "_boot_it_image_digest", "")
        if not digest:
            self._boot_it_provenance_result = None
            self.provenance_status.setText("Checksum: waiting for the image SHA-256 calculation to finish.")
            return
        try:
            result = verify_sha256_manifest(image, manifest, actual_digest=digest)
        except (OSError, UnicodeError, ValueError) as exc:
            self._boot_it_provenance_result = None
            self.provenance_status.setText(f"Checksum: manifest error: {exc}")
            return
        render_result(self, result)

    def build_ui(self) -> None:
        original_build_ui(self)
        self._boot_it_image_digest = ""
        self._boot_it_image_stat = None
        self._boot_it_provenance_result = None

        group = core.QtWidgets.QGroupBox("Checksum provenance (optional)")
        group_layout = core.QtWidgets.QVBoxLayout(group)
        picker = core.QtWidgets.QHBoxLayout()
        self.provenance_edit = core.QtWidgets.QLineEdit()
        self.provenance_edit.setPlaceholderText("Select publisher SHA256SUMS / checksum manifest")
        picker.addWidget(self.provenance_edit, 1)
        browse_button = core.QtWidgets.QPushButton("Browse…")
        verify_button = core.QtWidgets.QPushButton("Verify")
        picker.addWidget(browse_button)
        picker.addWidget(verify_button)
        group_layout.addLayout(picker)
        self.provenance_status = core.QtWidgets.QLabel(
            "Checksum: optional. Select an official SHA-256 manifest to compare."
        )
        self.provenance_status.setWordWrap(True)
        group_layout.addWidget(self.provenance_status)

        root = self.layout()
        write_index = root.indexOf(self.write_button)
        root.insertWidget(write_index if write_index >= 0 else root.count(), group)

        browse_button.clicked.connect(self._boot_it_browse_manifest)
        verify_button.clicked.connect(self._boot_it_verify_manifest)
        self.provenance_edit.textChanged.connect(self._boot_it_manifest_changed)
        self.image_edit.textChanged.connect(self._boot_it_clear_provenance)

    def hash_ready(self, path: str, digest: str) -> None:
        original_hash_ready(self, path, digest)
        if path != self.image_edit.text():
            return
        self._boot_it_image_digest = digest or ""
        try:
            stat = Path(path).stat()
            self._boot_it_image_stat = (stat.st_size, stat.st_mtime_ns)
        except OSError:
            self._boot_it_image_stat = None
        if hasattr(self, "provenance_edit") and self.provenance_edit.text().strip():
            verify_manifest(self)

    def start_write(self) -> None:
        manifest = self.provenance_edit.text().strip() if hasattr(self, "provenance_edit") else ""
        if manifest:
            image = self.image_edit.text().strip()
            digest = getattr(self, "_boot_it_image_digest", "")
            fingerprint = getattr(self, "_boot_it_image_stat", None)
            try:
                stat = Path(image).stat()
                current_fingerprint = (stat.st_size, stat.st_mtime_ns)
            except OSError as exc:
                core.QtWidgets.QMessageBox.critical(self, core.APP_NAME, f"Image is no longer readable: {exc}")
                return
            if not digest or fingerprint != current_fingerprint:
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    "The image changed or has not finished hashing. Wait for SHA-256 to finish, then verify the manifest again.",
                )
                return
            try:
                result = verify_sha256_manifest(image, manifest, actual_digest=digest)
            except (OSError, UnicodeError, ValueError) as exc:
                core.QtWidgets.QMessageBox.critical(self, core.APP_NAME, f"Checksum manifest cannot be verified: {exc}")
                return
            render_result(self, result)
            if not result.is_match:
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    f"Checksum provenance gate blocked this write:\n\n{result.message}",
                )
                return
        original_start_write(self)

    window_type._boot_it_clear_provenance = clear_provenance
    window_type._boot_it_manifest_changed = manifest_changed
    window_type._boot_it_browse_manifest = browse_manifest
    window_type._boot_it_verify_manifest = verify_manifest
    window_type._build_ui = build_ui
    window_type._hash_ready = hash_ready
    window_type.start_write = start_write


def install_runtime_patches(core: ModuleType) -> None:
    """Install mandatory runtime hardening before the GUI starts."""

    def linux_write(
        image: str,
        device: str,
        progress_callback: Callable[[int, int], None],
        cancel_event: threading.Event,
    ) -> None:
        _fixed_linux_write(core, image, device, progress_callback, cancel_event)

    core.linux_write = linux_write
    _install_image_intelligence(core)
    _install_checksum_provenance(core)
