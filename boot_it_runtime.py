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
from boot_it_openpgp import (
    OpenPGPVerification,
    find_gpg,
    verify_cleartext_manifest,
    verify_detached_manifest,
)
from boot_it_provenance import (
    ProvenanceResult,
    verify_sha256_manifest,
    verify_sha256_manifest_text,
)


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

    def auth_mode(self) -> str:
        if not hasattr(self, "auth_mode_combo"):
            return "none"
        return str(self.auth_mode_combo.currentData() or "none")

    def clear_verification_state(self) -> None:
        self._boot_it_provenance_result = None
        self._boot_it_openpgp_result = None

    def clear_provenance(self) -> None:
        clear_verification_state(self)
        self._boot_it_image_digest = ""
        self._boot_it_image_stat = None
        if hasattr(self, "provenance_status"):
            self.provenance_status.setText(
                "Checksum: not verified. Select a manifest to establish filename-bound provenance."
            )
        if hasattr(self, "auth_status"):
            self.auth_status.setText("Authenticity: not verified.")

    def manifest_changed(self, _text: str) -> None:
        clear_verification_state(self)
        if hasattr(self, "provenance_status"):
            self.provenance_status.setText(
                "Checksum: manifest selected; waiting for verification."
                if self.provenance_edit.text().strip()
                else "Checksum: optional. Select an official SHA-256 manifest to compare."
            )
        if hasattr(self, "auth_status") and auth_mode(self) != "none":
            self.auth_status.setText("Authenticity: configuration changed; re-verification required.")

    def auth_config_changed(self, *_args) -> None:
        clear_verification_state(self)
        mode = auth_mode(self)
        if hasattr(self, "signature_edit"):
            detached = mode == "detached"
            self.signature_edit.setEnabled(detached)
            self.signature_browse_button.setEnabled(detached)
        if hasattr(self, "auth_status"):
            if mode == "none":
                self.auth_status.setText(
                    "Authenticity: disabled. A checksum match alone does not authenticate the publisher."
                )
            else:
                self.auth_status.setText("Authenticity: configuration changed; verification required.")

    def browse_manifest(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select checksum manifest",
            "",
            "Checksum manifests (*.sha256 *.sha256sum *.checksums *.txt *.asc);;All files (*)",
        )
        if path:
            self.provenance_edit.setText(path)

    def browse_public_key(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select publisher OpenPGP public key",
            "",
            "OpenPGP public keys (*.asc *.gpg *.pgp);;All files (*)",
        )
        if path:
            self.public_key_edit.setText(path)

    def browse_signature(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select detached OpenPGP signature",
            "",
            "OpenPGP signatures (*.asc *.sig *.gpg);;All files (*)",
        )
        if path:
            self.signature_edit.setText(path)

    def render_result(self, result: ProvenanceResult) -> None:
        self._boot_it_provenance_result = result
        authenticated = result.authenticity == "openpgp_verified"
        if result.status == "verified":
            text = (
                "Checksum: MATCH. Manifest authenticity is cryptographically verified."
                if authenticated
                else "Checksum: MATCH with selected manifest. Manifest authenticity is not independently verified."
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

    def render_auth_result(self, result: OpenPGPVerification) -> None:
        self._boot_it_openpgp_result = result
        self.auth_status.setText(
            f"Authenticity: VERIFIED {result.mode} OpenPGP signature by pinned fingerprint "
            f"{result.signer_fingerprint}."
        )
        self.auth_status.setToolTip(result.message)

    def authenticate_manifest(self) -> OpenPGPVerification:
        mode = auth_mode(self)
        if mode == "none":
            raise ValueError("OpenPGP authenticity mode is disabled.")
        manifest = self.provenance_edit.text().strip()
        public_key = self.public_key_edit.text().strip()
        fingerprint = self.fingerprint_edit.text().strip()
        if not manifest:
            raise ValueError("Select the checksum manifest first.")
        if not public_key:
            raise ValueError("Select the publisher OpenPGP public key.")
        if not fingerprint:
            raise ValueError("Enter the publisher's full trusted OpenPGP fingerprint.")

        gpg = find_gpg()
        if mode == "detached":
            signature = self.signature_edit.text().strip()
            if not signature:
                raise ValueError("Select the detached OpenPGP signature file.")
            result = verify_detached_manifest(
                manifest,
                signature,
                public_key,
                fingerprint,
                gpg_path=gpg,
            )
        elif mode == "cleartext":
            result = verify_cleartext_manifest(
                manifest,
                public_key,
                fingerprint,
                gpg_path=gpg,
            )
        else:
            raise ValueError(f"Unsupported authenticity mode: {mode}")
        render_auth_result(self, result)
        return result

    def verify_selected_manifest(self) -> ProvenanceResult:
        image = self.image_edit.text().strip()
        manifest = self.provenance_edit.text().strip()
        if not manifest:
            raise ValueError("Select a checksum manifest first.")
        valid, reason = core.validate_image(image)
        if not valid:
            raise ValueError(f"Image is not ready for verification: {reason}")
        digest = getattr(self, "_boot_it_image_digest", "")
        if not digest:
            raise ValueError("Wait for the image SHA-256 calculation to finish.")

        mode = auth_mode(self)
        if mode == "none":
            result = verify_sha256_manifest(image, manifest, actual_digest=digest)
        else:
            auth_result = authenticate_manifest(self)
            result = verify_sha256_manifest_text(
                image,
                auth_result.plaintext,
                manifest_label=manifest,
                actual_digest=digest,
                authenticity="openpgp_verified",
            )
        render_result(self, result)
        return result

    def verify_manifest(self) -> None:
        clear_verification_state(self)
        try:
            verify_selected_manifest(self)
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            self.provenance_status.setText(f"Checksum/provenance verification failed: {exc}")
            if auth_mode(self) != "none":
                self.auth_status.setText(f"Authenticity: verification failed: {exc}")

    def build_ui(self) -> None:
        original_build_ui(self)
        self._boot_it_image_digest = ""
        self._boot_it_image_stat = None
        self._boot_it_provenance_result = None
        self._boot_it_openpgp_result = None

        group = core.QtWidgets.QGroupBox("Image provenance and publisher authenticity")
        group_layout = core.QtWidgets.QVBoxLayout(group)

        manifest_picker = core.QtWidgets.QHBoxLayout()
        self.provenance_edit = core.QtWidgets.QLineEdit()
        self.provenance_edit.setPlaceholderText("Select publisher SHA256SUMS / CHECKSUM manifest")
        manifest_picker.addWidget(self.provenance_edit, 1)
        browse_button = core.QtWidgets.QPushButton("Manifest…")
        verify_button = core.QtWidgets.QPushButton("Verify")
        manifest_picker.addWidget(browse_button)
        manifest_picker.addWidget(verify_button)
        group_layout.addLayout(manifest_picker)

        self.provenance_status = core.QtWidgets.QLabel(
            "Checksum: optional. Select an official SHA-256 manifest to compare."
        )
        self.provenance_status.setWordWrap(True)
        group_layout.addWidget(self.provenance_status)

        auth_row = core.QtWidgets.QHBoxLayout()
        self.auth_mode_combo = core.QtWidgets.QComboBox()
        self.auth_mode_combo.addItem("Checksum only", "none")
        self.auth_mode_combo.addItem("OpenPGP detached signature", "detached")
        self.auth_mode_combo.addItem("OpenPGP cleartext-signed manifest", "cleartext")
        auth_row.addWidget(self.auth_mode_combo)
        self.public_key_edit = core.QtWidgets.QLineEdit()
        self.public_key_edit.setPlaceholderText("Publisher public key (.asc/.gpg)")
        auth_row.addWidget(self.public_key_edit, 1)
        key_button = core.QtWidgets.QPushButton("Key…")
        auth_row.addWidget(key_button)
        group_layout.addLayout(auth_row)

        signature_row = core.QtWidgets.QHBoxLayout()
        self.signature_edit = core.QtWidgets.QLineEdit()
        self.signature_edit.setPlaceholderText("Detached signature (.gpg/.sig/.asc)")
        self.signature_edit.setEnabled(False)
        signature_row.addWidget(self.signature_edit, 1)
        self.signature_browse_button = core.QtWidgets.QPushButton("Signature…")
        self.signature_browse_button.setEnabled(False)
        signature_row.addWidget(self.signature_browse_button)
        self.fingerprint_edit = core.QtWidgets.QLineEdit()
        self.fingerprint_edit.setPlaceholderText("Trusted full OpenPGP fingerprint")
        signature_row.addWidget(self.fingerprint_edit, 1)
        group_layout.addLayout(signature_row)

        self.auth_status = core.QtWidgets.QLabel(
            "Authenticity: disabled. A checksum match alone does not authenticate the publisher."
        )
        self.auth_status.setWordWrap(True)
        group_layout.addWidget(self.auth_status)

        root = self.layout()
        write_index = root.indexOf(self.write_button)
        root.insertWidget(write_index if write_index >= 0 else root.count(), group)

        browse_button.clicked.connect(self._boot_it_browse_manifest)
        verify_button.clicked.connect(self._boot_it_verify_manifest)
        key_button.clicked.connect(self._boot_it_browse_public_key)
        self.signature_browse_button.clicked.connect(self._boot_it_browse_signature)
        self.provenance_edit.textChanged.connect(self._boot_it_manifest_changed)
        self.image_edit.textChanged.connect(self._boot_it_clear_provenance)
        self.auth_mode_combo.currentIndexChanged.connect(self._boot_it_auth_config_changed)
        self.public_key_edit.textChanged.connect(self._boot_it_auth_config_changed)
        self.signature_edit.textChanged.connect(self._boot_it_auth_config_changed)
        self.fingerprint_edit.textChanged.connect(self._boot_it_auth_config_changed)

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
            self.provenance_status.setText("Checksum: SHA-256 ready; press Verify to evaluate provenance.")
            if auth_mode(self) != "none":
                self.auth_status.setText("Authenticity: SHA-256 ready; press Verify to authenticate manifest.")

    def start_write(self) -> None:
        manifest = self.provenance_edit.text().strip() if hasattr(self, "provenance_edit") else ""
        mode = auth_mode(self)
        if mode != "none" and not manifest:
            core.QtWidgets.QMessageBox.critical(
                self,
                core.APP_NAME,
                "OpenPGP authenticity verification is enabled but no checksum manifest is selected.",
            )
            return
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
                    "The image changed or has not finished hashing. Wait for SHA-256 to finish, then verify again.",
                )
                return
            try:
                result = verify_selected_manifest(self)
            except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    f"Image provenance/authenticity gate blocked this write:\n\n{exc}",
                )
                return
            if not result.is_match:
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    f"Checksum provenance gate blocked this write:\n\n{result.message}",
                )
                return
            if mode != "none" and result.authenticity != "openpgp_verified":
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    "OpenPGP authenticity was requested but did not reach the verified state.",
                )
                return
        original_start_write(self)

    window_type._boot_it_clear_provenance = clear_provenance
    window_type._boot_it_manifest_changed = manifest_changed
    window_type._boot_it_auth_config_changed = auth_config_changed
    window_type._boot_it_browse_manifest = browse_manifest
    window_type._boot_it_browse_public_key = browse_public_key
    window_type._boot_it_browse_signature = browse_signature
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
