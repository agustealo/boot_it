from __future__ import annotations

from pathlib import Path
from types import ModuleType

from boot_it_openpgp import verify_cleartext_manifest, verify_detached_manifest


def install_openpgp_authenticity(core: ModuleType) -> None:
    """Layer optional OpenPGP authentication over checksum provenance."""
    window_type = getattr(core, "BootItWindow", None)
    if window_type is None:
        return

    if not hasattr(window_type, "_boot_it_auth_original_build_ui"):
        window_type._boot_it_auth_original_build_ui = window_type._build_ui
    original_build_ui = window_type._boot_it_auth_original_build_ui

    if not hasattr(window_type, "_boot_it_auth_original_start_write"):
        window_type._boot_it_auth_original_start_write = window_type.start_write
    original_start_write = window_type._boot_it_auth_original_start_write

    def clear_auth(self, *_args) -> None:
        self._boot_it_openpgp_result = None
        if hasattr(self, "auth_status"):
            self.auth_status.setText(
                "OpenPGP: optional. A valid signature must match the explicitly pinned fingerprint."
            )
            self.auth_status.setToolTip("")

    def set_mode_state(self) -> None:
        cleartext = self.auth_mode.currentData() == "cleartext"
        self.auth_signature_edit.setEnabled(not cleartext)
        self.auth_signature_button.setEnabled(not cleartext)
        self.auth_signature_edit.setPlaceholderText(
            "Not used for cleartext-signed manifests"
            if cleartext
            else "Select detached .gpg/.sig signature"
        )
        clear_auth(self)

    def browse_signature(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select OpenPGP signature",
            "",
            "OpenPGP signatures (*.gpg *.sig *.asc);;All files (*)",
        )
        if path:
            self.auth_signature_edit.setText(path)

    def browse_key(self) -> None:
        path, _ = core.QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select OpenPGP public key",
            "",
            "OpenPGP public keys (*.asc *.pgp *.gpg);;All files (*)",
        )
        if path:
            self.auth_key_edit.setText(path)

    def auth_requested(self) -> bool:
        values = [
            self.auth_signature_edit.text().strip(),
            self.auth_key_edit.text().strip(),
            self.auth_fingerprint_edit.text().strip(),
        ]
        return any(values)

    def authenticate(self) -> bool:
        manifest = self.provenance_edit.text().strip() if hasattr(self, "provenance_edit") else ""
        key_path = self.auth_key_edit.text().strip()
        fingerprint = self.auth_fingerprint_edit.text().strip()
        mode = self.auth_mode.currentData()
        signature = self.auth_signature_edit.text().strip()

        if not manifest:
            self.auth_status.setText("OpenPGP: select a checksum manifest first.")
            self._boot_it_openpgp_result = None
            return False
        if not key_path or not fingerprint:
            self.auth_status.setText("OpenPGP: public key and full trusted fingerprint are required.")
            self._boot_it_openpgp_result = None
            return False
        if mode == "detached" and not signature:
            self.auth_status.setText("OpenPGP: detached-signature mode requires a signature file.")
            self._boot_it_openpgp_result = None
            return False

        # First require the selected image to match the selected checksum
        # content. Authenticating a manifest that does not describe the image
        # must never produce a green authenticity state.
        self._boot_it_verify_manifest()
        provenance = getattr(self, "_boot_it_provenance_result", None)
        if provenance is None or not provenance.is_match:
            self.auth_status.setText(
                "OpenPGP: checksum manifest does not currently verify the selected image."
            )
            self._boot_it_openpgp_result = None
            return False

        try:
            if mode == "cleartext":
                result = verify_cleartext_manifest(manifest, key_path, fingerprint)
            else:
                result = verify_detached_manifest(manifest, signature, key_path, fingerprint)
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            self._boot_it_openpgp_result = None
            self.auth_status.setText(f"OpenPGP: authentication failed: {exc}")
            return False

        self._boot_it_openpgp_result = result
        self.auth_status.setText(
            "OpenPGP: AUTHENTICATED manifest under pinned fingerprint "
            f"{result.trusted_fingerprint}."
        )
        self.auth_status.setToolTip(
            "The signature is cryptographically valid under the explicitly supplied fingerprint. "
            "Boot It does not decide where you obtained or trusted that fingerprint."
        )
        return True

    def build_ui(self) -> None:
        original_build_ui(self)
        self._boot_it_openpgp_result = None

        group = core.QtWidgets.QGroupBox("OpenPGP manifest authenticity (optional)")
        layout = core.QtWidgets.QVBoxLayout(group)

        mode_row = core.QtWidgets.QHBoxLayout()
        mode_row.addWidget(core.QtWidgets.QLabel("Signature format:"))
        self.auth_mode = core.QtWidgets.QComboBox()
        self.auth_mode.addItem("Detached signature", "detached")
        self.auth_mode.addItem("Cleartext-signed manifest", "cleartext")
        mode_row.addWidget(self.auth_mode, 1)
        layout.addLayout(mode_row)

        signature_row = core.QtWidgets.QHBoxLayout()
        self.auth_signature_edit = core.QtWidgets.QLineEdit()
        self.auth_signature_edit.setPlaceholderText("Select detached .gpg/.sig signature")
        self.auth_signature_button = core.QtWidgets.QPushButton("Signature…")
        signature_row.addWidget(self.auth_signature_edit, 1)
        signature_row.addWidget(self.auth_signature_button)
        layout.addLayout(signature_row)

        key_row = core.QtWidgets.QHBoxLayout()
        self.auth_key_edit = core.QtWidgets.QLineEdit()
        self.auth_key_edit.setPlaceholderText("Select publisher OpenPGP public key / certificate")
        key_button = core.QtWidgets.QPushButton("Public key…")
        key_row.addWidget(self.auth_key_edit, 1)
        key_row.addWidget(key_button)
        layout.addLayout(key_row)

        fingerprint_row = core.QtWidgets.QHBoxLayout()
        self.auth_fingerprint_edit = core.QtWidgets.QLineEdit()
        self.auth_fingerprint_edit.setPlaceholderText("Full trusted fingerprint, 40 or 64 hex characters")
        authenticate_button = core.QtWidgets.QPushButton("Authenticate")
        fingerprint_row.addWidget(self.auth_fingerprint_edit, 1)
        fingerprint_row.addWidget(authenticate_button)
        layout.addLayout(fingerprint_row)

        self.auth_status = core.QtWidgets.QLabel(
            "OpenPGP: optional. A valid signature must match the explicitly pinned fingerprint."
        )
        self.auth_status.setWordWrap(True)
        layout.addWidget(self.auth_status)

        root = self.layout()
        write_index = root.indexOf(self.write_button)
        root.insertWidget(write_index if write_index >= 0 else root.count(), group)

        self.auth_mode.currentIndexChanged.connect(self._boot_it_auth_mode_changed)
        self.auth_signature_button.clicked.connect(self._boot_it_browse_signature)
        key_button.clicked.connect(self._boot_it_browse_key)
        authenticate_button.clicked.connect(self._boot_it_authenticate)
        self.auth_signature_edit.textChanged.connect(self._boot_it_clear_auth)
        self.auth_key_edit.textChanged.connect(self._boot_it_clear_auth)
        self.auth_fingerprint_edit.textChanged.connect(self._boot_it_clear_auth)
        self.provenance_edit.textChanged.connect(self._boot_it_clear_auth)
        self.image_edit.textChanged.connect(self._boot_it_clear_auth)
        set_mode_state(self)

    def start_write(self) -> None:
        if auth_requested(self):
            mode = self.auth_mode.currentData()
            complete = bool(
                self.auth_key_edit.text().strip()
                and self.auth_fingerprint_edit.text().strip()
                and (mode == "cleartext" or self.auth_signature_edit.text().strip())
            )
            if not complete:
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    "OpenPGP authentication is partially configured. Complete it or clear those fields before writing.",
                )
                return
            if not authenticate(self):
                core.QtWidgets.QMessageBox.critical(
                    self,
                    core.APP_NAME,
                    "OpenPGP authenticity verification failed. The write is blocked.",
                )
                return
        original_start_write(self)

    window_type._boot_it_clear_auth = clear_auth
    window_type._boot_it_auth_mode_changed = set_mode_state
    window_type._boot_it_browse_signature = browse_signature
    window_type._boot_it_browse_key = browse_key
    window_type._boot_it_authenticate = authenticate
    window_type._build_ui = build_ui
    window_type.start_write = start_write
