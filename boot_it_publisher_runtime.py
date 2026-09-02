from __future__ import annotations

from types import ModuleType

from boot_it_publishers import PROFILES, PublisherProfile, get_profile


def install_publisher_profiles(core: ModuleType) -> None:
    """Add audited publisher presets without downloading or trusting keys implicitly."""
    window_type = getattr(core, "BootItWindow", None)
    if window_type is None:
        return

    if not hasattr(window_type, "_boot_it_publishers_original_build_ui"):
        window_type._boot_it_publishers_original_build_ui = window_type._build_ui
    original_build_ui = window_type._boot_it_publishers_original_build_ui

    def selected_profile(self) -> PublisherProfile | None:
        if not hasattr(self, "publisher_profile_combo"):
            return None
        profile_id = str(self.publisher_profile_combo.currentData() or "")
        if not profile_id:
            return None
        return get_profile(profile_id)

    def apply_profile(self, *_args) -> None:
        profile = selected_profile(self)
        if profile is None:
            self.publisher_profile_status.setText(
                "Publisher profile: Custom/manual. You control signature mode and trusted fingerprint."
            )
            self.publisher_profile_status.setToolTip("")
            return

        mode_index = self.auth_mode.findData(profile.mode)
        if mode_index < 0:
            self.publisher_profile_status.setText(
                f"Publisher profile error: unsupported signature mode {profile.mode!r}."
            )
            return

        # Profiles pin metadata only. They never download, import, or choose a
        # public key on the user's behalf.
        self.auth_mode.setCurrentIndex(mode_index)
        self.auth_fingerprint_edit.setText(profile.trusted_fingerprint)
        self.publisher_profile_status.setText(
            f"Publisher profile: {profile.label}. Fingerprint pinned from publisher-maintained verification docs. "
            "Select the publisher public-key file locally before authentication."
        )
        self.publisher_profile_status.setToolTip(
            f"Publisher: {profile.publisher}\n"
            f"Fingerprint: {profile.trusted_fingerprint}\n"
            f"Key source: {profile.key_source}\n"
            f"Verification source: {profile.verification_source}\n"
            f"{profile.notes}"
        )
        if hasattr(self, "auth_status"):
            self.auth_status.setText(
                "OpenPGP: publisher profile selected; public key and signature/checksum files still require local selection."
            )

    def build_ui(self) -> None:
        original_build_ui(self)

        group = core.QtWidgets.QGroupBox("Trusted publisher profile")
        layout = core.QtWidgets.QVBoxLayout(group)
        row = core.QtWidgets.QHBoxLayout()
        row.addWidget(core.QtWidgets.QLabel("Publisher:"))
        self.publisher_profile_combo = core.QtWidgets.QComboBox()
        self.publisher_profile_combo.addItem("Custom / manual", "")
        for profile in PROFILES:
            self.publisher_profile_combo.addItem(profile.label, profile.profile_id)
        row.addWidget(self.publisher_profile_combo, 1)
        layout.addLayout(row)

        self.publisher_profile_status = core.QtWidgets.QLabel(
            "Publisher profile: Custom/manual. You control signature mode and trusted fingerprint."
        )
        self.publisher_profile_status.setWordWrap(True)
        layout.addWidget(self.publisher_profile_status)

        root = self.layout()
        write_index = root.indexOf(self.write_button)
        root.insertWidget(write_index if write_index >= 0 else root.count(), group)
        self.publisher_profile_combo.currentIndexChanged.connect(self._boot_it_apply_publisher_profile)

    window_type._boot_it_selected_publisher_profile = selected_profile
    window_type._boot_it_apply_publisher_profile = apply_profile
    window_type._build_ui = build_ui
