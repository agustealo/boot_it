from __future__ import annotations

import pytest

from scripts.windows_authenticode import normalize_thumbprint, signing_config_from_values


def test_empty_authenticode_configuration_is_disabled() -> None:
    config = signing_config_from_values("", "", "", "")
    assert config.enabled is False


def test_partial_authenticode_configuration_fails_closed() -> None:
    with pytest.raises(ValueError, match="partially configured"):
        signing_config_from_values("ZmFrZQ==", "secret", "", "https://timestamp.example.test")


def test_authenticode_configuration_requires_https_timestamp() -> None:
    with pytest.raises(ValueError, match="must use HTTPS"):
        signing_config_from_values(
            "ZmFrZQ==",
            "secret",
            "0123456789abcdef0123456789abcdef01234567",
            "http://timestamp.example.test",
        )


def test_authenticode_configuration_normalizes_full_thumbprint() -> None:
    config = signing_config_from_values(
        "ZmFrZQ==",
        "secret",
        "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67",
        "https://timestamp.example.test",
    )
    assert config.enabled is True
    assert config.expected_thumbprint == "0123456789ABCDEF0123456789ABCDEF01234567"


def test_short_certificate_identifier_is_rejected() -> None:
    with pytest.raises(ValueError, match="full 40-hex"):
        normalize_thumbprint("DEADBEEF")
