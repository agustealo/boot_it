from __future__ import annotations

import re

import pytest

from boot_it_publishers import PROFILES, get_profile, profile_ids


FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}(?:[0-9A-F]{24})?$")


def test_publisher_profile_ids_are_unique() -> None:
    ids = profile_ids()
    assert len(ids) == len(set(ids))
    assert len(ids) == len(PROFILES)


def test_publisher_profile_fingerprints_are_full_and_unique() -> None:
    fingerprints = [profile.trusted_fingerprint for profile in PROFILES]
    assert all(FINGERPRINT_RE.fullmatch(value) for value in fingerprints)
    assert len(fingerprints) == len(set(fingerprints))


def test_profiles_use_supported_signature_modes() -> None:
    assert {profile.mode for profile in PROFILES} <= {"detached", "cleartext"}


def test_profiles_point_to_https_publisher_verification_sources() -> None:
    for profile in PROFILES:
        assert profile.key_source.startswith("https://")
        assert profile.verification_source.startswith("https://")
        assert any(
            domain in profile.verification_source
            for domain in ("ubuntu.com", "fedoraproject.org", "debian.org")
        )


def test_expected_current_profiles_are_present() -> None:
    assert get_profile("fedora-44").trusted_fingerprint == "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6"
    assert get_profile("fedora-45").trusted_fingerprint == "4F50A6114CD5C6976A7F1179655A4B02F577861E"
    assert get_profile("ubuntu-release-iso-2012").mode == "detached"
    assert get_profile("ubuntu-cloud-images").trusted_fingerprint == "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
    assert get_profile("debian-testing-cd").mode == "detached"


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(KeyError, match="Unknown publisher profile"):
        get_profile("not-a-real-publisher")
