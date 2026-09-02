from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PublisherProfile:
    profile_id: str
    label: str
    publisher: str
    mode: str
    trusted_fingerprint: str
    key_source: str
    verification_source: str
    notes: str = ""


# Fingerprints are intentionally sourced from publisher-maintained verification
# documentation, not keyserver search results. Profiles do not download keys and
# never replace the user's explicitly supplied public-key file.
PROFILES: tuple[PublisherProfile, ...] = (
    PublisherProfile(
        profile_id="ubuntu-release-iso-2012",
        label="Ubuntu release ISO (2012 signing key)",
        publisher="Canonical / Ubuntu",
        mode="detached",
        trusted_fingerprint="843938DF228D22F7B3742BC0D94AA3F0EFE21092",
        key_source="https://keyserver.ubuntu.com/",
        verification_source="https://ubuntu.com/tutorials/how-to-verify-ubuntu",
        notes="For SHA256SUMS + SHA256SUMS.gpg release-image verification.",
    ),
    PublisherProfile(
        profile_id="ubuntu-release-iso-legacy",
        label="Ubuntu release ISO (legacy signing key)",
        publisher="Canonical / Ubuntu",
        mode="detached",
        trusted_fingerprint="C5986B4F1257FFA86632CBA746181433FBB75451",
        key_source="https://keyserver.ubuntu.com/",
        verification_source="https://ubuntu.com/tutorials/how-to-verify-ubuntu",
        notes="Legacy Ubuntu CD Image Automatic Signing Key still documented by Ubuntu.",
    ),
    PublisherProfile(
        profile_id="ubuntu-cloud-images",
        label="Ubuntu cloud images",
        publisher="Canonical / Ubuntu",
        mode="detached",
        trusted_fingerprint="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
        key_source="https://keyserver.ubuntu.com/",
        verification_source="https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/",
        notes="UEC Image Automatic Signing Key used by Ubuntu public/cloud images.",
    ),
    PublisherProfile(
        profile_id="fedora-45",
        label="Fedora 45",
        publisher="Fedora Project",
        mode="cleartext",
        trusted_fingerprint="4F50A6114CD5C6976A7F1179655A4B02F577861E",
        key_source="https://fedoraproject.org/fedora.gpg",
        verification_source="https://fedoraproject.org/security/",
        notes="Current Fedora 45 OpenPGP certificate listed by the Fedora Project.",
    ),
    PublisherProfile(
        profile_id="fedora-44",
        label="Fedora 44",
        publisher="Fedora Project",
        mode="cleartext",
        trusted_fingerprint="36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
        key_source="https://fedoraproject.org/fedora.gpg",
        verification_source="https://fedoraproject.org/security/",
        notes="Fedora 44 OpenPGP certificate listed by the Fedora Project.",
    ),
    PublisherProfile(
        profile_id="fedora-rawhide-2026",
        label="Fedora Rawhide (2026 key)",
        publisher="Fedora Project",
        mode="cleartext",
        trusted_fingerprint="D924B10D3E810DABDD8B56B596E7E91491211FCE",
        key_source="https://fedoraproject.org/fedora.gpg",
        verification_source="https://fedoraproject.org/security/",
        notes="Current Rawhide certificate listed by the Fedora Project.",
    ),
    PublisherProfile(
        profile_id="debian-cd-da87",
        label="Debian CD signing key (DA87E80D6294BE9B)",
        publisher="Debian",
        mode="detached",
        trusted_fingerprint="DF9B9C49EAA9298432589D76DA87E80D6294BE9B",
        key_source="https://www.debian.org/CD/verify",
        verification_source="https://www.debian.org/CD/verify",
        notes="One of Debian's officially listed CD signing keys used for releases in recent years.",
    ),
    PublisherProfile(
        profile_id="debian-cd-9880",
        label="Debian CD signing key (988021A964E6EA7D)",
        publisher="Debian",
        mode="detached",
        trusted_fingerprint="10460DAD76165AD81FBC0CE9988021A964E6EA7D",
        key_source="https://www.debian.org/CD/verify",
        verification_source="https://www.debian.org/CD/verify",
        notes="One of Debian's officially listed CD signing keys used for releases in recent years.",
    ),
    PublisherProfile(
        profile_id="debian-testing-cd",
        label="Debian Testing CD automatic signing key",
        publisher="Debian",
        mode="detached",
        trusted_fingerprint="F41D30342F3546695F65C66942468F4009EA8AC3",
        key_source="https://www.debian.org/CD/verify",
        verification_source="https://www.debian.org/CD/verify",
        notes="Debian Testing CDs Automatic Signing Key listed by Debian.",
    ),
)


_BY_ID = {profile.profile_id: profile for profile in PROFILES}


def get_profile(profile_id: str) -> PublisherProfile:
    try:
        return _BY_ID[profile_id]
    except KeyError as exc:
        raise KeyError(f"Unknown publisher profile: {profile_id}") from exc


def profile_ids() -> tuple[str, ...]:
    return tuple(profile.profile_id for profile in PROFILES)
