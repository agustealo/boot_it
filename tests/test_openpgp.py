from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from boot_it_openpgp import (
    normalize_fingerprint,
    verify_cleartext_manifest,
    verify_detached_manifest,
)

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="GnuPG is required for OpenPGP integration tests")


def _gpg(home: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("GNUPGHOME", None)
    return subprocess.run(
        [
            shutil.which("gpg") or "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            *args,
        ],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


@pytest.fixture()
def signing_material(tmp_path: Path) -> tuple[Path, str, Path]:
    home = tmp_path / "signer-home"
    home.mkdir(mode=0o700)
    generated = _gpg(
        home,
        "--quick-gen-key",
        "Boot It CI Signing Key <boot-it-ci@example.invalid>",
        "ed25519",
        "sign",
        "1d",
    )
    assert generated.returncode == 0

    listing = _gpg(home, "--with-colons", "--fingerprint", "--list-keys").stdout
    fingerprint = next(
        line.split(":")[9]
        for line in listing.splitlines()
        if line.startswith("fpr:")
    )
    public_key = tmp_path / "signer.asc"
    exported = _gpg(home, "--armor", "--export", fingerprint)
    public_key.write_text(exported.stdout, encoding="utf-8")
    return home, fingerprint, public_key


def _manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{'a' * 64}  boot.iso\n", encoding="utf-8")
    return manifest


def test_normalize_fingerprint_accepts_grouped_v4_fingerprint() -> None:
    raw = "D2EB 4462 6FDD C30B 513D 5BB7 1A5D 6C4C 7DB8 7C81"
    assert normalize_fingerprint(raw) == "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"


def test_invalid_short_key_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="40 or 64"):
        normalize_fingerprint("EFE21092")


def test_detached_signature_is_verified_in_isolated_keyring(
    tmp_path: Path,
    signing_material: tuple[Path, str, Path],
) -> None:
    signer_home, fingerprint, public_key = signing_material
    manifest = _manifest(tmp_path)
    signature = tmp_path / "SHA256SUMS.gpg"
    _gpg(
        signer_home,
        "--armor",
        "--detach-sign",
        "--output",
        str(signature),
        str(manifest),
    )

    result = verify_detached_manifest(manifest, signature, public_key, fingerprint)
    assert result.valid
    assert result.mode == "detached"
    assert result.trusted_fingerprint == fingerprint
    assert "boot.iso" in result.plaintext


def test_detached_signature_rejects_tampered_manifest(
    tmp_path: Path,
    signing_material: tuple[Path, str, Path],
) -> None:
    signer_home, fingerprint, public_key = signing_material
    manifest = _manifest(tmp_path)
    signature = tmp_path / "SHA256SUMS.gpg"
    _gpg(signer_home, "--detach-sign", "--output", str(signature), str(manifest))
    manifest.write_text(f"{'b' * 64}  boot.iso\n", encoding="utf-8")

    with pytest.raises(ValueError, match="verification failed"):
        verify_detached_manifest(manifest, signature, public_key, fingerprint)


def test_supplied_key_must_contain_explicit_trusted_fingerprint(
    tmp_path: Path,
    signing_material: tuple[Path, str, Path],
) -> None:
    signer_home, fingerprint, public_key = signing_material
    manifest = _manifest(tmp_path)
    signature = tmp_path / "SHA256SUMS.gpg"
    _gpg(signer_home, "--detach-sign", "--output", str(signature), str(manifest))
    replacement = ("0" if fingerprint[0] != "0" else "1") + fingerprint[1:]

    with pytest.raises(ValueError, match="does not contain the trusted fingerprint"):
        verify_detached_manifest(manifest, signature, public_key, replacement)


def test_cleartext_signed_manifest_is_verified_and_extracted(
    tmp_path: Path,
    signing_material: tuple[Path, str, Path],
) -> None:
    signer_home, fingerprint, public_key = signing_material
    manifest = _manifest(tmp_path)
    signed_manifest = tmp_path / "Fedora-Example-CHECKSUM"
    _gpg(
        signer_home,
        "--clearsign",
        "--output",
        str(signed_manifest),
        str(manifest),
    )

    result = verify_cleartext_manifest(signed_manifest, public_key, fingerprint)
    assert result.valid
    assert result.mode == "cleartext"
    assert result.trusted_fingerprint == fingerprint
    assert result.plaintext == manifest.read_text(encoding="utf-8")
