from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}(?:[0-9A-F]{24})?$")
STATUS_VALID_RE = re.compile(r"^\[GNUPG:\] VALIDSIG (.+)$")
MAX_OPENPGP_FILE_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class OpenPGPVerification:
    valid: bool
    signer_fingerprint: str
    trusted_fingerprint: str
    plaintext: str
    mode: str
    message: str


def normalize_fingerprint(value: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if not FINGERPRINT_RE.fullmatch(normalized):
        raise ValueError("Trusted OpenPGP fingerprint must contain 40 or 64 hexadecimal characters.")
    return normalized


def find_gpg() -> str:
    executable = shutil.which("gpg") or shutil.which("gpg.exe")
    if not executable:
        raise RuntimeError(
            "GnuPG is required for OpenPGP authenticity verification. Install GnuPG/Gpg4win and retry."
        )
    return executable


def _check_small_file(path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_file():
        raise FileNotFoundError(candidate)
    size = candidate.stat().st_size
    if size == 0:
        raise ValueError(f"{label} is empty.")
    if size > MAX_OPENPGP_FILE_SIZE:
        raise ValueError(f"{label} is unexpectedly large.")
    return candidate


def _run_gpg(gpg: str, homedir: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("GNUPGHOME", None)
    return subprocess.run(
        [
            gpg,
            "--homedir",
            str(homedir),
            "--batch",
            "--no-tty",
            "--no-auto-key-retrieve",
            "--no-auto-key-locate",
            *arguments,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _fingerprints_from_colons(output: str) -> list[str]:
    fingerprints: list[str] = []
    for line in output.splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr" and len(fields) > 9:
            value = fields[9].upper()
            if FINGERPRINT_RE.fullmatch(value):
                fingerprints.append(value)
    return fingerprints


def _validsig_fingerprints(status_output: str) -> list[str]:
    found: list[str] = []
    for line in status_output.splitlines():
        match = STATUS_VALID_RE.match(line.strip())
        if not match:
            continue
        for token in match.group(1).split():
            token = token.upper()
            if FINGERPRINT_RE.fullmatch(token) and token not in found:
                found.append(token)
    return found


def _prepare_key_home(gpg: str, homedir: Path, public_key: Path, trusted: str) -> None:
    imported = _run_gpg(
        gpg,
        homedir,
        ["--import-options", "import-minimal", "--import", str(public_key)],
    )
    if imported.returncode != 0:
        raise ValueError(f"Unable to import OpenPGP public key: {imported.stderr.strip()}")

    listed = _run_gpg(gpg, homedir, ["--with-colons", "--fingerprint", "--list-keys"])
    if listed.returncode != 0:
        raise ValueError(f"Unable to inspect imported OpenPGP key: {listed.stderr.strip()}")
    fingerprints = _fingerprints_from_colons(listed.stdout)
    if trusted not in fingerprints:
        visible = ", ".join(fingerprints) if fingerprints else "none"
        raise ValueError(
            f"The supplied key file does not contain the trusted fingerprint {trusted}. "
            f"Imported fingerprints: {visible}."
        )


def _verify_signature_status(status_output: str, trusted: str) -> str:
    fingerprints = _validsig_fingerprints(status_output)
    if not fingerprints:
        raise ValueError("OpenPGP verification did not produce a valid-signature status.")
    if trusted not in fingerprints:
        raise ValueError(
            "The OpenPGP signature is cryptographically valid, but it was not made by the explicitly trusted fingerprint."
        )
    return fingerprints[0]


def verify_detached_manifest(
    manifest_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    trusted_fingerprint: str,
    *,
    gpg_path: str | None = None,
) -> OpenPGPVerification:
    manifest = _check_small_file(manifest_path, "Checksum manifest")
    signature = _check_small_file(signature_path, "OpenPGP signature")
    public_key = _check_small_file(public_key_path, "OpenPGP public key")
    trusted = normalize_fingerprint(trusted_fingerprint)
    gpg = gpg_path or find_gpg()

    with tempfile.TemporaryDirectory(prefix="boot-it-openpgp-") as temp_dir:
        home = Path(temp_dir)
        try:
            home.chmod(stat.S_IRWXU)
        except OSError:
            pass
        _prepare_key_home(gpg, home, public_key, trusted)
        verified = _run_gpg(
            gpg,
            home,
            ["--status-fd", "1", "--verify", str(signature), str(manifest)],
        )
        if verified.returncode != 0:
            raise ValueError(f"OpenPGP signature verification failed: {verified.stderr.strip()}")
        signer = _verify_signature_status(verified.stdout, trusted)

    plaintext = manifest.read_text(encoding="utf-8", errors="strict")
    return OpenPGPVerification(
        valid=True,
        signer_fingerprint=signer,
        trusted_fingerprint=trusted,
        plaintext=plaintext,
        mode="detached",
        message="Checksum manifest signature is valid under the explicitly trusted OpenPGP fingerprint.",
    )


def verify_cleartext_manifest(
    signed_manifest_path: str | Path,
    public_key_path: str | Path,
    trusted_fingerprint: str,
    *,
    gpg_path: str | None = None,
) -> OpenPGPVerification:
    signed_manifest = _check_small_file(signed_manifest_path, "Cleartext-signed checksum manifest")
    public_key = _check_small_file(public_key_path, "OpenPGP public key")
    trusted = normalize_fingerprint(trusted_fingerprint)
    gpg = gpg_path or find_gpg()

    with tempfile.TemporaryDirectory(prefix="boot-it-openpgp-") as temp_dir:
        home = Path(temp_dir)
        try:
            home.chmod(stat.S_IRWXU)
        except OSError:
            pass
        _prepare_key_home(gpg, home, public_key, trusted)
        output_path = home / "manifest.txt"
        verified = _run_gpg(
            gpg,
            home,
            [
                "--status-fd",
                "2",
                "--output",
                str(output_path),
                "--decrypt",
                str(signed_manifest),
            ],
        )
        if verified.returncode != 0:
            raise ValueError(f"OpenPGP cleartext signature verification failed: {verified.stderr.strip()}")
        signer = _verify_signature_status(verified.stderr, trusted)
        plaintext = output_path.read_text(encoding="utf-8", errors="strict")

    return OpenPGPVerification(
        valid=True,
        signer_fingerprint=signer,
        trusted_fingerprint=trusted,
        plaintext=plaintext,
        mode="cleartext",
        message="Cleartext checksum manifest signature is valid under the explicitly trusted OpenPGP fingerprint.",
    )
