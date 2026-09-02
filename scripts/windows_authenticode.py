from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

THUMBPRINT_RE = re.compile(r"^[0-9A-F]{40}$")


@dataclass(frozen=True)
class SigningConfig:
    enabled: bool
    pfx_base64: str = ""
    password: str = ""
    expected_thumbprint: str = ""
    timestamp_url: str = ""


@dataclass(frozen=True)
class SigningReport:
    signed: bool
    signature_status: str
    binary_sha256: str
    signer_thumbprint: str | None = None
    signer_subject: str | None = None
    timestamped: bool = False
    timestamp_subject: str | None = None
    timestamp_thumbprint: str | None = None
    digest_algorithm: str | None = None
    timestamp_digest_algorithm: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_thumbprint(value: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if not THUMBPRINT_RE.fullmatch(normalized):
        raise ValueError("Expected signer thumbprint must be a full 40-hex certificate thumbprint.")
    return normalized


def signing_config_from_values(
    pfx_base64: str,
    password: str,
    expected_thumbprint: str,
    timestamp_url: str,
) -> SigningConfig:
    values = [pfx_base64.strip(), password, expected_thumbprint.strip(), timestamp_url.strip()]
    present = [bool(value) for value in values]
    if not any(present):
        return SigningConfig(enabled=False)
    if not all(present):
        missing = [
            name
            for name, value in zip(
                ("PFX", "password", "expected thumbprint", "timestamp URL"),
                present,
                strict=True,
            )
            if not value
        ]
        raise ValueError(
            "Windows Authenticode signing is partially configured; missing " + ", ".join(missing) + "."
        )
    if not timestamp_url.lower().startswith("https://"):
        raise ValueError("Windows Authenticode timestamp URL must use HTTPS.")
    return SigningConfig(
        enabled=True,
        pfx_base64=pfx_base64.strip(),
        password=password,
        expected_thumbprint=normalize_thumbprint(expected_thumbprint),
        timestamp_url=timestamp_url.strip(),
    )


def signing_config_from_environment() -> SigningConfig:
    return signing_config_from_values(
        os.environ.get("WINDOWS_CODESIGN_PFX_B64", ""),
        os.environ.get("WINDOWS_CODESIGN_PASSWORD", ""),
        os.environ.get("WINDOWS_CODESIGN_THUMBPRINT", ""),
        os.environ.get("WINDOWS_CODESIGN_TIMESTAMP_URL", ""),
    )


def find_signtool() -> str:
    direct = shutil.which("signtool") or shutil.which("signtool.exe")
    if direct:
        return direct
    roots = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Kits" / "10" / "bin",
    ]
    candidates: list[Path] = []
    for root in roots:
        if root.is_dir():
            candidates.extend(root.glob("*/x64/signtool.exe"))
    if not candidates:
        raise RuntimeError("signtool.exe was not found. Install the Windows SDK signing tools.")
    return str(sorted(candidates, reverse=True)[0])


def _signature_metadata(binary: Path) -> dict[str, object]:
    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$s=Get-AuthenticodeSignature -LiteralPath $args[0];"
            "[pscustomobject]@{"
            "Status=[string]$s.Status;"
            "StatusMessage=$s.StatusMessage;"
            "SignerThumbprint=if($s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{$null};"
            "SignerSubject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};"
            "TimestampThumbprint=if($s.TimeStamperCertificate){$s.TimeStamperCertificate.Thumbprint}else{$null};"
            "TimestampSubject=if($s.TimeStamperCertificate){$s.TimeStamperCertificate.Subject}else{$null}"
            "}|ConvertTo-Json -Compress"
        ),
        str(binary.resolve()),
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def sign_and_verify(binary: Path, config: SigningConfig, *, signtool: str | None = None) -> SigningReport:
    if not binary.is_file():
        raise FileNotFoundError(binary)
    if not config.enabled:
        return SigningReport(
            signed=False,
            signature_status="unsigned; Authenticode credentials not configured",
            binary_sha256=sha256_file(binary),
        )

    tool = signtool or find_signtool()
    try:
        pfx_bytes = base64.b64decode(config.pfx_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("WINDOWS_CODESIGN_PFX_B64 is not valid base64.") from exc
    if not pfx_bytes:
        raise ValueError("WINDOWS_CODESIGN_PFX_B64 decoded to an empty file.")

    with tempfile.TemporaryDirectory(prefix="boot-it-signing-") as temp_dir:
        pfx_path = Path(temp_dir) / "codesign.pfx"
        pfx_path.write_bytes(pfx_bytes)
        subprocess.run(
            [
                tool,
                "sign",
                "/fd",
                "SHA256",
                "/f",
                str(pfx_path),
                "/p",
                config.password,
                "/tr",
                config.timestamp_url,
                "/td",
                "SHA256",
                "/v",
                str(binary.resolve()),
            ],
            check=True,
        )

    subprocess.run(
        [tool, "verify", "/pa", "/all", "/v", "/tw", str(binary.resolve())],
        check=True,
    )
    metadata = _signature_metadata(binary)
    status = str(metadata.get("Status") or "")
    signer_thumbprint = normalize_thumbprint(str(metadata.get("SignerThumbprint") or ""))
    if status.lower() != "valid":
        raise RuntimeError(f"Authenticode verification status is {status!r}, not 'Valid'.")
    if signer_thumbprint != config.expected_thumbprint:
        raise RuntimeError(
            "Authenticode signer thumbprint mismatch: "
            f"expected {config.expected_thumbprint}, got {signer_thumbprint}."
        )
    timestamp_thumbprint_raw = str(metadata.get("TimestampThumbprint") or "").strip()
    if not timestamp_thumbprint_raw:
        raise RuntimeError("Authenticode signature is valid but does not contain a timestamp certificate.")
    timestamp_thumbprint = normalize_thumbprint(timestamp_thumbprint_raw)

    return SigningReport(
        signed=True,
        signature_status="Authenticode signature verified with pinned signer and RFC 3161 timestamp",
        binary_sha256=sha256_file(binary),
        signer_thumbprint=signer_thumbprint,
        signer_subject=str(metadata.get("SignerSubject") or "") or None,
        timestamped=True,
        timestamp_subject=str(metadata.get("TimestampSubject") or "") or None,
        timestamp_thumbprint=timestamp_thumbprint,
        digest_algorithm="SHA256",
        timestamp_digest_algorithm="SHA256",
    )


def write_report(report: SigningReport, path: Path) -> None:
    path.write_text(json.dumps(asdict(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign and verify a Boot It Windows executable when credentials are configured.")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    config = signing_config_from_environment()
    report = sign_and_verify(args.binary, config)
    write_report(report, args.report)
    print("signed" if report.signed else "unsigned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
