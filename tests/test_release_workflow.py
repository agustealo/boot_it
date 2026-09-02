from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def test_release_workflow_is_manual_and_version_guarded() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "scripts/release_contract.py" in text
    assert "--source-ref \"$GITHUB_REF\"" in text
    assert "--source-sha \"$GITHUB_SHA\"" in text


def test_release_workflow_attests_binary_and_sbom() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/attest@v4.2.1" in text
    assert text.count("actions/attest@v4.2.1") == 2
    assert "sbom-path:" in text
    assert "anchore/sbom-action@v0.24.0" in text
    assert "format: spdx-json" in text


def test_release_workflow_has_minimal_split_permissions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "contents: write" in text
    assert "name: Publish GitHub release" in text


def test_release_workflow_verifies_checksums_before_publication() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    verify_index = text.index("sha256sum --check SHA256SUMS")
    release_index = text.index("gh release create")
    assert verify_index < release_index
    assert "--prerelease" in text


def test_windows_authenticode_runs_before_packaging_and_attestation() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    sign_index = text.index("Sign and verify Windows Authenticode when configured")
    package_index = text.index("Smoke, checksum, and manifest")
    attest_index = text.index("Attest executable build provenance")
    assert sign_index < package_index < attest_index
    assert "scripts/windows_authenticode.py" in text
    assert "--signing-report signing-report.json" in text


def test_windows_authenticode_uses_pinned_signer_and_timestamp_configuration() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "WINDOWS_CODESIGN_PFX_B64" in text
    assert "WINDOWS_CODESIGN_PASSWORD" in text
    assert "WINDOWS_CODESIGN_THUMBPRINT" in text
    assert "WINDOWS_CODESIGN_TIMESTAMP_URL" in text
    assert "if (-not $report.signed)" in text
    assert "if (-not $report.timestamped)" in text
