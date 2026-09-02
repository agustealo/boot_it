from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PACKAGE_WORKFLOW = ROOT / ".github" / "workflows" / "package.yml"

CHECKOUT_SHA = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_ARTIFACT_SHA = "d3f86a106a0bac45b974a628896c90dbdf5c8093"
ATTEST_SHA = "508db95dd578ae2727ebd6217d5ba78e4fbda05d"
SBOM_SHA = "e22c389904149dbc22b58101806040fa8d37a610"


def test_release_workflow_is_manual_and_version_guarded() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "scripts/release_contract.py" in text
    assert "--source-ref \"$GITHUB_REF\"" in text
    assert "--source-sha \"$GITHUB_SHA\"" in text


def test_release_workflow_attests_binary_and_sbom_with_immutable_actions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count(f"actions/attest@{ATTEST_SHA}") == 2
    assert "sbom-path:" in text
    assert f"anchore/sbom-action@{SBOM_SHA}" in text
    assert "format: spdx-json" in text
    assert f"actions/checkout@{CHECKOUT_SHA}" in text
    assert f"actions/setup-python@{SETUP_PYTHON_SHA}" in text
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}" in text
    assert f"actions/download-artifact@{DOWNLOAD_ARTIFACT_SHA}" in text


def test_release_workflow_has_no_mutable_action_tags() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    uses_lines = [line.strip() for line in text.splitlines() if "uses:" in line]
    assert uses_lines
    assert all("@v" not in line.split("#", 1)[0] for line in uses_lines)


def test_release_workflow_has_minimal_split_permissions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "contents: write" in text
    assert "name: Publish GitHub release" in text


def test_release_workflow_verifies_checksums_and_builds_index_before_publication() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    verify_index = text.index("sha256sum --check SHA256SUMS")
    index_index = text.index("scripts/release_index.py")
    release_index = text.index("gh release create")
    assert verify_index < index_index < release_index
    assert "--output dist/release-index.json" in text
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


def test_frozen_workflows_include_all_runtime_hardening_modules() -> None:
    for workflow in (WORKFLOW, PACKAGE_WORKFLOW):
        text = workflow.read_text(encoding="utf-8")
        assert "--hidden-import boot_it_source" in text
        assert "--hidden-import boot_it_source_runtime" in text
        assert "--hidden-import boot_it_topology" in text
        assert "--hidden-import boot_it_topology_runtime" in text
