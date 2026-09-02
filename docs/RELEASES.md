# Boot It release trust

Boot It release automation separates three different claims that must not be conflated:

1. **Checksum integrity**: the downloaded executable matches the SHA-256 published in the release bundle.
2. **GitHub build provenance**: GitHub Actions attests which repository, workflow, commit, and build identity produced the executable.
3. **Platform code signing**: Windows Authenticode or another platform-native publisher signature. This is not configured yet and release manifests continue to report the executable itself as unsigned.

## Release candidate workflow

The `Release Candidate` workflow is manually dispatched from `main`. The requested version must exactly match `boot_it_meta.__version__`; dispatches from any other branch or ref fail before building.

For each Windows and Linux executable the workflow:

- audits runtime Python dependencies with `pip-audit`;
- builds the frozen GUI executable with the pinned PyInstaller toolchain;
- runs the executable's headless self-test;
- creates a SHA-256 checksum and machine-readable package manifest;
- generates an SPDX JSON SBOM from the frozen executable using Anchore Syft;
- creates a GitHub build-provenance attestation for the executable;
- creates a GitHub SBOM attestation binding that SPDX document to the executable; and
- uploads the binary, checksum, JSON manifest, and SBOM into the release bundle.

The final release job combines the platform bundles, validates every `.sha256` entry again, and only then creates the GitHub release. Existing release/tag collisions are allowed to fail rather than silently replacing a published release.

## Verify a downloaded executable

First verify the ordinary SHA-256 checksum from the release bundle. On Linux:

```bash
sha256sum --check SHA256SUMS
```

On Windows PowerShell, calculate the file hash and compare it with the matching `.sha256` entry:

```powershell
Get-FileHash .\Boot-It-*.exe -Algorithm SHA256
```

Then verify GitHub build provenance with GitHub CLI:

```bash
gh attestation verify ./Boot-It-<version>-<platform> -R agustealo/boot_it
```

For the Windows executable include the `.exe` suffix. GitHub's attestation verification establishes that the artifact was produced by the repository's GitHub Actions identity and records the source commit/workflow context.

The adjacent JSON package manifest also records the GitHub source SHA, source ref, workflow run ID, and run attempt when built in Actions. That metadata is useful for offline inspection, but it is not a cryptographic substitute for the GitHub attestation.

## Signing status

GitHub artifact attestations are cryptographic supply-chain provenance, but they are **not Windows Authenticode signatures** and must not be presented as such. Until real platform signing credentials are provisioned and verified in CI, Boot It package manifests keep:

```json
{
  "signed": false,
  "signature_status": "unsigned release candidate"
}
```

A future code-signing slice can add Authenticode/Linux signing as a separate gate without weakening or replacing these provenance controls.
