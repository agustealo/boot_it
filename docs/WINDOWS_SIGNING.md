# Windows Authenticode release signing

Boot It supports optional Windows Authenticode signing in the manual `Release Candidate` workflow.

Signing is deliberately dormant until all required repository configuration exists. An entirely absent configuration produces an unsigned Windows release candidate and the package manifest says so. A partially configured signing setup fails the Windows release job and cannot silently downgrade to unsigned output.

## Required repository configuration

Secrets:

- `WINDOWS_CODESIGN_PFX_B64`: base64-encoded PFX/PKCS#12 code-signing certificate and private key.
- `WINDOWS_CODESIGN_PASSWORD`: password protecting that PFX.

Variables:

- `WINDOWS_CODESIGN_THUMBPRINT`: full 40-hex SHA-1 certificate thumbprint for the expected leaf signing certificate. This is an identity pin, not the file digest algorithm.
- `WINDOWS_CODESIGN_TIMESTAMP_URL`: HTTPS RFC 3161 timestamp service URL supplied by the code-signing CA or trusted timestamp provider.

Do not commit the PFX or its password to the repository.

## Release behavior

For Windows releases the workflow order is:

1. Build the frozen executable.
2. If signing configuration is completely absent, record an unsigned signing report.
3. If any signing input is present, require all signing inputs.
4. Sign with SignTool using `/fd SHA256` and RFC 3161 `/tr ... /td SHA256`.
5. Verify the executable with SignTool using the default Authenticode application policy.
6. Read the resulting signature through Windows `Get-AuthenticodeSignature`.
7. Require `Status = Valid`.
8. Require the actual signer certificate thumbprint to exactly match `WINDOWS_CODESIGN_THUMBPRINT`.
9. Require a timestamp certificate to be present.
10. Only then package, hash, generate the SBOM, create GitHub attestations, and publish.

A signing failure, signer mismatch, invalid signature, missing timestamp, invalid PFX, or partial configuration blocks the Windows release job.

## Why the thumbprint is SHA-1 shaped

Windows certificate thumbprints are commonly represented as 40 hexadecimal characters derived from SHA-1. That thumbprint is used here only to identify the expected certificate. The executable signature itself uses SHA-256, and the RFC 3161 timestamp request also uses SHA-256.

## Trust layers

Boot It keeps these claims separate:

- `signed: true` means the packaged Windows executable passed Authenticode verification under the pinned signer certificate and contains a timestamp certificate.
- GitHub artifact attestation proves which GitHub Actions workflow and source identity produced the artifact.
- SHA-256 checksums provide file-integrity comparison.

None of those layers substitutes for another.
