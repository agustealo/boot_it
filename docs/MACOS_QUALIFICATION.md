# macOS physical-media qualification

macOS support is not considered release-qualified merely because the application builds or opens. Boot It must prove the destructive-media lifecycle against a disposable physical external target before the README or a release may claim macOS support.

## What CI already proves

The Package workflow independently builds qualification `.app` bundles for Apple Silicon and Intel macOS runners. Each bundle must:

- use the native PyInstaller `--onedir --windowed` application-bundle mode;
- contain the canonical launcher and cross-platform safety runtime;
- execute the frozen `--self-test` successfully;
- pass `codesign --verify --deep --strict` for its qualification/ad-hoc bundle signature;
- report the actual executable architecture;
- produce a SHA-256 checksum and machine-readable qualification manifest;
- declare `distribution_signed: false`, `notarized: false`, and `release_eligible: false` until the real release-signing gates are provisioned.

CI does **not** have a physical USB controller attached. The remaining proof must therefore run on real disposable media.

## Non-destructive inventory first

From the exact candidate branch/commit being qualified:

```bash
python3 scripts/qualify_macos_usb.py
```

The command prints the external physical targets visible through the same macOS classifier used by Boot It. Review all returned fields before continuing, especially:

- `device`
- `model`
- `size_gib`
- `bus`
- `external`
- `virtual`
- `writable`
- `safe`
- `reason`
- `hardware_id`

A target with `safe: false` must never be used for the destructive qualification.

## Destructive qualification

> **Danger:** this test destroys data on the selected target. Use only a disposable USB/SSD whose contents can be lost completely.

Assuming inventory identifies the disposable drive as `/dev/disk4`:

```bash
python3 scripts/qualify_macos_usb.py \
  --destructive \
  --device /dev/disk4 \
  --confirm-device /dev/disk4 \
  --json-output macos-physical-qualification.json
```

The repeated device argument is intentional. The harness then independently rediscovers the target and compares the canonical identity immediately before destructive work. A removed/replaced device, changed identity, blocked target, virtual disk, internal disk, read-only medium, or unresolved system-storage topology aborts the test before the write.

The default destructive qualification performs:

1. a deterministic 128 MiB qualification-image build;
2. fresh target rediscovery and identity validation;
3. whole-disk unmount;
4. an intentional partial-write cancellation probe;
5. another target rediscovery and identity validation;
6. a complete raw write through `/dev/rdiskN`;
7. byte-for-byte verification against the exact qualification payload;
8. device eject;
9. a JSON evidence record.

macOS owns administrator credential collection through its native authorization dialog. Boot It does not capture or store the administrator password.

The cancellation probe can be skipped only when diagnosing a controller-specific problem:

```bash
python3 scripts/qualify_macos_usb.py \
  --destructive \
  --device /dev/disk4 \
  --confirm-device /dev/disk4 \
  --skip-cancel-probe
```

A run that skips cancellation does not satisfy the full release qualification gate.

## Required release evidence

Before changing README platform support or publishing a macOS release, preserve evidence for the exact candidate commit that shows:

- ARM64 packaged self-test passed;
- x86_64 packaged self-test passed;
- package checksum/manifest generation passed;
- non-destructive physical-device inventory passed on a real Mac;
- destructive cancellation probe passed on disposable media;
- complete raw write passed;
- byte-for-byte verification passed;
- eject passed;
- the GUI candidate detects the same physical device correctly;
- the GUI candidate completes a real ISO/IMG write and verification on disposable media;
- real application screenshots were captured from that qualified UI state.

Screenshots are product evidence. Do not use generated mockups, Figma-only screens, stale UI captures, or screenshots showing features that are not present in the qualified application.

## Still separate from release signing

Physical media qualification proves the disk backend. It does not replace macOS distribution requirements. Public macOS release artifacts still require the release policy to provide and verify, as applicable:

- Developer ID Application signing;
- hardened runtime;
- notarization;
- stapling;
- Gatekeeper assessment;
- final DMG/package checksums and release-index binding.

Until those gates are implemented and green, CI-produced macOS `.app` bundles remain qualification artifacts rather than consumer release artifacts.
