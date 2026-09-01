# Boot It

Boot It is a desktop utility for writing bootable ISO and IMG images to removable USB media on Linux and Windows. The current implementation prioritizes target-device safety, native device discovery, explicit destructive-write confirmation, identity revalidation, cancellation safety, and byte-for-byte post-write verification.

## Current capabilities

- Linux USB discovery through `lsblk` with removable/USB transport filtering.
- Windows USB discovery through PowerShell `Get-Disk`; Boot It does not depend on deprecated WMIC.
- System, read-only, and otherwise unsafe targets are blocked before writing.
- Stable hardware identity is captured from WWN/serial information where the operating system exposes it.
- The selected USB is rediscovered immediately before destructive work; changed, removed, or newly-blocked targets are rejected before writing.
- Image capacity is checked against the target device before destructive operations begin.
- Linux writes use `dd` with `conv=fsync`, elevated through PolicyKit (`pkexec`) when necessary.
- Windows writes target the selected `\\.\PhysicalDriveN` device and require Administrator privileges.
- Mounted target volumes are dismounted before raw writing.
- Active writes and verification can be cancelled. Linux child process groups are terminated; Windows loops stop cooperatively at chunk boundaries.
- Cancelled writes are explicitly reported as partial/unverified media and are never presented as successful.
- Every successful write is verified byte-for-byte against the source image.
- SHA-256 is calculated for the selected image so users can compare it with a publisher-provided checksum.
- Long-running write and hashing work executes off the GUI thread.
- Logs are stored at `~/.boot_it/boot_it.log`.

## Supported platforms

### Linux

Boot It expects a modern Linux userspace with:

- Python 3.10 or newer
- `lsblk`, `findmnt`, `dd`, `cmp`
- `udisksctl` when available for normal unmounting
- `pkexec`/PolicyKit when raw-device elevation is required

### Windows

Boot It expects:

- Windows 10/11 with PowerShell
- Python 3.10 or newer
- Administrator privileges when writing physical USB media

macOS is not currently implemented and is intentionally reported as unsupported rather than silently pretending otherwise.

## Installation

```bash
git clone https://github.com/agustealo/boot_it.git
cd boot_it
python -m pip install -r requirements.txt
```

Run either entry point:

```bash
python boot_it.py
```

or:

```bash
python boot-it.py
```

On Windows, launch the terminal or packaged application with Administrator privileges before writing USB media.

## Safe usage

1. Download the ISO/IMG from the operating-system or software publisher.
2. Compare Boot It's displayed SHA-256 digest with the publisher's official checksum when one is available.
3. Insert the target USB drive and press **Refresh** if needed.
4. Confirm the exact model, device identifier, capacity, and displayed hardware identity shown by Boot It.
5. Press **Write and verify**.
6. Boot It rediscoveries the target and refuses to continue if its physical identity or safety state changed after confirmation.
7. Boot It dismounts the target, writes the image, flushes it, and verifies the written bytes against the source.

Writing an image destroys the existing contents of the selected USB device. System disks are excluded from the writable target set, but the final device confirmation remains an important safety boundary.

If **Cancel** is used after writing has started, treat that USB as incomplete and unbootable until it has been rewritten successfully. Cancellation during verification means Boot It has not certified the image even if the write itself may have completed.

## Development

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run the quality checks:

```bash
python -m compileall -q boot_it.py boot-it.py tests
python -m pytest -q
```

The GitHub Actions quality workflow runs those checks on Python 3.10, 3.12, and 3.14.

## Architecture notes

The project deliberately uses native disk inventory instead of parsing human-oriented command output such as legacy WMIC tables. Platform-specific destructive operations are isolated behind explicit Linux/Windows functions, while validation, device metadata, hashing, progress reporting, cancellation, and the GUI remain shared.

A device path such as `/dev/sdb` or `\\.\PhysicalDrive2` is treated as a location, not a durable identity. Boot It captures a fingerprint when the target is selected and rebuilds it from fresh OS inventory immediately before destructive work. This prevents a removed/reinserted or replacement device from inheriting an earlier safety decision merely because the operating system reused the same path.

Boot It currently performs direct image writes. Multi-ISO operation is a different product mode and should be implemented as an explicit, separately tested feature rather than layered implicitly onto raw-image writing.

## Near-term hardening roadmap

- Package signed Windows and Linux releases instead of requiring users to run from source.
- Add hardware-backed integration tests using disposable virtual/removable disks.
- Add image-format introspection and publisher-checksum retrieval where a trustworthy upstream metadata source exists.
- Add macOS disk discovery/unmount/raw-write support only after the same target-safety and verification guarantees are implemented.
- Evaluate a separate Ventoy-style multi-image mode instead of weakening the verified single-image workflow.

## License

Boot It is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [`LICENSE`](LICENSE).

## Contributing

Pull requests should preserve the safety invariants: never expose a known system disk as writable, never trust a stale target identity, never claim success before verification completes, never accept a target larger/smaller mismatch silently, and never reintroduce password capture into the application process.
