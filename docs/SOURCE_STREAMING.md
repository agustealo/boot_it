# Immutable source streaming

Boot It binds destructive writes to the exact image bytes that were approved by the GUI.

## Why this exists

Rechecking a pathname immediately before and after a write detects many source-image TOCTOU attacks, but the writer can still reopen that pathname later. A pathname is a mutable name, not an immutable byte source.

## Boot It source lifecycle

1. The GUI hashes the selected image and records SHA-256 plus file identity.
2. After destructive confirmation, but before target revalidation, unmounting, dismounting, or raw writing, the worker copies the approved source into an anonymous temporary file.
3. Snapshot creation verifies the original file identity before and after copying and verifies the copied bytes against the approved SHA-256 digest.
4. The anonymous snapshot handle becomes the only source for destructive writing and post-write verification.
5. The snapshot is closed and automatically removed when the worker finishes or fails.

Replacing, renaming, or modifying the original image after snapshot creation therefore cannot alter the bytes written or verified.

## Linux privilege boundary

Linux no longer invokes `dd if=<image> of=<device>` for the GUI-approved path. Boot It reads the anonymous snapshot as the unprivileged process and streams it to `dd` over stdin. Only the raw-target process is elevated when `pkexec` is required.

Verification similarly streams the same anonymous snapshot handle to `cmp` over stdin. Neither destructive command receives the original source pathname.

## Windows boundary

Windows writes and verifies directly from the same anonymous snapshot handle while opening only the physical target path separately.

## Tradeoff

The stronger byte binding requires temporary free disk space approximately equal to the selected image size. Snapshot creation happens before the target is touched. If the snapshot cannot be created, verified, flushed, or completed, the destructive operation is aborted before target mutation begins.

Snapshot creation remains cancellable so large images do not create an uncancellable pre-write phase.

## What this guarantees

For the normal GUI destructive path, the bytes used for raw writing and the bytes used for post-write verification come from the same verified anonymous snapshot. The original image pathname is not reopened for either phase.

Lower-level writer functions remain usable by isolated integration tests and embedders when no GUI-approved source seal is registered; those callers are responsible for their own source trust boundary.
