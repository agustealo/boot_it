# Destructive-path integration testing

Boot It tests its Linux raw-write path against kernel loop devices before physical-media testing.

## Safety boundary

The integration suite never discovers or selects host disks. Each test creates a disposable backing file inside the runner's temporary directory and attaches only that file to a newly allocated loop device with `losetup --find --show`.

The suite exercises the same `linux_write()` and `linux_verify()` functions used by the application. It proves that:

- a source image can be written through the kernel block-device layer and read back identically;
- byte-for-byte verification succeeds after an unchanged write;
- deliberately corrupted written media is rejected by verification; and
- cancellation terminates the isolated writer process instead of leaving the worker alive indefinitely.

## Opt-in execution

The tests are skipped unless `BOOT_IT_LOOPBACK_TESTS=1` is set and the process is running with root privileges. GitHub Actions supplies both conditions only inside the dedicated `Loopback Integration` workflow.

Run manually on a disposable Linux test machine with:

```bash
sudo BOOT_IT_LOOPBACK_TESTS=1 QT_QPA_PLATFORM=offscreen python -m pytest -q tests/integration/test_linux_loopback.py
```

Never point these tests at a physical disk or change the fixture to accept an externally supplied device path. Physical-media qualification belongs in a separate, explicitly provisioned hardware lab.