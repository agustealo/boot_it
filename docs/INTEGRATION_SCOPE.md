# Integration coverage scope

The loopback suite validates Boot It's Linux raw-write mechanics against a real kernel block-device interface. It is intentionally not a substitute for physical USB qualification.

Covered now:

- raw write through `dd` to a block device;
- byte-for-byte verification through `cmp`;
- corruption detection after a completed write;
- cancellation of the isolated writer process group;
- CI proof on Ubuntu 24.04 with disposable loop devices.

Not covered by this suite:

- USB controller firmware behavior;
- surprise physical removal during write;
- UAS versus usb-storage transport differences;
- flash-media write caching or controller lies;
- Windows physical-drive semantics;
- actual BIOS/UEFI bootability on hardware.

Those belong in the next physical-media qualification layer, using dedicated sacrificial USB devices and explicit host isolation.