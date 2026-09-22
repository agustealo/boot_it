from __future__ import annotations

from dataclasses import dataclass


class OperationCancelled(RuntimeError):
    """Raised when a destructive operation is cancelled intentionally."""


@dataclass(frozen=True)
class DriveInfo:
    """Canonical physical-target description shared by every platform backend.

    ``device`` is an operating-system location, not a durable identity. The
    ``identity`` property deliberately combines the current location with stable
    hardware and media characteristics so Boot It can rediscover and revalidate
    the selected target immediately before destructive work begins.
    """

    device: str
    size: int
    model: str
    bus: str
    removable: bool
    safe: bool
    reason: str = ""
    hardware_id: str = ""
    external: bool = True
    virtual: bool = False
    writable: bool = True
    platform: str = ""

    @property
    def size_gib(self) -> float:
        return self.size / (1024**3)

    @property
    def label(self) -> str:
        suffix = "" if self.safe else f" [blocked: {self.reason}]"
        return f"{self.model or 'USB drive'} · {self.size_gib:.2f} GiB · {self.device}{suffix}"

    @property
    def identity(self) -> tuple[str, int, str, str, str]:
        return (
            self.device,
            self.size,
            self.model.strip().casefold(),
            self.bus.strip().casefold(),
            self.hardware_id.strip().casefold(),
        )
