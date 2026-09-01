#!/usr/bin/env python3
"""Boot It canonical launcher with headless diagnostics before Qt initialization."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from boot_it_meta import __version__, diagnostics_json, write_self_test


def _launcher_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--self-test", metavar="PATH")
    return parser


def load_application_main() -> Callable[[Sequence[str] | None], int]:
    """Load the application only after installing mandatory runtime hardening."""
    import boot_it as core
    from boot_it_auth_runtime import install_openpgp_authenticity
    from boot_it_runtime import install_runtime_patches

    install_runtime_patches(core)
    install_openpgp_authenticity(core)
    return core.main


def launcher(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    known, _unknown = _launcher_parser().parse_known_args(args)
    if known.version:
        print(__version__)
        return 0
    if known.diagnose:
        print(diagnostics_json())
        return 0
    if known.self_test:
        write_self_test(known.self_test)
        return 0

    application_main = load_application_main()
    return application_main([sys.argv[0], *args])


if __name__ == "__main__":
    raise SystemExit(launcher())
