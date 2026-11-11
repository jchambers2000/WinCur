"""WinCur assessment-only application entry point."""

from __future__ import annotations

import argparse
from pathlib import Path


def dispatch() -> int:
    from wincur.logging_setup import configure_logging
    configure_logging()
    parser = argparse.ArgumentParser(description="WinCur Windows security assessment")
    parser.add_argument("--packaging-probe", metavar="OUTPUT")
    arguments = parser.parse_args()
    if arguments.packaging_probe:
        from wincur.packaging_probe import run_packaging_probe
        return run_packaging_probe(Path(arguments.packaging_probe))
    from wincur.ui import main
    return main()


if __name__ == "__main__":
    raise SystemExit(dispatch())
