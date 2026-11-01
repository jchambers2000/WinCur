"""WinCur application and narrowly scoped elevated-helper entry point."""

from __future__ import annotations

import argparse
from pathlib import Path


def dispatch() -> int:
    from wincur.logging_setup import configure_logging
    configure_logging()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--helper-scan", nargs=2, metavar=("PROFILE", "OUTPUT"))
    parser.add_argument("--helper-preview", nargs=2, metavar=("ACTION_ID", "OUTPUT"))
    parser.add_argument("--helper-action", nargs=3, metavar=("ACTION_ID", "REQUEST", "OUTPUT"))
    parser.add_argument("--helper-rollback", nargs=3, metavar=("ACTION_ID", "RECORD", "OUTPUT"))
    parser.add_argument("--packaging-probe", metavar="OUTPUT")
    arguments, _ = parser.parse_known_args()
    if arguments.helper_scan:
        from wincur.helper import elevated_scan
        return elevated_scan(arguments.helper_scan[0], Path(arguments.helper_scan[1]))
    if arguments.helper_preview:
        from wincur.helper import preview_action
        return preview_action(arguments.helper_preview[0], Path(arguments.helper_preview[1]))
    if arguments.helper_action:
        from wincur.helper import apply_action
        return apply_action(arguments.helper_action[0], Path(arguments.helper_action[1]), Path(arguments.helper_action[2]))
    if arguments.helper_rollback:
        from wincur.helper import rollback_action
        return rollback_action(arguments.helper_rollback[0], Path(arguments.helper_rollback[1]), Path(arguments.helper_rollback[2]))
    if arguments.packaging_probe:
        from wincur.packaging_probe import run_packaging_probe
        return run_packaging_probe(Path(arguments.packaging_probe))
    from wincur.ui import main
    return main()


if __name__ == "__main__":
    raise SystemExit(dispatch())
