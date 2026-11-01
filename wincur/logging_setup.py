"""Sanitized local application logging."""

from __future__ import annotations

import logging
import os
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging() -> Path | None:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "WinCur"
    logger = logging.getLogger("wincur")
    if logger.handlers:
        handler = next((item for item in logger.handlers if isinstance(item, RotatingFileHandler)), None)
        return Path(handler.baseFilename) if handler else None
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    path: Path | None = None
    try:
        base.mkdir(parents=True, exist_ok=True); path = base / "wincur.log"
        handler: logging.Handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    except OSError:
        # Logging must never prevent startup. A temporary log is preferable to
        # discarding diagnostics when the application-data directory is denied.
        try:
            path = Path(tempfile.gettempdir()) / "WinCur" / "wincur.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=1, encoding="utf-8")
        except OSError:
            path = None; handler = logging.StreamHandler()
    handler.setFormatter(formatter); logger.addHandler(handler); logger.setLevel(logging.INFO); logger.propagate = False
    if path is None or path.parent != base:
        logger.warning("Primary application log directory was unavailable; fallback logging is active.")
    return path
