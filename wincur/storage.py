"""Small, dependency-free helpers for durable local application data writes."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Replace *path* only after a complete, flushed temporary write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: Any, *, indent: int | None = None) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=True, indent=indent))


def exclusive_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Durably create *path* without replacing a file created by another process."""
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
