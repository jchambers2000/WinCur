"""Runtime resource resolution for source and frozen WinCur executions."""

from __future__ import annotations

import sys
from pathlib import Path


def resource_path(name: str) -> Path:
    """Return a package resource without depending on the working directory."""
    candidate = Path(name)
    if candidate.is_absolute() or not candidate.parts or any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError("A package resource must be a safe relative path.")
    if bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS).resolve() / "wincur" / candidate
    return Path(__file__).resolve().parent / candidate


def require_resource(name: str) -> Path:
    path = resource_path(name)
    if not path.is_file():
        mode = "bundled application" if bool(getattr(sys, "frozen", False)) else "source installation"
        raise FileNotFoundError(f"Required WinCur resource '{name}' is missing from the {mode}: {path}")
    return path
