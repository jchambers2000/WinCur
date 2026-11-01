"""Portable build identity for source and frozen WinCur executions."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .resources import resource_path


DEVELOPMENT_BUILD_ID = "development-source"
_BUILD_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def load_build_info(path: Path | None = None, *, required: bool = False) -> dict[str, str]:
    """Read immutable packaging metadata, with a clear source-tree fallback."""
    candidate = path or resource_path("build_info.json")
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8-sig"))
        if not isinstance(payload, dict):
            raise ValueError("build information must be a JSON object")
        build_id = str(payload.get("build_id", "")).strip()
        if not _BUILD_ID_PATTERN.fullmatch(build_id):
            raise ValueError("build_id is missing or contains unsupported characters")
        built_utc = str(payload.get("built_utc", "")).strip()
        return {"build_id": build_id, "built_utc": built_utc}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if required:
            raise ValueError(f"WinCur build information is unavailable or invalid: {candidate}: {exc}") from exc
        return {"build_id": DEVELOPMENT_BUILD_ID, "built_utc": ""}


def build_identifier() -> str:
    return load_build_info()["build_id"]
