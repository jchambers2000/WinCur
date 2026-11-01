"""Local, sanitized hardening action history."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import ActionRecord


def default_action_history_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "WinCur" / "action_history.jsonl"


def save_action_record(record: ActionRecord, path: Path | None = None) -> Path:
    destination = path or default_action_history_path(); destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_dict(), ensure_ascii=True) + "\n"); handle.flush(); os.fsync(handle.fileno())
    if record.to_dict() not in load_action_history(destination, limit=100):
        raise OSError("The hardening audit record could not be verified after saving.")
    return destination


def load_action_history(path: Path | None = None, limit: int = 100) -> list[dict[str, Any]]:
    source = path or default_action_history_path()
    if not source.exists(): return []
    records = []
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
                if isinstance(record, dict): records.append(record)
            except json.JSONDecodeError: continue
    return records[-limit:]
