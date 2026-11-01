"""Narrow helper entry points used after an explicit UAC prompt."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from .checks import run_all_checks
from .hardening import HardeningEngine, WindowsHardeningBackend
from .privileges import is_administrator
from .scoring import load_scoring_config, score_results
from .storage import atomic_write_json


LOGGER = logging.getLogger("wincur.helper")


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_json(path, payload)


def _read_and_remove_json(path: Path) -> Any:
    """Consume protected helper input even when its content is malformed."""
    try:
        content = path.read_text(encoding="utf-8")
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            LOGGER.warning("Protected helper input could not be removed: %s", path)
    return json.loads(content)


def elevated_scan(profile: str, output: Path) -> int:
    try:
        config = load_scoring_config(); findings = run_all_checks(config); assessment = score_results(findings, config, profile)
        payload = {"ok": True, "privilege": "Administrator" if is_administrator() else "Standard",
                   "timestamp_utc": datetime.now(timezone.utc).isoformat(), "source": "Live elevated scan",
                   "findings": [item.to_dict() for item in findings], "assessment": assessment.to_dict()}
    except Exception as exc:
        LOGGER.exception("Elevated scan failed")
        payload = {"ok": False, "error": str(exc), "privilege": "Administrator" if is_administrator() else "Standard"}
    _write_atomic(output, payload)
    return 0 if payload["ok"] else 1


def preview_action(action_id: str, output: Path) -> int:
    try:
        preview = HardeningEngine(WindowsHardeningBackend()).preview(action_id)
        payload = {"ok": True, "preview": preview.to_dict()}
    except Exception as exc:
        LOGGER.exception("Elevated preview %s failed", action_id)
        payload = {"ok": False, "error": str(exc)}
    _write_atomic(output, payload)
    return 0 if payload["ok"] else 1


def apply_action(action_id: str, request_path: Path, output: Path) -> int:
    try:
        request = _read_and_remove_json(request_path)
        if request.get("action_id") != action_id: raise ValueError("Preview action identifier mismatch.")
        record = HardeningEngine(WindowsHardeningBackend()).execute(
            action_id, confirmed=True, expected_preview_token=str(request.get("preview_token") or ""),
            preview_created_utc=str(request.get("created_utc") or ""),
        )
        LOGGER.info("Hardening action %s completed with outcome %s", action_id, record.outcome.value)
        payload = {"ok": True, "record": record.to_dict()}
    except Exception as exc:
        LOGGER.exception("Hardening action %s failed", action_id)
        payload = {"ok": False, "error": str(exc)}
    _write_atomic(output, payload)
    return 0 if payload["ok"] else 1


def rollback_action(action_id: str, record_path: Path, output: Path) -> int:
    try:
        record_data = _read_and_remove_json(record_path)
        if str(record_data.get("action_id")) != action_id: raise ValueError("Rollback action identifier mismatch.")
        record = HardeningEngine(WindowsHardeningBackend()).rollback(record_data, confirmed=True)
        LOGGER.info("Rollback %s completed with outcome %s", action_id, record.outcome.value)
        payload = {"ok": True, "record": record.to_dict()}
    except Exception as exc:
        LOGGER.exception("Rollback %s failed", action_id)
        payload = {"ok": False, "error": str(exc)}
    _write_atomic(output, payload)
    return 0 if payload["ok"] else 1
