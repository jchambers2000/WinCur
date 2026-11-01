"""Versioned, local persistence for immutable assessment baseline snapshots."""

from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import atomic_write_text


SCHEMA_VERSION = 1


def default_baseline_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "WinCur" / "security_baselines.json"


@dataclass(frozen=True)
class SecurityBaseline:
    baseline_id: str
    name: str
    created_utc: str
    assessment_snapshot: dict[str, Any]

    @classmethod
    def create(cls, name: str, assessment: dict[str, Any]) -> "SecurityBaseline":
        clean_name = name.strip()
        if not clean_name: raise ValueError("A baseline name is required.")
        snapshot = json.loads(json.dumps(assessment, ensure_ascii=True))
        return cls(str(uuid.uuid4()), clean_name, datetime.now(timezone.utc).isoformat(), snapshot)

    def renamed(self, name: str) -> "SecurityBaseline":
        clean_name = name.strip()
        if not clean_name: raise ValueError("A baseline name is required.")
        return replace(self, name=clean_name)

    def to_dict(self) -> dict[str, Any]:
        return {"baseline_id": self.baseline_id, "name": self.name, "created_utc": self.created_utc,
                "assessment_snapshot": copy.deepcopy(self.assessment_snapshot)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityBaseline":
        snapshot = data.get("assessment_snapshot")
        if not isinstance(snapshot, dict): raise ValueError("Baseline snapshot is missing.")
        baseline_id = str(data.get("baseline_id", "")).strip(); name = str(data.get("name", "")).strip()
        if not baseline_id or not name: raise ValueError("Baseline identity or name is missing.")
        return cls(baseline_id, name, str(data.get("created_utc", "Unknown")), copy.deepcopy(snapshot))


@dataclass
class BaselineCollection:
    baselines: list[SecurityBaseline] = field(default_factory=list)
    active_baseline_id: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def active(self) -> SecurityBaseline | None:
        return next((item for item in self.baselines if item.baseline_id == self.active_baseline_id), None)


class BaselineStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_baseline_path(); self._preserve_before_save = False

    def load(self) -> BaselineCollection:
        if not self.path.exists(): return BaselineCollection()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self._preserve_before_save = True
            return BaselineCollection(warnings=[f"Baseline storage could not be read: {exc}"])
        if not isinstance(raw, dict): self._preserve_before_save = True; return BaselineCollection(warnings=["Baseline storage has an invalid root object."])
        warnings = []
        if raw.get("schema_version") != SCHEMA_VERSION:
            self._preserve_before_save = True
            warnings.append(f"Baseline schema {raw.get('schema_version', 'Unknown')} is not fully supported; recoverable records were loaded.")
        baselines = []; raw_baselines = raw.get("baselines", [])
        if not isinstance(raw_baselines, list): self._preserve_before_save = True; warnings.append("Baseline record collection was invalid and ignored."); raw_baselines = []
        for index, item in enumerate(raw_baselines):
            try: baselines.append(SecurityBaseline.from_dict(item))
            except (AttributeError, TypeError, ValueError): self._preserve_before_save = True; warnings.append(f"Baseline record {index + 1} was invalid and skipped.")
        active = str(raw.get("active_baseline_id")) if raw.get("active_baseline_id") else None
        if active and not any(item.baseline_id == active for item in baselines): warnings.append("The active baseline reference was missing and was cleared."); active = None
        return BaselineCollection(baselines, active, warnings)

    def save(self, collection: BaselineCollection) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._preserve_before_save and self.path.exists():
            recovery = self.path.with_suffix(self.path.suffix + ".recovery")
            if not recovery.exists(): shutil.copy2(self.path, recovery)
        payload = {"schema_version": SCHEMA_VERSION, "active_baseline_id": collection.active_baseline_id,
                   "baselines": [item.to_dict() for item in collection.baselines]}
        atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=True))
        self._preserve_before_save = False

    def _save_or_restore(self, collection: BaselineCollection,
                         previous_baselines: list[SecurityBaseline],
                         previous_active_id: str | None) -> None:
        """Keep the live model aligned with durable storage when saving fails."""
        try:
            self.save(collection)
        except Exception:
            collection.baselines[:] = previous_baselines
            collection.active_baseline_id = previous_active_id
            raise

    def create(self, collection: BaselineCollection, name: str, assessment: dict[str, Any], *, activate: bool = False) -> SecurityBaseline:
        previous_baselines = list(collection.baselines); previous_active_id = collection.active_baseline_id
        baseline = SecurityBaseline.create(name, assessment); collection.baselines.append(baseline)
        if activate or not collection.active_baseline_id: collection.active_baseline_id = baseline.baseline_id
        self._save_or_restore(collection, previous_baselines, previous_active_id); return baseline

    def rename(self, collection: BaselineCollection, baseline_id: str, name: str) -> SecurityBaseline:
        for index, baseline in enumerate(collection.baselines):
            if baseline.baseline_id == baseline_id:
                previous_baselines = list(collection.baselines); previous_active_id = collection.active_baseline_id
                renamed = baseline.renamed(name); collection.baselines[index] = renamed
                self._save_or_restore(collection, previous_baselines, previous_active_id); return renamed
        raise KeyError("Baseline was not found.")

    def delete(self, collection: BaselineCollection, baseline_id: str) -> None:
        previous_baselines = list(collection.baselines); previous_active_id = collection.active_baseline_id
        before = len(collection.baselines); collection.baselines[:] = [item for item in collection.baselines if item.baseline_id != baseline_id]
        if len(collection.baselines) == before: raise KeyError("Baseline was not found.")
        if collection.active_baseline_id == baseline_id: collection.active_baseline_id = collection.baselines[0].baseline_id if collection.baselines else None
        self._save_or_restore(collection, previous_baselines, previous_active_id)

    def set_active(self, collection: BaselineCollection, baseline_id: str | None) -> None:
        if baseline_id and not any(item.baseline_id == baseline_id for item in collection.baselines): raise KeyError("Baseline was not found.")
        previous_baselines = list(collection.baselines); previous_active_id = collection.active_baseline_id
        collection.active_baseline_id = baseline_id
        self._save_or_restore(collection, previous_baselines, previous_active_id)
