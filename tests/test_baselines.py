from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wincur.baselines import BaselineCollection, BaselineStore


def assessment(timestamp="2026-01-01T00:00:00Z", evidence="original"):
    return {"timestamp_utc": timestamp, "assessment_privilege": "Standard", "assessment": {"profile": "Standard", "policy_version": "2.0", "score": 80, "coverage": 90}, "results": [{"check_id": "uac", "status": "Pass", "evidence": evidence}]}


class BaselineStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); self.path = self.root / "baselines.json"; self.store = BaselineStore(self.path); self.collection = BaselineCollection()

    def tearDown(self) -> None: self.temp.cleanup()

    def test_create_persist_multiple_and_active_baseline(self) -> None:
        first = self.store.create(self.collection, "Personal", assessment()); second = self.store.create(self.collection, "Travel", assessment("2026-02-01T00:00:00Z"))
        loaded = self.store.load(); self.assertEqual([item.name for item in loaded.baselines], ["Personal", "Travel"]); self.assertEqual(loaded.active_baseline_id, first.baseline_id)
        self.store.set_active(loaded, second.baseline_id); self.assertEqual(self.store.load().active.name, "Travel")

    def test_snapshot_is_immutable_and_rename_changes_only_name(self) -> None:
        source = assessment(); baseline = self.store.create(self.collection, "Original", source); source["results"][0]["evidence"] = "mutated"
        before = json.dumps(baseline.assessment_snapshot, sort_keys=True); renamed = self.store.rename(self.collection, baseline.baseline_id, "Renamed")
        self.assertEqual(renamed.name, "Renamed"); self.assertEqual(json.dumps(renamed.assessment_snapshot, sort_keys=True), before); self.assertEqual(renamed.assessment_snapshot["results"][0]["evidence"], "original")

    def test_create_and_activate_is_one_transaction_and_restores_on_failure(self) -> None:
        existing = self.store.create(self.collection, "Existing", assessment())
        with patch.object(self.store, "save", wraps=self.store.save) as save:
            created = self.store.create(self.collection, "Active", assessment("2026-03-01T00:00:00Z"), activate=True)
        self.assertEqual(save.call_count, 1); self.assertEqual(self.collection.active_baseline_id, created.baseline_id)
        before = list(self.collection.baselines); before_active = self.collection.active_baseline_id
        with patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError): self.store.create(self.collection, "Partial", assessment(), activate=True)
        self.assertEqual(self.collection.baselines, before); self.assertEqual(self.collection.active_baseline_id, before_active); self.assertNotEqual(existing.baseline_id, before_active)

    def test_atomic_replace_failure_preserves_disk_and_live_collection(self) -> None:
        existing = self.store.create(self.collection, "Existing", assessment()); before_disk = self.path.read_text(encoding="utf-8")
        with patch("wincur.storage.os.replace", side_effect=OSError("replace denied")):
            with self.assertRaises(OSError): self.store.create(self.collection, "Partial", assessment(), activate=True)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before_disk); self.assertEqual(self.collection.baselines, [existing]); self.assertEqual(self.collection.active_baseline_id, existing.baseline_id); self.assertEqual(list(self.root.glob(".baselines.json.*.tmp")), [])

    def test_delete_does_not_depend_on_history_file(self) -> None:
        baseline = self.store.create(self.collection, "Independent", assessment()); history = self.root / "scan_history.jsonl"; history.write_text("history", encoding="utf-8"); history.unlink()
        self.assertEqual(self.store.load().baselines[0].baseline_id, baseline.baseline_id); self.store.delete(self.collection, baseline.baseline_id); self.assertEqual(self.store.load().baselines, [])

    def test_corruption_and_partial_records_are_handled_without_crash(self) -> None:
        self.path.write_text("not json", encoding="utf-8"); loaded = self.store.load(); self.assertEqual(loaded.baselines, []); self.assertTrue(loaded.warnings)
        self.store.create(loaded, "Recovered after corruption", assessment()); self.assertTrue(self.path.with_suffix(".json.recovery").exists()); self.assertEqual(self.path.with_suffix(".json.recovery").read_text(encoding="utf-8"), "not json")
        self.path.write_text(json.dumps({"schema_version": 1, "baselines": [{"name": "broken"}, {"baseline_id": "ok", "name": "Recovered", "created_utc": "now", "assessment_snapshot": assessment()}]}), encoding="utf-8")
        loaded = self.store.load(); self.assertEqual([item.name for item in loaded.baselines], ["Recovered"]); self.assertTrue(loaded.warnings)


if __name__ == "__main__": unittest.main()
