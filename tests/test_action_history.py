from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wincur.action_history import load_action_history, save_action_record
from wincur.models import ActionOutcome, ActionRecord


class ActionHistoryTests(unittest.TestCase):
    def test_action_audit_round_trip_preserves_recorded_outcome_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action_history.jsonl"
            first = ActionRecord.create("disable_autorun", {"enabled": True}, {"enabled": False}, ActionOutcome.FAILURE, "Verification failed", "Observed enabled", True)
            second = ActionRecord.create("enable_powershell_logging", {"script_block": False}, {"script_block": True}, ActionOutcome.SUCCESS, "Verified", "Observed enabled", True)
            save_action_record(first, path); save_action_record(second, path); loaded = load_action_history(path, limit=10)
            self.assertEqual(loaded, [first.to_dict(), second.to_dict()]); self.assertEqual(load_action_history(path, limit=1), [second.to_dict()]); self.assertEqual(loaded[0]["outcome"], "Failure")

    def test_action_audit_skips_corrupt_lines_without_modifying_valid_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action_history.jsonl"; record = ActionRecord.create("disable_autorun", {}, {}, ActionOutcome.CANCELLED, "No change", "No change attempted", False)
            save_action_record(record, path)
            with path.open("a", encoding="utf-8") as handle: handle.write("{not-json}\n")
            self.assertEqual(load_action_history(path), [record.to_dict()]); self.assertIn("{not-json}", path.read_text(encoding="utf-8"))

    def test_rollback_snapshot_schema_round_trip_and_legacy_default(self) -> None:
        record = ActionRecord.create("disable_autorun", {"schema_version": 2}, {"schema_version": 2}, ActionOutcome.SUCCESS, "Verified", "Verified", True, rollback_snapshot_schema=2)
        self.assertEqual(ActionRecord.from_dict(record.to_dict()).rollback_snapshot_schema, 2)
        legacy = record.to_dict(); legacy.pop("rollback_snapshot_schema")
        self.assertEqual(ActionRecord.from_dict(legacy).rollback_snapshot_schema, 1)


if __name__ == "__main__": unittest.main()
