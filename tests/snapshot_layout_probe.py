"""Isolated Qt scale-factor probe used by Saved Snapshots layout tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication, QDialogButtonBox

from wincur.models import AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def main() -> int:
    app = QApplication([])
    temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
    results = [
        CheckResult(f"check_{index}", f"Security check {index}", "Long category name used to verify table horizontal scrolling",
                    CheckStatus.PASS, "Evidence", "Meets the selected profile.", 1, "Low")
        for index in range(18)
    ]
    score = AssessmentScore(100.0, 100.0, profile="Standard", policy_version="2.1",
                            dispositions={item.check_id: "Scored" for item in results})
    record = ScanRecord.create("1.0.0", "Windows 11", "TEST-PC", results, score, "Standard").to_dict()
    contexts = [
        patch("wincur.ui.load_history", return_value=[record]),
        patch("wincur.ui.load_action_history", return_value=[]),
        patch("wincur.ui.is_administrator", return_value=False),
    ]
    for context in contexts: context.start()
    try:
        window = WinCurWindow(ThemeManager(root / "appearance.json"), baseline_path=root / "baselines.json", history_path=root / "history.jsonl")
        window.baseline_store.create(window.baseline_collection, "Reference", record, activate=True)
        with patch("wincur.ui.QDialog.exec", return_value=0): window._open_saved_snapshots()
        dialog = window.baseline_dialog; dialog.show(); app.processEvents(); window._compare_selected_baseline(); window._toggle_baseline_advanced(); app.processEvents(); app.processEvents()
        table = window.baseline_results_table; last = table.item(table.rowCount() - 1, 0); table.scrollToItem(last); app.processEvents(); last_rect = table.visualItemRect(last)
        close_box = dialog.findChildren(QDialogButtonBox)[0]; available = dialog.screen().availableGeometry(); frame = dialog.frameGeometry()
        result = {
            "scale": app.devicePixelRatio(),
            "dialog_within_screen": frame.left() >= available.left() and frame.top() >= available.top() and frame.right() <= available.right() and frame.bottom() <= available.bottom(),
            "details_visible": window.baseline_advanced_widget.isVisible(),
            "splitter_height": window.baseline_comparison_splitter.height(),
            "table_viewport_height": table.viewport().height(),
            "header_height": table.horizontalHeader().height(),
            "header_visible": table.horizontalHeader().isVisible(),
            "row_height": table.verticalHeader().defaultSectionSize(),
            "table_vertical_maximum": table.verticalScrollBar().maximum(),
            "table_horizontal_maximum": table.horizontalScrollBar().maximum(),
            "table_horizontal_visible": table.horizontalScrollBar().isVisible(),
            "outer_horizontal_visible": window.baseline_scroll.horizontalScrollBar().isVisible(),
            "outer_vertical_maximum": window.baseline_scroll.verticalScrollBar().maximum(),
            "last_row_visible": last_rect.top() >= 0 and last_rect.bottom() < table.viewport().height(),
            "close_visible": close_box.isVisible() and close_box.mapTo(dialog, close_box.rect().bottomRight()).y() <= dialog.rect().bottom(),
            "splitter_sizes": window.baseline_comparison_splitter.sizes(),
        }
        expanded_height = dialog.height(); window._toggle_baseline_advanced(); app.processEvents()
        result["collapsed_after_toggle"] = window.baseline_advanced_widget.isHidden()
        result["collapsed_height_not_larger"] = dialog.height() <= expanded_height
        result["collapsed_close_visible"] = close_box.isVisible() and close_box.mapTo(dialog, close_box.rect().bottomRight()).y() <= dialog.rect().bottom()
        dialog.reject()
        with patch("wincur.ui.QDialog.exec", return_value=0): window._open_saved_snapshots()
        result["reopened_collapsed"] = window.baseline_advanced_widget.isHidden()
        result["reopened_at_top"] = window.baseline_scroll.verticalScrollBar().value() == 0
        print(json.dumps(result)); window.close()
    finally:
        for context in reversed(contexts): context.stop()
        temporary.cleanup()
    return 0


if __name__ == "__main__": raise SystemExit(main())
