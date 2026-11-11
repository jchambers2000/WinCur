"""Isolated Qt scale-factor probe for the Security Issues detail layout."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication

from wincur.models import AssessmentScore, CheckResult, CheckStatus, Remediation, ScanRecord
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def main() -> int:
    app = QApplication([])
    temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
    explanation = " ".join(["This finding contains a detailed explanation that must remain readable at Windows display scaling."] * 18)
    recommendation = " ".join(["Review the documented Windows setting and decide whether the recommended configuration is appropriate."] * 16)
    evidence = " ".join([rf"HKLM\SOFTWARE\WinCur\ReadOnlyExample\Value{index}=not-configured" for index in range(80)])
    remediation = Remediation(recommendation, "Administrator review may be required.", explanation,
                              "Run a later read-only assessment.", "Use documented Windows administration guidance.")
    finding = CheckResult("layout_probe", "Long security finding title that wraps without being clipped",
                          "Attack Surface", CheckStatus.FAIL, evidence, explanation, 1, "High", remediation)
    score = AssessmentScore(0.0, 100.0, profile="Standard", policy_version="2.1",
                            dispositions={finding.check_id: "Scored"})
    record = ScanRecord.create("1.0.0", "Windows 11", "TEST-PC", [finding], score, "Standard").to_dict()
    contexts = [
        patch("wincur.ui.load_history", return_value=[record]),
        patch("wincur.ui.load_action_history", return_value=[]),
        patch("wincur.ui.is_administrator", return_value=False),
    ]
    for context in contexts: context.start()
    try:
        window = WinCurWindow(ThemeManager(root / "appearance.json"), baseline_path=root / "baselines.json",
                              history_path=root / "history.jsonl", layout_path=root / "layout.json")
        window.resize(1600, 900); window.show(); window._view_history_record(record); window._set_page(1)
        app.processEvents(); window.findings_splitter.update_for_width(1300); app.processEvents()
        window._toggle_finding_technical(); window.finding_detail_splitter.setSizes([1, 1]); app.processEvents()

        window.details.verticalScrollBar().setValue(window.details.verticalScrollBar().maximum())
        window.technical_finding_details.verticalScrollBar().setValue(window.technical_finding_details.verticalScrollBar().maximum())
        app.processEvents()
        line_height = max(1, window.detail_title.fontMetrics().lineSpacing())
        payload = {
            "scale": app.devicePixelRatio(),
            "non_collapsible": not window.finding_detail_splitter.childrenCollapsible(),
            "title_lines": window.detail_title.height() / line_height,
            "description_height": window.details.height(),
            "description_minimum": window.details.minimumHeight(),
            "technical_height": window.technical_finding_details.height(),
            "technical_minimum": window.technical_finding_details.minimumHeight(),
            "description_vertical_maximum": window.details.verticalScrollBar().maximum(),
            "technical_vertical_maximum": window.technical_finding_details.verticalScrollBar().maximum(),
            "description_at_end": window.details.verticalScrollBar().value() == window.details.verticalScrollBar().maximum(),
            "technical_at_end": window.technical_finding_details.verticalScrollBar().value() == window.technical_finding_details.verticalScrollBar().maximum(),
            "description_horizontal_maximum": window.details.horizontalScrollBar().maximum(),
            "technical_horizontal_maximum": window.technical_finding_details.horizontalScrollBar().maximum(),
            "description_margin": window.details.document().documentMargin(),
            "technical_margin": window.technical_finding_details.document().documentMargin(),
        }
        print(json.dumps(payload)); window.close()
    finally:
        for context in reversed(contexts): context.stop()
        temporary.cleanup()
    return 0


if __name__ == "__main__": raise SystemExit(main())
