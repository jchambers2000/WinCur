from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


class SecurityIssuesLayoutTests(unittest.TestCase):
    def test_detail_text_remains_readable_and_scrollable_at_supported_scale_factors(self) -> None:
        root = Path(__file__).resolve().parent.parent
        for scale in ("1", "1.25", "1.5"):
            with self.subTest(scale=scale):
                environment = dict(os.environ, QT_QPA_PLATFORM="offscreen", QT_SCALE_FACTOR=scale)
                completed = subprocess.run(
                    [sys.executable, "-m", "tests.security_issues_layout_probe"], cwd=root,
                    env=environment, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads([line for line in completed.stdout.splitlines() if line.strip()][-1])
                self.assertAlmostEqual(payload["scale"], float(scale))
                self.assertTrue(payload["non_collapsible"])
                self.assertGreaterEqual(payload["title_lines"], 2)
                self.assertGreaterEqual(payload["description_height"], payload["description_minimum"])
                self.assertGreaterEqual(payload["technical_height"], payload["technical_minimum"])
                self.assertGreater(payload["description_vertical_maximum"], 0)
                self.assertGreater(payload["technical_vertical_maximum"], 0)
                self.assertTrue(payload["description_at_end"])
                self.assertTrue(payload["technical_at_end"])
                self.assertEqual(payload["description_horizontal_maximum"], 0)
                self.assertEqual(payload["technical_horizontal_maximum"], 0)
                self.assertGreaterEqual(payload["description_margin"], 8)
                self.assertGreaterEqual(payload["technical_margin"], 8)


if __name__ == "__main__": unittest.main()
