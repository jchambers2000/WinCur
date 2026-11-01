from __future__ import annotations

import types
import unittest
from pathlib import Path
from unittest.mock import patch

from wincur import privileges


class PrivilegeTests(unittest.TestCase):
    def test_failed_or_denied_elevation_returns_false(self) -> None:
        shell32 = types.SimpleNamespace(ShellExecuteW=lambda *args: 5)
        fake_windll = types.SimpleNamespace(shell32=shell32)
        with patch.object(privileges.os, "name", "nt"), patch.object(privileges.ctypes, "windll", fake_windll, create=True):
            started, message = privileges.launch_elevated_helper(["--helper-scan", "result.json"])
        self.assertFalse(started)
        self.assertIn("denied", message.lower())

    def test_elevated_helper_entry_is_resolved_relative_to_installed_module(self) -> None:
        calls = []; shell32 = types.SimpleNamespace(ShellExecuteW=lambda *args: calls.append(args) or 33); fake_windll = types.SimpleNamespace(shell32=shell32)
        with patch.object(privileges.os, "name", "nt"), patch.object(privileges.ctypes, "windll", fake_windll, create=True): started, _ = privileges.launch_elevated_helper(["--helper-scan", "Standard", "result.json"])
        expected = Path(privileges.__file__).resolve().parent.parent / "main.py"; self.assertTrue(started); self.assertIn(str(expected), calls[0][3]); self.assertEqual(Path(calls[0][4]), expected.parent)


if __name__ == "__main__": unittest.main()
