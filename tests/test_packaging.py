from __future__ import annotations

import json
import hashlib
import os
import subprocess
import struct
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from wincur import APP_VERSION, privileges, resources
from wincur.build_info import DEVELOPMENT_BUILD_ID, load_build_info
from wincur.action_history import default_action_history_path
from wincur.baselines import default_baseline_path
from wincur.packaging_probe import run_packaging_probe
from wincur.reporting import default_history_path
from wincur.scoring import load_scoring_config
from wincur.scoring import default_profile_path
from wincur.theme import default_preference_path


ROOT = Path(__file__).resolve().parent.parent


class PackagingConfigurationTests(unittest.TestCase):
    def test_spec_bundles_scoring_policy_and_builds_onedir(self) -> None:
        spec = (ROOT / "WinCur.spec").read_text(encoding="utf-8")
        self.assertIn('"scoring_config.json"', spec)
        self.assertIn('(str(scoring_config), "wincur")', spec)
        self.assertIn('(str(portrait_resource), "wincur/assets")', spec)
        self.assertIn('(str(icon_resource), "wincur/assets")', spec)
        self.assertIn('(str(branding_hashes), "wincur/assets")', spec)
        self.assertIn('(str(build_info), "wincur")', spec)
        self.assertIn("COLLECT(", spec)
        self.assertIn("windows_version_info.txt", spec)
        self.assertNotIn("onefile", spec.casefold())

    def test_build_script_uses_isolated_outputs_and_validates_runtime_files(self) -> None:
        script = (ROOT / "tools" / "build_windows.ps1").read_text(encoding="utf-8")
        for required in ("WinCur.spec", "scoring_config.json", "wincur_portrait.png", "wincur.ico", "qwindows.dll", "packaging-probe.json", "BUILD_MANIFEST.json", "build_info.json"):
            self.assertIn(required, script)
        self.assertIn('artifacts\\windows\\candidates', script)
        self.assertIn('"WinCur-$version-$buildId"', script)
        self.assertIn("Get-ManifestPath", script)
        self.assertIn("Candidate only", script)
        self.assertIn('"--distpath", $distRoot', script)
        self.assertIn('"--workpath", $workRoot', script)
        self.assertNotIn("Stop-Process", script)
        self.assertNotIn("Remove-Item", script)
        self.assertNotIn("generate_brand_assets.py", script)
        self.assertIn("branding_hashes.json", script)

    def test_promotion_is_explicit_verified_and_never_overwrites(self) -> None:
        script = (ROOT / "tools" / "promote_windows_candidate.ps1").read_text(encoding="utf-8")
        for required in ("ConfirmValidated", "ShouldProcess", "verify_windows_dist.ps1", "ExpectedBuildId", "smoke_test", "Move-Item", "candidates", "current", "archive"):
            self.assertIn(required, script)
        self.assertNotIn("Remove-Item", script)
        self.assertIn("already contains", script)

    def test_build_information_is_validated_and_source_has_clear_fallback(self) -> None:
        self.assertEqual(load_build_info()["build_id"], DEVELOPMENT_BUILD_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); valid = root / "build_info.json"
            valid.write_text(json.dumps({"build_id": "20261101-120000-42-a1b2c3d4", "built_utc": "2026-11-01T18:00:00Z"}), encoding="utf-8")
            self.assertEqual(load_build_info(valid, required=True)["build_id"], "20261101-120000-42-a1b2c3d4")
            valid.write_text(json.dumps({"build_id": "20261101-120000-42-bom", "built_utc": "2026-11-01T18:00:00Z"}), encoding="utf-8-sig")
            self.assertEqual(load_build_info(valid, required=True)["build_id"], "20261101-120000-42-bom")
            valid.write_text('{"build_id": "unsafe build id"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "build information"):
                load_build_info(valid, required=True)

    def test_version_resource_matches_application_version(self) -> None:
        metadata = (ROOT / "packaging" / "windows_version_info.txt").read_text(encoding="utf-8")
        self.assertEqual(APP_VERSION, "1.0.0")
        self.assertIn("filevers=(1, 0, 0, 0)", metadata)
        self.assertIn("prodvers=(1, 0, 0, 0)", metadata)
        self.assertIn("StringStruct('ProductVersion', '1.0.0')", metadata)
        self.assertIn("StringStruct('ProductName', 'WinCur')", metadata)
        self.assertNotIn("LegalCopyright", metadata); self.assertNotIn("CompanyName", metadata)

    def test_source_and_frozen_resource_paths_ignore_working_directory(self) -> None:
        source = resources.resource_path("scoring_config.json")
        self.assertTrue(source.is_file()); self.assertEqual(source.parent.name, "wincur")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundled = root / "wincur" / "scoring_config.json"; bundled.parent.mkdir(); bundled.write_text("{}", encoding="utf-8")
            with patch.object(resources.sys, "frozen", True, create=True), patch.object(resources.sys, "_MEIPASS", str(root), create=True):
                self.assertEqual(resources.resource_path("scoring_config.json"), bundled)
                self.assertEqual(resources.resource_path("assets/wincur.ico"), root / "wincur" / "assets" / "wincur.ico")

    def test_missing_bundled_resource_fails_with_actionable_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "probe.json"
            with patch.object(resources.sys, "frozen", True, create=True), patch.object(resources.sys, "_MEIPASS", str(root), create=True):
                code = run_packaging_probe(output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(code, 1); self.assertFalse(payload["ok"])
            self.assertIn("scoring_config.json", payload["error"]); self.assertIn("bundled application", payload["error"])

    def test_source_packaging_probe_does_not_run_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "probe.json"; code = run_packaging_probe(output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(code, 0); self.assertTrue(payload["ok"])
            self.assertFalse(payload["frozen"]); self.assertEqual(payload["application_version"], APP_VERSION)
            self.assertEqual(payload["build_id"], DEVELOPMENT_BUILD_ID); self.assertEqual(payload["scoring_policy"], "2.1"); self.assertGreaterEqual(payload["icon_images"], 9)

    def test_packaging_probe_reports_missing_brand_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "probe.json"
            code = run_packaging_probe(output, portrait=root / "missing.png")
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(code, 1); self.assertFalse(payload["ok"]); self.assertIn("missing.png", payload["error"])

    def test_main_dispatch_declares_fixed_packaging_probe_mode(self) -> None:
        entry = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--packaging-probe", metavar="OUTPUT")', entry)
        self.assertIn("return run_packaging_probe(Path(arguments.packaging_probe))", entry)

    def test_scoring_loader_reports_explicit_missing_resource(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaises(FileNotFoundError): load_scoring_config(missing)

    def test_frozen_helper_preserves_fixed_arguments_and_quotes_paths(self) -> None:
        calls = []; shell32 = types.SimpleNamespace(ShellExecuteW=lambda *args: calls.append(args) or 33)
        arguments = ["--helper-scan", "Enterprise", r"C:\Path With Spaces\result.json"]
        with patch.object(privileges.os, "name", "nt"), patch.object(privileges.sys, "frozen", True, create=True), patch.object(privileges.ctypes, "windll", types.SimpleNamespace(shell32=shell32), create=True):
            started, _ = privileges.launch_elevated_helper(arguments)
        self.assertTrue(started); self.assertEqual(calls[0][2], str(Path(privileges.sys.executable).resolve()))
        self.assertEqual(calls[0][3], subprocess.list2cmdline(arguments)); self.assertNotIn("main.py", calls[0][3])

    def test_approved_portrait_and_multisize_icon_are_required(self) -> None:
        spec = (ROOT / "WinCur.spec").read_text(encoding="utf-8")
        documentation = (ROOT / "PACKAGING.md").read_text(encoding="utf-8")
        portrait = ROOT / "wincur" / "assets" / "wincur_portrait.png"; icon = ROOT / "wincur" / "assets" / "wincur.ico"
        self.assertTrue(portrait.is_file()); self.assertTrue(icon.is_file()); self.assertIn("wincur\\assets\\wincur.ico", documentation)
        header = icon.read_bytes()[:6]; self.assertEqual(header[:4], b"\x00\x00\x01\x00"); self.assertGreaterEqual(struct.unpack("<H", header[4:6])[0], 9)
        self.assertIn("icon=str(icon_resource)", spec); self.assertNotIn("else None", spec)

    def test_approved_branding_hashes_are_exact_and_probe_rejects_drift(self) -> None:
        assets = ROOT / "wincur" / "assets"
        expected = json.loads((assets / "branding_hashes.json").read_text(encoding="utf-8"))
        for name in ("wincur_portrait.png", "wincur.ico"):
            self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest().upper(), expected[name])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); changed = root / "wincur_portrait.png"
            changed.write_bytes((assets / "wincur_portrait.png").read_bytes() + b"drift")
            output = root / "probe.json"
            code = run_packaging_probe(output, portrait=changed)
            self.assertEqual(code, 1)
            self.assertIn("integrity check", json.loads(output.read_text(encoding="utf-8"))["error"])

    def test_writable_state_paths_do_not_use_installation_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            local_data = Path(directory) / "LocalData"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(local_data)}):
                paths = (default_history_path(), default_action_history_path(), default_baseline_path(), default_profile_path(), default_preference_path())
                pending = privileges.pending_output_path("packaging-test")
            for path in (*paths, pending):
                self.assertTrue(path.is_relative_to(local_data / "WinCur"), path)
                self.assertFalse(path.is_relative_to(ROOT), path)


if __name__ == "__main__": unittest.main()
