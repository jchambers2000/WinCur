from __future__ import annotations

import json
import hashlib
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wincur import APP_VERSION, resources
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
        self.assertIn("uac_admin=False", spec)
        for unused_qt in ("Qt6Pdf.dll", "Qt6Qml.dll", "Qt6Quick.dll", "Qt6VirtualKeyboard.dll", "qpdf.dll", "qtvirtualkeyboardplugin.dll"):
            self.assertIn(unused_qt, spec)
        self.assertNotIn("onefile", spec.casefold())

    def test_build_script_uses_isolated_outputs_and_validates_runtime_files(self) -> None:
        script = (ROOT / "tools" / "build_windows.ps1").read_text(encoding="utf-8")
        for required in ("WinCur.spec", "scoring_config.json", "wincur_portrait.png", "wincur.ico", "qwindows.dll", "packaging-probe.json", "BUILD_MANIFEST.json", "build_info.json", "THIRD_PARTY_NOTICES.md", "PYTHON-3.14.10-LICENSE.txt", "validated_toolchain.json", "frozen_dependency_inventory.json", "third_party_notices", "NOTICE_MANIFEST.json", "mesa-llvmpipe-11.2.2", "microsoft-vc-runtime-2026", "pyinstaller-6.22.3"):
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
        self.assertIn("PyInstaller.utils.cliutils.archive_viewer", script)
        for forbidden in ("wincur.helper", "wincur.hardening", "wincur.privileges"):
            self.assertIn(forbidden, script)
        self.assertIn("unused_qt_runtime_check", script)

    def test_third_party_notice_payload_is_complete_and_hash_validated(self) -> None:
        payload = ROOT / "packaging" / "third_party_notices"
        manifest = json.loads((payload / "NOTICE_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["qt_version"], "6.12.0")
        self.assertEqual(manifest["pyside_version"], "6.12.0")
        self.assertGreaterEqual(len(manifest["qt_attributions"]), 50)
        inventory = json.loads((ROOT / "packaging" / "frozen_dependency_inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256((payload / "NOTICE_MANIFEST.json").read_bytes()).hexdigest().upper(),
            inventory["third_party_notice_payload"]["manifest_sha256"],
        )
        paths = {entry["path"] for entry in manifest["files"]}
        self.assertIn("mesa-llvmpipe-11.2.2/NOTICE.txt", paths)
        self.assertIn("microsoft-vc-runtime-2026/NOTICE.txt", paths)
        self.assertIn("pyinstaller-6.22.3/COPYING.txt", paths)
        self.assertTrue(any(path.startswith("qt-6.12.0/attributions/") for path in paths))
        self.assertTrue(any(path.startswith("pyside6-6.12.0/") for path in paths))
        for entry in manifest["files"]:
            target = payload / entry["path"]
            self.assertTrue(target.is_file(), entry["path"])
            self.assertEqual(target.stat().st_size, entry["size"], entry["path"])
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), entry["sha256"], entry["path"])

        verifier = (ROOT / "tools" / "verify_windows_dist.ps1").read_text(encoding="utf-8")
        self.assertIn("Assert-ThirdPartyNoticePayload", verifier)
        self.assertIn("third-party\\NOTICE_MANIFEST.json", verifier)
        self.assertIn("Third-party notice file failed integrity validation", verifier)

        microsoft_notice = (payload / "microsoft-vc-runtime-2026" / "NOTICE.txt").read_text(encoding="utf-8")
        self.assertIn("separate works", microsoft_notice)
        self.assertIn("WinCur's GPL license grant does", microsoft_notice)
        self.assertIn("not apply to them", microsoft_notice)
        self.assertIn("Nothing in this notice limits the rights granted", microsoft_notice)
        self.assertIn("Visual Studio 2026 Distributable Code list", microsoft_notice)

    def test_public_release_documents_and_validated_toolchain_are_declared(self) -> None:
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        toolchain = json.loads((ROOT / "packaging" / "validated_toolchain.json").read_text(encoding="utf-8"))
        portable = (ROOT / "packaging" / "PORTABLE_README.txt").read_text(encoding="utf-8")
        inventory = json.loads((ROOT / "packaging" / "frozen_dependency_inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(toolchain["application_version"], "1.0.0")
        self.assertEqual(toolchain["scoring_policy"], "2.1")
        self.assertEqual(toolchain["validated_environment"]["python"], "3.14.10")
        self.assertEqual(toolchain["validated_environment"]["pyside6"], "6.12.0")
        self.assertEqual(toolchain["validated_environment"]["pyinstaller"], "6.22.3")
        self.assertIn("Qt6Widgets.dll", inventory["qt_libraries"])
        self.assertIn("Qt6VirtualKeyboard.dll", inventory["explicitly_excluded_qt"])
        self.assertIn("qt-everywhere-src-6.12.0.zip", notices)
        self.assertIn("pyside-setup-everywhere-src-6.12.0.zip", notices)
        self.assertIn("Administrator Scan", portable)
        self.assertIn("unsigned", portable.casefold())

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

    def test_removed_helper_modes_and_unknown_arguments_fail_closed(self) -> None:
        for arguments in (
            ["--helper-scan", "Enterprise", "result.json"],
            ["--helper-preview", "autorun", "result.json"],
            ["--helper-action", "autorun", "request.json", "result.json"],
            ["--helper-rollback", "autorun", "record.json", "result.json"],
            ["--unknown-release-option"],
        ):
            completed = subprocess.run(
                [sys.executable, str(ROOT / "main.py"), *arguments],
                cwd=ROOT, capture_output=True, text=True, timeout=15,
                env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
            )
            self.assertNotEqual(completed.returncode, 0, arguments)
            self.assertIn("unrecognized arguments", completed.stderr)

    def test_frozen_analysis_excludes_mutation_and_elevation_modules(self) -> None:
        spec = (ROOT / "WinCur.spec").read_text(encoding="utf-8")
        for module in ("wincur.hardening", "wincur.helper", "wincur.privileges"):
            self.assertIn(f'"{module}"', spec)
        entry = (ROOT / "main.py").read_text(encoding="utf-8")
        interface = (ROOT / "wincur" / "ui.py").read_text(encoding="utf-8")
        for forbidden in ("wincur.helper", "wincur.hardening", "wincur.privileges", "launch_elevated_helper"):
            self.assertNotIn(forbidden, entry)
            self.assertNotIn(forbidden, interface)

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
            for path in paths:
                self.assertTrue(path.is_relative_to(local_data / "WinCur"), path)
                self.assertFalse(path.is_relative_to(ROOT), path)


if __name__ == "__main__": unittest.main()
