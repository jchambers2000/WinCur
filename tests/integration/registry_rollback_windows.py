"""Opt-in real-registry tests for WinCur's production rollback implementation.

This file intentionally does not match unittest discovery's ``test*.py`` pattern.
Run it only by its exact path and only in a disposable Windows VM after setting
WINCUR_RUN_REGISTRY_INTEGRATION=1.
"""

from __future__ import annotations

import os
import unittest
import uuid

if os.name != "nt":
    raise unittest.SkipTest("Real Windows registry integration tests require Windows.")
if os.environ.get("WINCUR_RUN_REGISTRY_INTEGRATION") != "1":
    raise unittest.SkipTest("Set WINCUR_RUN_REGISTRY_INTEGRATION=1 explicitly.")

import winreg  # noqa: E402  (import only after the two safety gates)

from wincur.hardening import WindowsHardeningBackend  # noqa: E402


INTEGRATION_BASE = r"Software\WinCur\IntegrationTests"
OWNER_VALUE = "WinCurIntegrationTestOwner"


def _key_exists(path: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False


def _read_value(path: str, name: str):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
        return winreg.QueryValueEx(key, name)


def _delete_owned_tree(path: str, owned_root: str) -> None:
    """Delete only descendants of a UUID namespace whose ownership is proven."""
    normalized = path.strip("\\").casefold()
    trusted = owned_root.strip("\\").casefold()
    if normalized != trusted and not normalized.startswith(trusted + "\\"):
        raise RuntimeError(f"Refusing cleanup outside the owned integration namespace: {path}")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, owned_root, 0, winreg.KEY_READ) as owner:
        value, value_type = winreg.QueryValueEx(owner, OWNER_VALUE)
    if value_type != winreg.REG_SZ or value != owned_root.rsplit("\\", 1)[-1]:
        raise RuntimeError("Integration namespace ownership could not be established; cleanup was refused.")

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE
        ) as key:
            children: list[str] = []
            index = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, index)); index += 1
                except OSError:
                    break
            values: list[str] = []
            index = 0
            while True:
                try:
                    values.append(winreg.EnumValue(key, index)[0]); index += 1
                except OSError:
                    break
        for child in children:
            _delete_owned_tree(path + "\\" + child, owned_root)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            for name in values:
                winreg.DeleteValue(key, name)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        return


def _autorun_backend(root: str, leaf: str = "Explorer"):
    path = root + "\\" + leaf
    targets = (
        (path, "NoDriveTypeAutoRun", 255),
        (path, "NoAutorun", 1),
    )
    return WindowsHardeningBackend._for_registry_integration_tests(
        "disable_autorun", root, targets
    ), path


def _powershell_backend(root: str):
    parent = root + r"\Parent"
    script = parent + r"\Child"
    module = script + r"\ModuleLogging"
    names = module + r"\ModuleNames"
    targets = (
        (script, "EnableScriptBlockLogging", 1),
        (module, "EnableModuleLogging", 1),
        (names, "*", "*"),
    )
    return WindowsHardeningBackend._for_registry_integration_tests(
        "enable_powershell_logging", root, targets
    ), (parent, script, module, names)


def _apply_and_capture(backend, action_id: str):
    original = backend.capture(action_id)
    backend.apply(action_id, original)
    assert backend.verify(action_id)[0]
    return original, backend.capture(action_id)


class _FailSecondWrite:
    def __init__(self, delegate):
        self._delegate = delegate
        self._writes = 0

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def SetValueEx(self, key, name, reserved, value_type, value):
        self._writes += 1
        if self._writes == 2:
            raise PermissionError("controlled integration-test write failure")
        return self._delegate.SetValueEx(key, name, reserved, value_type, value)


class RegistryRollbackIntegrationTests(unittest.TestCase):
    def setUp(self):
        unique_id = str(uuid.uuid4())
        self.root = INTEGRATION_BASE + "\\" + unique_id
        if _key_exists(self.root):
            self.fail(f"The unique integration namespace already exists: {self.root}")
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.root, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, OWNER_VALUE, 0, winreg.REG_SZ, unique_id)
        # addCleanup also runs when a later setUp assertion fails.
        self.addCleanup(_delete_owned_tree, self.root, self.root)
        self.assertEqual(_read_value(self.root, OWNER_VALUE), (unique_id, winreg.REG_SZ))

    def test_newly_created_key_cleanup(self):
        backend, path = _autorun_backend(self.root)
        sibling = self.root + r"\UnrelatedSibling"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, sibling, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Marker", 0, winreg.REG_SZ, "preserve")
        self.assertFalse(_key_exists(path))
        original, owned = _apply_and_capture(backend, "disable_autorun")
        self.assertEqual(_read_value(path, "NoDriveTypeAutoRun"), (255, winreg.REG_DWORD))
        self.assertEqual(_read_value(path, "NoAutorun"), (1, winreg.REG_DWORD))
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertTrue(success and changed)
        self.assertIn("restored and verified", evidence)
        self.assertFalse(_key_exists(path))
        self.assertEqual(_read_value(sibling, "Marker"), ("preserve", winreg.REG_SZ))

    def test_preserves_preexisting_empty_key(self):
        backend, path = _autorun_backend(self.root)
        winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path).Close()
        original, owned = _apply_and_capture(backend, "disable_autorun")
        success, _, _ = backend.rollback("disable_autorun", original, owned)
        self.assertTrue(success and _key_exists(path))
        with self.assertRaises(FileNotFoundError):
            _read_value(path, "NoAutorun")

    def test_restores_original_values_and_registry_types(self):
        backend, path = _autorun_backend(self.root)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_SZ, "legacy")
            winreg.SetValueEx(key, "NoAutorun", 0, winreg.REG_DWORD, 0)
        original, owned = _apply_and_capture(backend, "disable_autorun")
        self.assertTrue(backend.rollback("disable_autorun", original, owned)[0])
        self.assertEqual(_read_value(path, "NoDriveTypeAutoRun"), ("legacy", winreg.REG_SZ))
        self.assertEqual(_read_value(path, "NoAutorun"), (0, winreg.REG_DWORD))
        self.assertTrue(_key_exists(path))

    def test_preserves_unrelated_value_and_reports_partial(self):
        backend, path = _autorun_backend(self.root)
        original, owned = _apply_and_capture(backend, "disable_autorun")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Unrelated", 0, winreg.REG_DWORD, 7)
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(success); self.assertTrue(changed); self.assertIn("safely skipped", evidence)
        self.assertEqual(_read_value(path, "Unrelated"), (7, winreg.REG_DWORD))
        self.assertTrue(_key_exists(path))

    def test_preserves_unrelated_subkey_and_reports_partial(self):
        backend, path = _autorun_backend(self.root)
        original, owned = _apply_and_capture(backend, "disable_autorun")
        child = path + r"\UnrelatedChild"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, child, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Marker", 0, winreg.REG_SZ, "preserve")
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(success); self.assertTrue(changed); self.assertIn("safely skipped", evidence)
        self.assertEqual(_read_value(child, "Marker"), ("preserve", winreg.REG_SZ))

    def test_nested_created_keys_are_removed_child_first(self):
        backend, paths = _powershell_backend(self.root)
        parent, script, module, names = paths
        winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, parent).Close()
        sibling = parent + r"\Sibling"
        winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, sibling).Close()
        original, owned = _apply_and_capture(backend, "enable_powershell_logging")
        self.assertTrue(backend.rollback("enable_powershell_logging", original, owned)[0])
        self.assertTrue(_key_exists(parent) and _key_exists(sibling))
        self.assertFalse(_key_exists(script) or _key_exists(module) or _key_exists(names))

    def test_external_target_change_is_not_overwritten(self):
        backend, path = _autorun_backend(self.root)
        original, owned = _apply_and_capture(backend, "disable_autorun")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "NoAutorun", 0, winreg.REG_DWORD, 0)
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(success or changed); self.assertIn("newer changes were preserved", evidence)
        self.assertEqual(_read_value(path, "NoAutorun"), (0, winreg.REG_DWORD))

    def test_repeated_rollback_is_rejected_without_writes(self):
        backend, path = _autorun_backend(self.root)
        original, owned = _apply_and_capture(backend, "disable_autorun")
        self.assertTrue(backend.rollback("disable_autorun", original, owned)[0])
        state_after_first = backend.capture("disable_autorun")
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(success or changed); self.assertIn("newer changes were preserved", evidence)
        self.assertEqual(backend.capture("disable_autorun"), state_after_first)
        self.assertFalse(_key_exists(path))

    def test_legacy_snapshot_value_restore_without_key_cleanup(self):
        backend, path = _autorun_backend(self.root)
        winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path).Close()
        original_v2, owned_v2 = _apply_and_capture(backend, "disable_autorun")
        original = {"values": original_v2["values"]}
        owned = {"values": owned_v2["values"]}
        success, _, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertTrue(success); self.assertIn("Legacy snapshot", evidence); self.assertTrue(_key_exists(path))
        malformed = {"values": []}
        result = backend.rollback("disable_autorun", malformed, {"recommended": "legacy"})
        self.assertEqual(result[:2], (False, False)); self.assertIn("precondition failed", result[2])

    def test_controlled_failure_reports_partial_and_cleanup_remains_safe(self):
        backend, path = _autorun_backend(self.root)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 145)
            winreg.SetValueEx(key, "NoAutorun", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "Unrelated", 0, winreg.REG_SZ, "preserve")
        original, owned = _apply_and_capture(backend, "disable_autorun")
        failing = _FailSecondWrite(winreg)
        backend._winreg = lambda: failing
        success, changed, evidence = backend.rollback("disable_autorun", original, owned)
        backend._winreg = lambda: winreg
        self.assertFalse(success); self.assertTrue(changed); self.assertIn("controlled integration-test write failure", evidence)
        self.assertEqual(_read_value(path, "Unrelated"), ("preserve", winreg.REG_SZ))
        self.assertEqual(_read_value(path, "NoDriveTypeAutoRun"), (145, winreg.REG_DWORD))
        self.assertEqual(_read_value(path, "NoAutorun"), (1, winreg.REG_DWORD))


if __name__ == "__main__":
    unittest.main()
