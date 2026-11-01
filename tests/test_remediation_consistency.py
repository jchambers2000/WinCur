from __future__ import annotations

import unittest
from unittest.mock import patch

from wincur.checks import ProbeError
from wincur.hardening import HardeningEngine, ManagementState, WindowsHardeningBackend, rollback_record_eligibility
from wincur.models import ActionOutcome


class _Key:
    def __init__(self, registry, path): self.registry, self.path = registry, path
    def __enter__(self): return self
    def __exit__(self, *_): return False


class FakeWinreg:
    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self, values=None, keys=None):
        self.values = dict(values or {}); self.keys = set()
        for path in [*(keys or []), *(path for path, _ in self.values)]: self._create_key(path)
        self.writes = []
        self.fail_write_number = None
        self.fail_delete_paths = set(); self.denied_paths = set(); self.deleted_keys = []

    @staticmethod
    def _parents(path):
        parts = path.split("\\"); return ["\\".join(parts[:index]) for index in range(1, len(parts) + 1)]

    def _create_key(self, path): self.keys.update(self._parents(path))

    def OpenKey(self, root, path, reserved, access):
        if path in self.denied_paths: raise PermissionError("access denied")
        if path not in self.keys: raise FileNotFoundError(path)
        return _Key(self, path)

    def CreateKeyEx(self, root, path, reserved, access):
        if path in self.denied_paths: raise PermissionError("access denied")
        self._create_key(path); return _Key(self, path)

    def QueryValueEx(self, key, name):
        try: return self.values[(key.path, name)]
        except KeyError: raise FileNotFoundError(name)

    def SetValueEx(self, key, name, reserved, value_type, value):
        if self.fail_write_number == len(self.writes) + 1:
            raise PermissionError("access denied")
        self.values[(key.path, name)] = (value, value_type)
        self.writes.append((key.path, name, value, value_type))

    def DeleteValue(self, key, name):
        if self.fail_write_number == len(self.writes) + 1:
            raise PermissionError("access denied")
        try: del self.values[(key.path, name)]
        except KeyError: raise FileNotFoundError(name)
        self.writes.append((key.path, name, None, None))

    def QueryInfoKey(self, key):
        prefix = key.path + "\\"
        children = {path[len(prefix):].split("\\", 1)[0] for path in self.keys if path.startswith(prefix)}
        values = sum(path == key.path for path, _ in self.values)
        return len(children), values, 0

    def DeleteKey(self, root, path):
        if path in self.fail_delete_paths: raise PermissionError("key deletion denied")
        if path not in self.keys: raise FileNotFoundError(path)
        prefix = path + "\\"
        if any(candidate.startswith(prefix) for candidate in self.keys) or any(value_path == path for value_path, _ in self.values):
            raise OSError("key is not empty")
        self.keys.remove(path); self.deleted_keys.append(path)


class FakeRunner:
    def __init__(self, profiles): self.profiles, self.commands = profiles, []
    def json(self, script):
        self.commands.append(script)
        if script.startswith("Set-NetFirewallProfile"):
            return self.profiles
        if isinstance(self.profiles, Exception): raise self.profiles
        return self.profiles


class ManagementRunner:
    def __init__(self, domain=False, matched=0): self.domain, self.matched, self.scripts = domain, matched, []
    def json(self, script):
        self.scripts.append(script)
        return {"DomainJoined": self.domain, "MatchedPolicyCount": self.matched}


class RemediationConsistencyTests(unittest.TestCase):
    AUTORUN_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    SCRIPT_PATH = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    MODULE_PATH = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    NAMES_PATH = MODULE_PATH + r"\ModuleNames"

    @staticmethod
    def backend(registry):
        backend = WindowsHardeningBackend()
        backend._winreg = lambda: registry
        return backend

    def test_autorun_apply_configures_and_verifies_both_values(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        original = backend.capture("disable_autorun")
        backend.apply("disable_autorun", original)
        self.assertEqual(registry.values[(self.AUTORUN_PATH, "NoDriveTypeAutoRun")], (255, registry.REG_DWORD))
        self.assertEqual(registry.values[(self.AUTORUN_PATH, "NoAutorun")], (1, registry.REG_DWORD))
        self.assertTrue(backend.verify("disable_autorun")[0])

    def test_stale_enrollment_registry_entries_do_not_classify_action_as_managed(self):
        registry = FakeWinreg(); runner = ManagementRunner(); backend = self.backend(registry); backend.runner = runner
        backend._mdm_registration_status = lambda: False
        state, evidence = backend.management_state("disable_autorun")
        self.assertEqual(state, ManagementState.UNMANAGED); self.assertIn("selected policy values are absent", evidence)
        self.assertFalse(any("Microsoft\\Enrollments" in script for script in runner.scripts))

    def test_supported_active_mdm_registration_remains_managed(self):
        registry = FakeWinreg(); backend = self.backend(registry); backend.runner = ManagementRunner(); backend._mdm_registration_status = lambda: True
        state, evidence = backend.management_state("disable_autorun")
        self.assertEqual(state, ManagementState.MANAGED); self.assertIn("active MDM registration", evidence)

    def test_matching_group_policy_remains_managed(self):
        registry = FakeWinreg(); backend = self.backend(registry); backend.runner = ManagementRunner(domain=True, matched=1); backend._mdm_registration_status = lambda: False
        state, evidence = backend.management_state("disable_autorun")
        self.assertEqual(state, ManagementState.MANAGED); self.assertIn("matching Group Policy", evidence)

    def test_unattributed_existing_policy_value_remains_blocked_as_unknown(self):
        registry = FakeWinreg({(self.AUTORUN_PATH, "NoAutorun"): (0, 4)})
        backend = self.backend(registry); backend.runner = ManagementRunner(); backend._mdm_registration_status = lambda: False
        state, evidence = backend.management_state("disable_autorun")
        self.assertEqual(state, ManagementState.UNKNOWN); self.assertIn("could not be reliably attributed", evidence)

    def test_mdm_registration_provider_failure_remains_blocked_as_unknown(self):
        registry = FakeWinreg(); backend = self.backend(registry); backend.runner = ManagementRunner()
        backend._mdm_registration_status = lambda: (_ for _ in ()).throw(OSError("provider unavailable"))
        state, evidence = backend.management_state("disable_autorun")
        self.assertEqual(state, ManagementState.UNKNOWN); self.assertIn("provider unavailable", evidence)

    def test_autorun_conflicting_value_fails_verification(self):
        registry = FakeWinreg({
            (self.AUTORUN_PATH, "NoDriveTypeAutoRun"): (255, 4),
            (self.AUTORUN_PATH, "NoAutorun"): (0, 4),
        })
        self.assertFalse(self.backend(registry).verify("disable_autorun")[0])

    def test_autorun_correct_data_with_wrong_registry_type_fails_verification(self):
        registry = FakeWinreg({
            (self.AUTORUN_PATH, "NoDriveTypeAutoRun"): (255, 1),
            (self.AUTORUN_PATH, "NoAutorun"): (1, 1),
        })
        self.assertFalse(self.backend(registry).verify("disable_autorun")[0])

    def test_powershell_apply_includes_script_block_module_and_all_modules(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        backend.apply("enable_powershell_logging", backend.capture("enable_powershell_logging"))
        self.assertEqual(registry.values[(self.SCRIPT_PATH, "EnableScriptBlockLogging")], (1, 4))
        self.assertEqual(registry.values[(self.MODULE_PATH, "EnableModuleLogging")], (1, 4))
        self.assertEqual(registry.values[(self.NAMES_PATH, "*")], ("*", 1))
        self.assertTrue(backend.verify("enable_powershell_logging")[0])

    def test_apply_rejects_external_change_before_registry_write(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        expected = backend.capture("disable_autorun")
        registry._create_key(self.AUTORUN_PATH)
        registry.values[(self.AUTORUN_PATH, "NoAutorun")] = (0, 4)
        with self.assertRaisesRegex(RuntimeError, "changed after preview"):
            backend.apply("disable_autorun", expected)
        self.assertEqual(registry.writes, [])

    def test_rollback_restores_existing_and_absent_values(self):
        registry = FakeWinreg({(self.AUTORUN_PATH, "NoDriveTypeAutoRun"): (145, 4)})
        backend = self.backend(registry)
        original = backend.capture("disable_autorun")
        backend.apply("disable_autorun", original)
        owned = backend.capture("disable_autorun")
        successful, changed, _ = backend.rollback("disable_autorun", original, owned)
        self.assertTrue(successful); self.assertTrue(changed)
        self.assertEqual(registry.values[(self.AUTORUN_PATH, "NoDriveTypeAutoRun")], (145, 4))
        self.assertNotIn((self.AUTORUN_PATH, "NoAutorun"), registry.values)

    def test_capture_distinguishes_existing_key_with_missing_value(self):
        registry = FakeWinreg(keys=[self.AUTORUN_PATH]); state = self.backend(registry).capture("disable_autorun")
        keys = {item["path"]: item["exists"] for item in state["keys"]}
        self.assertTrue(keys[self.AUTORUN_PATH]); self.assertTrue(all(not item["exists"] for item in state["values"]))

    def test_capture_distinguishes_completely_absent_key(self):
        state = self.backend(FakeWinreg()).capture("disable_autorun"); keys = {item["path"]: item["exists"] for item in state["keys"]}
        self.assertFalse(keys[self.AUTORUN_PATH]); self.assertEqual(state["schema_version"], 2)

    def test_newly_created_empty_keys_are_removed_but_preexisting_key_is_preserved(self):
        parent = self.AUTORUN_PATH.rsplit("\\", 1)[0]; registry = FakeWinreg(keys=[parent]); backend = self.backend(registry)
        original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun")
        successful, _, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertTrue(successful); self.assertNotIn(self.AUTORUN_PATH, registry.keys); self.assertIn(parent, registry.keys); self.assertIn("key structure", evidence)

        registry = FakeWinreg(keys=[self.AUTORUN_PATH]); backend = self.backend(registry); original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun")
        self.assertTrue(backend.rollback("disable_autorun", original, owned)[0]); self.assertIn(self.AUTORUN_PATH, registry.keys)

    def test_unrelated_value_preserves_created_key_and_reports_partial(self):
        parent = self.AUTORUN_PATH.rsplit("\\", 1)[0]; registry = FakeWinreg(keys=[parent]); backend = self.backend(registry)
        original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun")
        registry.values[(self.AUTORUN_PATH, "UnrelatedValue")] = (7, registry.REG_DWORD)
        successful, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(successful); self.assertTrue(changed); self.assertIn("safely skipped", evidence)
        self.assertIn(self.AUTORUN_PATH, registry.keys); self.assertEqual(registry.values[(self.AUTORUN_PATH, "UnrelatedValue")], (7, registry.REG_DWORD))

    def test_unrelated_subkey_preserves_created_key_and_reports_partial(self):
        parent = self.AUTORUN_PATH.rsplit("\\", 1)[0]; unrelated = self.AUTORUN_PATH + r"\Unrelated"; registry = FakeWinreg(keys=[parent]); backend = self.backend(registry)
        original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun"); registry._create_key(unrelated)
        successful, _, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(successful); self.assertIn("safely skipped", evidence); self.assertIn(unrelated, registry.keys); self.assertIn(self.AUTORUN_PATH, registry.keys)

    def test_powershell_nested_keys_are_removed_child_first(self):
        power_shell_parent = r"SOFTWARE\Policies\Microsoft\Windows"; registry = FakeWinreg(keys=[power_shell_parent]); backend = self.backend(registry)
        original = backend.capture("enable_powershell_logging"); backend.apply("enable_powershell_logging", original); owned = backend.capture("enable_powershell_logging")
        successful, _, _ = backend.rollback("enable_powershell_logging", original, owned)
        module = self.MODULE_PATH; names = self.NAMES_PATH; root = module.rsplit("\\", 1)[0]
        self.assertTrue(successful); self.assertLess(registry.deleted_keys.index(names), registry.deleted_keys.index(module)); self.assertLess(registry.deleted_keys.index(module), registry.deleted_keys.index(root))

    def test_original_powershell_values_and_registry_types_are_restored(self):
        registry = FakeWinreg({
            (self.SCRIPT_PATH, "EnableScriptBlockLogging"): (0, FakeWinreg.REG_DWORD),
            (self.MODULE_PATH, "EnableModuleLogging"): (0, FakeWinreg.REG_DWORD),
            (self.NAMES_PATH, "*"): ("SelectedModule", FakeWinreg.REG_SZ),
        }); backend = self.backend(registry); original = backend.capture("enable_powershell_logging")
        backend.apply("enable_powershell_logging", original); owned = backend.capture("enable_powershell_logging")
        self.assertTrue(backend.rollback("enable_powershell_logging", original, owned)[0])
        self.assertEqual(registry.values[(self.SCRIPT_PATH, "EnableScriptBlockLogging")], (0, FakeWinreg.REG_DWORD)); self.assertEqual(registry.values[(self.NAMES_PATH, "*")], ("SelectedModule", FakeWinreg.REG_SZ))

    def test_partial_remediation_failure_retains_exact_partial_state(self):
        registry = FakeWinreg(); backend = self.backend(registry); original = backend.capture("disable_autorun"); registry.fail_write_number = 2
        with self.assertRaises(PermissionError): backend.apply("disable_autorun", original)
        partial = backend.capture("disable_autorun"); values = {item["name"]: item for item in partial["values"]}
        self.assertTrue(values["NoDriveTypeAutoRun"]["exists"]); self.assertFalse(values["NoAutorun"]["exists"])

    def test_repeated_rollback_is_rejected_without_changes(self):
        registry = FakeWinreg(); backend = self.backend(registry); original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun")
        self.assertTrue(backend.rollback("disable_autorun", original, owned)[0]); writes = list(registry.writes); second = backend.rollback("disable_autorun", original, owned)
        self.assertEqual(second[:2], (False, False)); self.assertEqual(registry.writes, writes)

    def test_legacy_snapshot_restores_values_without_key_cleanup(self):
        registry = FakeWinreg(keys=[self.AUTORUN_PATH]); backend = self.backend(registry)
        current_original = backend.capture("disable_autorun"); legacy_original = {"values": current_original["values"]}
        backend.apply("disable_autorun", current_original); current_owned = backend.capture("disable_autorun"); legacy_owned = {"values": current_owned["values"]}
        record = {"action_id": "disable_autorun", "rollback_available": True, "original_configuration": legacy_original, "requested_configuration": legacy_owned}
        self.assertTrue(rollback_record_eligibility(record)[0])
        successful, _, evidence = backend.rollback("disable_autorun", legacy_original, legacy_owned)
        self.assertTrue(successful); self.assertIn("Legacy snapshot", evidence); self.assertIn(self.AUTORUN_PATH, registry.keys)

    def test_malformed_and_incorrectly_eligible_legacy_records_are_rejected(self):
        malformed = {"action_id": "disable_autorun", "rollback_available": True, "original_configuration": {"values": []}, "requested_configuration": {"recommended": "legacy"}}
        eligible, reason = rollback_record_eligibility(malformed)
        self.assertFalse(eligible); self.assertIn("schema", reason.lower())

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_engine_audit_result_distinguishes_complete_and_partial_key_restore(self, mocked_admin):
        parent = self.AUTORUN_PATH.rsplit("\\", 1)[0]; registry = FakeWinreg(keys=[parent]); backend = self.backend(registry); engine = HardeningEngine(backend)
        original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun")
        record = {"timestamp_utc": "2026-10-30T12:00:00+00:00", "action_id": "disable_autorun", "rollback_available": True, "rollback_snapshot_schema": 2, "original_configuration": original, "requested_configuration": owned}
        result = engine.rollback(record, True); self.assertEqual(result.outcome, ActionOutcome.SUCCESS); self.assertEqual(result.rollback_status, "Completed"); self.assertIn("key structure", result.verification_evidence); self.assertEqual(result.rollback_source_timestamp_utc, record["timestamp_utc"])

        registry = FakeWinreg(keys=[parent]); backend = self.backend(registry); engine = HardeningEngine(backend); original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun"); registry.values[(self.AUTORUN_PATH, "Unrelated")] = (1, 4)
        record.update(original_configuration=original, requested_configuration=owned); result = engine.rollback(record, True)
        self.assertEqual(result.outcome, ActionOutcome.PARTIAL); self.assertEqual(result.rollback_status, "Partial"); self.assertIn("safely skipped", result.verification_evidence)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_engine_records_version_two_rollback_snapshot(self, mocked_admin):
        registry = FakeWinreg(); backend = self.backend(registry); backend.management_state = lambda action_id: (ManagementState.UNMANAGED, "mock unmanaged")
        engine = HardeningEngine(backend); preview = engine.preview("disable_autorun"); record = engine.execute("disable_autorun", True, preview.preview_token, preview.created_utc)
        self.assertEqual(record.outcome, ActionOutcome.SUCCESS); self.assertTrue(record.rollback_available); self.assertEqual(record.rollback_snapshot_schema, 2)
        self.assertEqual(record.original_configuration["schema_version"], 2); self.assertEqual(record.requested_configuration["schema_version"], 2)

    def test_access_denied_during_key_capture_is_not_treated_as_missing(self):
        registry = FakeWinreg(); registry.denied_paths.add("SOFTWARE"); backend = self.backend(registry)
        with self.assertRaises(PermissionError): backend.capture("disable_autorun")

    def test_key_cleanup_access_failure_reports_partial_rollback(self):
        parent = self.AUTORUN_PATH.rsplit("\\", 1)[0]; registry = FakeWinreg(keys=[parent]); backend = self.backend(registry)
        original = backend.capture("disable_autorun"); backend.apply("disable_autorun", original); owned = backend.capture("disable_autorun"); registry.fail_delete_paths.add(self.AUTORUN_PATH)
        successful, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(successful); self.assertTrue(changed); self.assertIn("key cleanup failed", evidence); self.assertIn(self.AUTORUN_PATH, registry.keys)

    def test_rollback_preserves_external_change(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        original = backend.capture("disable_autorun")
        backend.apply("disable_autorun", original)
        owned = backend.capture("disable_autorun")
        registry.values[(self.AUTORUN_PATH, "NoAutorun")] = (0, 4)
        successful, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(successful); self.assertFalse(changed)
        self.assertIn("newer changes were preserved", evidence)
        self.assertEqual(registry.values[(self.AUTORUN_PATH, "NoAutorun")], (0, 4))

    def test_rollback_reports_partial_write_failure(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        original = backend.capture("disable_autorun")
        backend.apply("disable_autorun", original)
        owned = backend.capture("disable_autorun")
        registry.writes.clear(); registry.fail_write_number = 2
        successful, changed, evidence = backend.rollback("disable_autorun", original, owned)
        self.assertFalse(successful); self.assertTrue(changed); self.assertIn("access denied", evidence)

    def test_malformed_rollback_data_is_rejected_before_any_write(self):
        registry = FakeWinreg()
        backend = self.backend(registry)
        original = backend.capture("disable_autorun")
        backend.apply("disable_autorun", original)
        owned = backend.capture("disable_autorun")
        malformed = {**original, "keys": [dict(item) for item in original["keys"]], "values": [dict(item) for item in original["values"]]}
        malformed["values"][1].update(exists=True, value="not-a-dword", type=4)
        registry.writes.clear()
        successful, changed, evidence = backend.rollback("disable_autorun", malformed, owned)
        self.assertFalse(successful); self.assertFalse(changed)
        self.assertEqual(registry.writes, []); self.assertIn("DWORD data was invalid", evidence)

    @staticmethod
    def profiles(domain=True, private=True, public=True):
        return [
            {"Name": "Domain", "Enabled": domain, "PolicyStoreSourceType": "Local"},
            {"Name": "Private", "Enabled": private, "PolicyStoreSourceType": "Local"},
            {"Name": "Public", "Enabled": public, "PolicyStoreSourceType": "Local"},
        ]

    def test_firewall_only_targets_profiles_disabled_in_expected_state(self):
        runner = FakeRunner(self.profiles(domain=True, private=False, public=True))
        backend = WindowsHardeningBackend(runner)
        original = backend.capture("enable_firewall_profiles")
        backend.apply("enable_firewall_profiles", original)
        set_commands = [command for command in runner.commands if command.startswith("Set-NetFirewallProfile")]
        self.assertEqual(len(set_commands), 1)
        self.assertIn("-Profile Private ", set_commands[0])
        self.assertNotIn("Domain", set_commands[0]); self.assertNotIn("Public", set_commands[0])

    def test_firewall_already_compliant_apply_is_a_noop(self):
        runner = FakeRunner(self.profiles())
        backend = WindowsHardeningBackend(runner)
        backend.apply("enable_firewall_profiles", backend.capture("enable_firewall_profiles"))
        self.assertFalse(any(command.startswith("Set-NetFirewallProfile") for command in runner.commands))

    def test_firewall_rejects_missing_or_malformed_profile_state(self):
        for profiles in (self.profiles()[:2], self.profiles(domain="False")):
            with self.subTest(profiles=profiles):
                with self.assertRaises(ProbeError):
                    WindowsHardeningBackend(FakeRunner(profiles)).capture("enable_firewall_profiles")

    def test_firewall_rejects_managed_policy_during_apply(self):
        profiles = self.profiles(domain=False)
        profiles[0]["PolicyStoreSourceType"] = "GroupPolicy"
        backend = WindowsHardeningBackend(FakeRunner(profiles))
        original = backend.capture("enable_firewall_profiles")
        with self.assertRaisesRegex(RuntimeError, "organizationally managed"):
            backend.apply("enable_firewall_profiles", original)

    def test_firewall_access_denied_is_not_success(self):
        with self.assertRaises(ProbeError):
            WindowsHardeningBackend(FakeRunner(ProbeError("access denied"))).capture("enable_firewall_profiles")


if __name__ == "__main__":
    unittest.main()
