"""Reusable, opt-in hardening framework.

Only the three trusted action identifiers in ACTIONS can reach mutation code.
The UI supplies no PowerShell or registry paths. Every execution captures state,
applies one action, verifies it, and returns a structured record.
"""

from __future__ import annotations

import os
import ctypes
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from .checks import PowerShellRunner, ProbeError
from .models import ActionAvailability, ActionOutcome, ActionPreview, ActionRecord
from .privileges import is_administrator


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    title: str
    finding: str
    severity: str
    recommended: str
    rationale: str
    compatibility: str
    permissions: str
    exact_change: str
    verification: str
    rollback: str


ACTIONS: dict[str, ActionDefinition] = {
    "disable_autorun": ActionDefinition(
        "disable_autorun", "Disable AutoRun", "AutoRun policy", "Medium",
        "Disable AutoRun commands for all drive types.", "Reduces automatic command execution from removable and mounted media.",
        "Users must open removable-media content manually; legacy media workflows may change.", "Administrator",
        "Set HKLM Explorer policy values NoDriveTypeAutoRun=255 and NoAutorun=1 (DWORD).",
        "Read both policy values and require the requested DWORD values.",
        "Captured values can be restored, and operation-created keys are removed only when recorded as originally absent and still empty; confirmation is required."),
    "enable_powershell_logging": ActionDefinition(
        "enable_powershell_logging", "Enable PowerShell audit logging", "PowerShell audit logging", "Medium",
        "Enable Script Block Logging and Module Logging.", "Improves investigation and detection of PowerShell activity.",
        "Creates additional event data that may contain command content; plan retention, access, and privacy controls.", "Administrator",
        "Set EnableScriptBlockLogging=1, EnableModuleLogging=1, and ModuleNames wildcard=* under documented HKLM PowerShell policy keys.",
        "Read both enable values and require the ModuleNames wildcard.",
        "Captured values can be restored after confirmation; operation-created empty keys are removed only when their original absence is trustworthy."),
    "enable_firewall_profiles": ActionDefinition(
        "enable_firewall_profiles", "Enable Windows Firewall profiles", "Windows Firewall profiles", "Critical",
        "Enable every disabled Domain, Private, and Public profile.", "Reduces unfiltered network exposure.",
        "Unapproved inbound connections may stop working; review application firewall rules instead of disabling profiles.", "Administrator",
        "Use Set-NetFirewallProfile only for trusted profile names that are currently disabled.",
        "Read ActiveStore profiles and require Enabled=True for Domain, Private, and Public.",
        "Automatic rollback is unavailable because disabling a firewall profile would weaken protection."),
}


class HardeningBackend(Protocol):
    def management_state(self, action_id: str) -> tuple["ManagementState", str]: ...
    def capture(self, action_id: str) -> dict[str, Any]: ...
    def apply(self, action_id: str, expected_state: dict[str, Any]) -> None: ...
    def verify(self, action_id: str) -> tuple[bool, str]: ...
    def describe(self, action_id: str, state: dict[str, Any]) -> tuple[str, str]: ...
    def rollback(self, action_id: str, original: dict[str, Any], owned_state: dict[str, Any]) -> tuple[bool, bool, str]: ...


class ManagementState(str, Enum):
    UNMANAGED = "Unmanaged"
    MANAGED = "Managed"
    REQUIRES_ELEVATION = "RequiresElevation"
    UNKNOWN = "Unknown"


REGISTRY_ACTIONS: dict[str, tuple[tuple[str, str, Any], ...]] = {
    "disable_autorun": (
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun", 1),
    ),
    "enable_powershell_logging": (
        (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames", "*", "*"),
    ),
}

REGISTRY_SNAPSHOT_SCHEMA_VERSION = 2


class WindowsHardeningBackend:
    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self.runner = runner or PowerShellRunner()
        self._registry_actions = REGISTRY_ACTIONS
        self._registry_hive_name = "HKEY_LOCAL_MACHINE"

    @classmethod
    def _for_registry_integration_tests(
        cls,
        action_id: str,
        owned_root: str,
        targets: tuple[tuple[str, str, Any], ...],
    ) -> "WindowsHardeningBackend":
        """Build an HKCU-only backend for the opt-in Windows integration suite.

        This deliberately private factory is not referenced by the application UI.
        It accepts only a UUID-owned child of WinCur's integration-test namespace
        and preserves the selected production action's target count, value names,
        and requested data.  It cannot redirect an action to an arbitrary path or
        alter what that action writes.
        """
        if os.name != "nt" or os.environ.get("WINCUR_RUN_REGISTRY_INTEGRATION") != "1":
            raise RuntimeError("Registry integration backends require Windows and WINCUR_RUN_REGISTRY_INTEGRATION=1.")
        if action_id not in REGISTRY_ACTIONS:
            raise ValueError("Only an existing trusted registry action can be exercised.")
        prefix = r"Software\WinCur\IntegrationTests"
        normalized_root = owned_root.strip("\\")
        parts = normalized_root.split("\\")
        if len(parts) != 4 or "\\".join(parts[:3]).casefold() != prefix.casefold():
            raise ValueError("The integration-test root must be a unique direct child of the trusted HKCU namespace.")
        try:
            unique_id = uuid.UUID(parts[3])
        except (AttributeError, ValueError) as exc:
            raise ValueError("The integration-test root must end with a UUID owned by this test run.") from exc
        if str(unique_id).casefold() != parts[3].casefold():
            raise ValueError("The integration-test UUID must use canonical form.")
        production = REGISTRY_ACTIONS[action_id]
        if len(targets) != len(production):
            raise ValueError("The integration target schema must match the trusted production action.")
        trusted_tail = tuple((name, desired) for _, name, desired in production)
        supplied_tail = tuple((name, desired) for _, name, desired in targets)
        if supplied_tail != trusted_tail:
            raise ValueError("Integration targets cannot change trusted value names or requested data.")
        root_prefix = normalized_root.casefold() + "\\"
        if any(not path.casefold().startswith(root_prefix) for path, _, _ in targets):
            raise ValueError("Every integration target must be below the uniquely owned test root.")
        backend = cls()
        # The isolated backend exposes only this one redirected action.  It
        # cannot fall through to another production action under HKCU.
        backend._registry_actions = {action_id: tuple(targets)}
        backend._registry_hive_name = "HKEY_CURRENT_USER"
        return backend

    @staticmethod
    def _winreg():
        if os.name != "nt": raise OSError("Windows registry operations are supported only on Windows.")
        import winreg
        return winreg

    def _registry_hive(self, winreg):
        return getattr(winreg, self._registry_hive_name)

    def _registry_targets(self, action_id: str) -> tuple[tuple[str, str, Any], ...]:
        return self._registry_actions[action_id]

    @staticmethod
    def _registry_values_for_targets(
        state: dict[str, Any], targets: tuple[tuple[str, str, Any], ...]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        expected = {(path, name) for path, name, _ in targets}
        items = state.get("values")
        if not isinstance(items, list) or len(items) != len(expected):
            raise ValueError("Registry state did not match the trusted action schema.")
        mapped: dict[tuple[str, str], dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Registry state contained a malformed item.")
            key = (str(item.get("path")), str(item.get("name")))
            if key not in expected or key in mapped or not isinstance(item.get("exists"), bool):
                raise ValueError("Registry state did not match the trusted action schema.")
            mapped[key] = item
        return mapped

    @staticmethod
    def _mdm_registration_status() -> bool:
        """Use the supported Windows MDM registration API without requesting a UPN."""
        if os.name != "nt":
            raise OSError("Windows MDM registration status is supported only on Windows.")
        registered = ctypes.c_long(0)
        library = ctypes.WinDLL("MDMRegistration.dll", use_last_error=True)
        function = library.IsDeviceRegisteredWithManagement
        function.argtypes = (ctypes.POINTER(ctypes.c_long), ctypes.c_ulong, ctypes.c_wchar_p)
        function.restype = ctypes.c_long
        result = int(function(ctypes.byref(registered), 0, None))
        if result != 0:
            raise OSError(f"IsDeviceRegisteredWithManagement failed with HRESULT 0x{result & 0xFFFFFFFF:08X}.")
        return bool(registered.value)

    @staticmethod
    def _boolean(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        raise ProbeError(f"Firewall Enabled returned an invalid value: {value!r}")

    @staticmethod
    def _registry_values(action_id: str, state: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        return WindowsHardeningBackend._registry_values_for_targets(state, REGISTRY_ACTIONS[action_id])

    def _state_values(self, action_id: str, state: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        return self._registry_values_for_targets(state, self._registry_targets(action_id))

    @staticmethod
    def _registry_key_paths(action_id: str) -> tuple[str, ...]:
        return WindowsHardeningBackend._key_paths_for_targets(REGISTRY_ACTIONS[action_id])

    @staticmethod
    def _key_paths_for_targets(targets: tuple[tuple[str, str, Any], ...]) -> tuple[str, ...]:
        paths: set[str] = set()
        for target, _, _ in targets:
            parts = target.split("\\")
            paths.update("\\".join(parts[:index]) for index in range(1, len(parts) + 1))
        return tuple(sorted(paths, key=lambda path: (path.count("\\"), path.casefold())))

    def _key_paths(self, action_id: str) -> tuple[str, ...]:
        return self._key_paths_for_targets(self._registry_targets(action_id))

    @classmethod
    def _registry_keys(cls, action_id: str, state: dict[str, Any]) -> dict[str, bool]:
        return cls._registry_keys_for_paths(state, cls._registry_key_paths(action_id))

    @staticmethod
    def _registry_keys_for_paths(state: dict[str, Any], paths: tuple[str, ...]) -> dict[str, bool]:
        expected = set(paths); items = state.get("keys")
        if state.get("schema_version") != REGISTRY_SNAPSHOT_SCHEMA_VERSION or not isinstance(items, list) or len(items) != len(expected):
            raise ValueError("Registry key state did not match snapshot schema version 2.")
        mapped: dict[str, bool] = {}
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("exists"), bool):
                raise ValueError("Registry key state contained a malformed item.")
            path = str(item.get("path"))
            if path not in expected or path in mapped:
                raise ValueError("Registry key state did not match the trusted action schema.")
            mapped[path] = item["exists"]
        return mapped

    def _state_keys(self, action_id: str, state: dict[str, Any]) -> dict[str, bool]:
        return self._registry_keys_for_paths(state, self._key_paths(action_id))

    @staticmethod
    def _values_equal(left: dict[tuple[str, str], dict[str, Any]], right: dict[tuple[str, str], dict[str, Any]]) -> bool:
        fields = ("exists", "value", "type")
        return left.keys() == right.keys() and all(all(left[key].get(field) == right[key].get(field) for field in fields) for key in left)

    def management_state(self, action_id: str) -> tuple[ManagementState, str]:
        try:
            if action_id == "enable_firewall_profiles":
                data = self.runner.json("@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,PolicyStoreSourceType)")
                profiles = data if isinstance(data, list) else [data]
                sources = {str(item.get("Name")): str(item.get("PolicyStoreSourceType", "Unknown")) for item in profiles if item}
                managed = any("group" in source.lower() or "mdm" in source.lower() for source in sources.values())
                return (ManagementState.MANAGED if managed else ManagementState.UNMANAGED), "Active firewall policy sources: " + ", ".join(f"{k}={v}" for k, v in sources.items())
            policy_filter = {
                "disable_autorun": "($_.ValueName -in @('NoDriveTypeAutoRun','NoAutorun') -and $_.KeyName -like '*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer')",
                "enable_powershell_logging": "($_.ValueName -in @('EnableScriptBlockLogging','EnableModuleLogging','*') -and $_.KeyName -like '*\\Microsoft\\Windows\\PowerShell\\*')",
            }
            data = self.runner.json(
                "$domain=[bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain; $matched=@(); "
                f"if($domain){{$matched=@(Get-CimInstance -Namespace root/RSOP/Computer -ClassName RSOP_RegistryPolicySetting -ErrorAction Stop | Where-Object {{{policy_filter[action_id]}}} | Select-Object KeyName,ValueName,GPOID)}}; "
                "[pscustomobject]@{DomainJoined=$domain;MatchedPolicyCount=$matched.Count}"
            )
            if not isinstance(data, dict) or not isinstance(data.get("DomainJoined"), bool):
                raise ValueError("The policy-management provider returned malformed domain state.")
            matched_value = data.get("MatchedPolicyCount")
            if isinstance(matched_value, bool) or not isinstance(matched_value, int) or matched_value < 0:
                raise ValueError("The policy-management provider returned a malformed policy count.")
            domain = data["DomainJoined"]; matched = matched_value
            mdm_registered = self._mdm_registration_status()
            if matched > 0 or mdm_registered:
                reason = "matching Group Policy settings are present" if matched > 0 else "Windows reports active MDM registration"
                return ManagementState.MANAGED, f"Domain joined={domain}; matching Group Policy settings={matched}; MDM registered={mdm_registered}. Managed because {reason}."
            state = self.capture(action_id)
            existing = [item["name"] for item in state.get("values", []) if item.get("exists")]
            if existing:
                return ManagementState.UNKNOWN, f"Domain joined={domain}; matching Group Policy settings={matched}; MDM registered={mdm_registered}. Existing policy values could not be reliably attributed: {', '.join(existing)}."
            return ManagementState.UNMANAGED, f"Domain joined={domain}; matching Group Policy settings={matched}; MDM registered={mdm_registered}; selected policy values are absent."
        except (OSError, ProbeError, TypeError, ValueError, AttributeError) as exc:
            detail = str(exc)
            if "access" in detail.lower() or "denied" in detail.lower() or "unauthorized" in detail.lower():
                return ManagementState.REQUIRES_ELEVATION, f"Administrator access is required to determine policy management: {detail}"
            return ManagementState.UNKNOWN, f"Management status could not be determined reliably: {detail}"

    def capture(self, action_id: str) -> dict[str, Any]:
        if action_id in self._registry_actions:
            winreg = self._winreg(); values: list[dict[str, Any]] = []; key_state: dict[str, bool] = {}
            hive = self._registry_hive(winreg)
            for path in self._key_paths(action_id):
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ): key_state[path] = True
                except FileNotFoundError: key_state[path] = False
            for path, name, desired in self._registry_targets(action_id):
                item: dict[str, Any] = {"path": path, "name": name, "exists": False, "value": None, "type": None}
                if key_state[path]:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                        try:
                            value, value_type = winreg.QueryValueEx(key, name); item.update(exists=True, value=value, type=value_type)
                        except FileNotFoundError: pass
                values.append(item)
            return {"schema_version": REGISTRY_SNAPSHOT_SCHEMA_VERSION, "keys": [{"path": path, "exists": key_state[path]} for path in self._key_paths(action_id)], "values": values}
        if action_id == "enable_firewall_profiles":
            data = self.runner.json("@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,PolicyStoreSourceType)")
            profiles = data if isinstance(data, list) else [data]
            captured: dict[str, dict[str, Any]] = {}
            for profile in profiles:
                if not isinstance(profile, dict):
                    continue
                name = str(profile.get("Name"))
                if name in {"Domain", "Private", "Public"}:
                    if name in captured:
                        raise ProbeError(f"Firewall returned duplicate {name} profiles.")
                    captured[name] = {"name": name, "enabled": self._boolean(profile.get("Enabled")), "source": str(profile.get("PolicyStoreSourceType", "Unknown"))}
            if set(captured) != {"Domain", "Private", "Public"}:
                raise ProbeError("Firewall did not return all Domain, Private, and Public profiles.")
            return {"profiles": [captured[name] for name in ("Domain", "Private", "Public")]}
        raise ValueError("Unsupported action identifier.")

    def apply(self, action_id: str, expected_state: dict[str, Any]) -> None:
        if action_id in self._registry_actions:
            self._state_values(action_id, expected_state)
            if self.capture(action_id) != expected_state:
                raise RuntimeError("Configuration changed after preview; no registry writes were attempted.")
            winreg = self._winreg(); hive = self._registry_hive(winreg)
            for path, name, desired in self._registry_targets(action_id):
                with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
                    value_type = winreg.REG_DWORD if isinstance(desired, int) else winreg.REG_SZ
                    winreg.SetValueEx(key, name, 0, value_type, desired)
            return
        if action_id == "enable_firewall_profiles":
            original = self.capture(action_id)
            if original != expected_state:
                raise RuntimeError("Firewall configuration changed after preview; no changes were attempted.")
            if any("group" in p["source"].lower() or "mdm" in p["source"].lower() for p in original["profiles"]):
                raise RuntimeError("Firewall policy is organizationally managed; no changes were attempted.")
            disabled = [p["name"] for p in original["profiles"] if not p["enabled"]]
            allowed = [name for name in disabled if name in {"Domain", "Private", "Public"}]
            if allowed:
                self.runner.json(f"Set-NetFirewallProfile -Profile {','.join(allowed)} -Enabled True; @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled)")
            return
        raise ValueError("Unsupported action identifier.")

    def verify(self, action_id: str) -> tuple[bool, str]:
        state = self.capture(action_id)
        if action_id in self._registry_actions:
            desired = {(path, name): value for path, name, value in self._registry_targets(action_id)}
            winreg = self._winreg()
            mismatches = [
                f"{item['name']}={item['value']}"
                for item in state["values"]
                if not item["exists"]
                or item["value"] != desired[(item["path"], item["name"])]
                or item["type"] != (winreg.REG_DWORD if isinstance(desired[(item["path"], item["name"])], int) else winreg.REG_SZ)
            ]
            return not mismatches, "All requested policy values verified." if not mismatches else "Unverified values: " + ", ".join(mismatches)
        profiles = state.get("profiles", []); disabled = [p["name"] for p in profiles if not p["enabled"]]
        complete = len(profiles) == 3 and not disabled
        return complete, "All firewall profiles are enabled." if complete else "Disabled or missing profiles: " + ", ".join(disabled or ["one or more profiles missing"])

    def describe(self, action_id: str, state: dict[str, Any]) -> tuple[str, str]:
        technical = json.dumps(state, indent=2, sort_keys=True)
        if action_id == "disable_autorun":
            values = {item["name"]: item for item in state.get("values", [])}
            drive = values.get("NoDriveTypeAutoRun", {}); autorun = values.get("NoAutorun", {})
            summary = f"All-drive AutoRun policy: {'configured' if drive.get('exists') and drive.get('type') == 4 and drive.get('value') == 255 else 'not configured'}; AutoRun commands: {'disabled' if autorun.get('exists') and autorun.get('type') == 4 and autorun.get('value') == 1 else 'not disabled'}."
            return summary, technical
        if action_id == "enable_powershell_logging":
            values = {item["name"]: item for item in state.get("values", [])}
            enabled = lambda name, expected: values.get(name, {}).get("exists") and values.get(name, {}).get("value") == expected and values.get(name, {}).get("type") == (4 if isinstance(expected, int) else 1)
            summary = f"Script Block Logging: {'enabled' if enabled('EnableScriptBlockLogging', 1) else 'not enabled'}; Module Logging: {'enabled' if enabled('EnableModuleLogging', 1) else 'not enabled'}; all-modules rule: {'configured' if enabled('*', '*') else 'not configured'}."
            return summary, technical
        profiles = state.get("profiles", []); enabled = [p["name"] for p in profiles if p.get("enabled")]; disabled = [p["name"] for p in profiles if not p.get("enabled")]
        summary = "All Domain, Private, and Public firewall profiles are enabled." if len(enabled) == 3 and not disabled else "Enabled profiles: " + (", ".join(enabled) or "none") + "; disabled or missing: " + (", ".join(disabled) or "one or more missing") + "."
        return summary, technical

    def rollback(self, action_id: str, original: dict[str, Any], owned_state: dict[str, Any]) -> tuple[bool, bool, str]:
        if action_id == "enable_firewall_profiles":
            return False, False, "Automatic firewall rollback is intentionally unavailable because it could disable protection."
        if action_id not in self._registry_actions: return False, False, "This action does not support rollback."
        try:
            original_values = self._state_values(action_id, original)
            owned_values = self._state_values(action_id, owned_state)
            version = original.get("schema_version", 1)
            if version != owned_state.get("schema_version", 1) or version not in (1, REGISTRY_SNAPSHOT_SCHEMA_VERSION):
                raise ValueError("Rollback snapshot versions were inconsistent or unsupported.")
            original_keys = self._state_keys(action_id, original) if version == REGISTRY_SNAPSHOT_SCHEMA_VERSION else None
            owned_keys = self._state_keys(action_id, owned_state) if version == REGISTRY_SNAPSHOT_SCHEMA_VERSION else None
            current = self.capture(action_id); current_values = self._state_values(action_id, current)
            if not self._values_equal(current_values, owned_values):
                return False, False, "Rollback stopped because the configuration changed after this operation; newer changes were preserved."
            if owned_keys is not None and self._state_keys(action_id, current) != owned_keys:
                return False, False, "Rollback stopped because the registry key structure changed after this operation; newer changes were preserved."
        except (OSError, ProbeError, TypeError, ValueError) as exc:
            return False, False, f"Rollback precondition failed: {exc}"
        winreg = self._winreg(); hive = self._registry_hive(winreg); changed = False
        for path, name, _ in self._registry_targets(action_id):
            item = original_values[(path, name)]
            if not item.get("exists"):
                continue
            value_type, value = item.get("type"), item.get("value")
            if value_type not in (winreg.REG_DWORD, winreg.REG_SZ): return False, False, "Rollback contains an unsupported registry value type."
            if value_type == winreg.REG_DWORD and (not isinstance(value, int) or isinstance(value, bool)): return False, False, "Rollback DWORD data was invalid."
            if value_type == winreg.REG_SZ and not isinstance(value, str): return False, False, "Rollback string data was invalid."
        cleanup_skipped: list[str] = []; cleanup_failed: list[str] = []; removed_keys: list[str] = []
        try:
            for path, name, _ in self._registry_targets(action_id):
                item = original_values[(path, name)]
                with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
                    if bool(item.get("exists")):
                        value_type, value = int(item.get("type")), item.get("value")
                        winreg.SetValueEx(key, name, 0, value_type, value)
                        changed = True
                    else:
                        try:
                            winreg.DeleteValue(key, name)
                            changed = True
                        except FileNotFoundError: pass
            if original_keys is not None and owned_keys is not None:
                candidates = [path for path in self._key_paths(action_id) if not original_keys[path] and owned_keys[path]]
                for path in sorted(candidates, key=lambda value: (value.count("\\"), value.casefold()), reverse=True):
                    try:
                        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                            subkey_count, value_count, _ = winreg.QueryInfoKey(key)
                        if subkey_count or value_count:
                            cleanup_skipped.append(path); continue
                        winreg.DeleteKey(hive, path); removed_keys.append(path); changed = True
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        cleanup_failed.append(f"{path}: {exc}")
            verified_state = self.capture(action_id); verified_values = self._state_values(action_id, verified_state)
            values_restored = self._values_equal(verified_values, original_values)
            keys_restored = True if original_keys is None else self._state_keys(action_id, verified_state) == original_keys
            if values_restored and keys_restored and not cleanup_failed:
                if original_keys is None:
                    return True, changed, "Original registry values were restored and verified. Legacy snapshot: original key existence was not recorded, so key cleanup was not attempted."
                return True, changed, f"Original registry values and key structure were restored and verified. Removed {len(removed_keys)} operation-created empty key(s)."
            details = []
            if not values_restored: details.append("original target values were not fully restored")
            if cleanup_skipped: details.append("key cleanup was safely skipped because keys contained unrelated values or subkeys: " + ", ".join(cleanup_skipped))
            if cleanup_failed: details.append("key cleanup failed: " + "; ".join(cleanup_failed))
            if not keys_restored and not cleanup_skipped and not cleanup_failed: details.append("original key structure was not fully restored")
            return False, changed, "Rollback was partial: " + "; ".join(details or ["verification did not confirm the original state"])
        except (OSError, TypeError, ValueError) as exc:
            return False, changed, f"Rollback failed: {exc}"


def rollback_record_eligibility(record: dict[str, Any], history_records: list[dict[str, Any]] | None = None) -> tuple[bool, str]:
    """Validate audit metadata without reading or changing Windows state."""
    action_id = str(record.get("action_id", ""))
    if action_id not in REGISTRY_ACTIONS:
        return False, "This action does not support automatic registry rollback."
    if not bool(record.get("rollback_available")):
        return False, "This audit record is not marked as rollback-eligible."
    source_timestamp = str(record.get("timestamp_utc", ""))
    if history_records and source_timestamp and any(
        str(item.get("rollback_source_timestamp_utc", "")) == source_timestamp
        and str(item.get("rollback_status", "")).casefold() in ("completed", "partial")
        for item in history_records
    ):
        return False, "This action has already been rolled back and cannot be rolled back again."
    original = record.get("original_configuration"); owned = record.get("requested_configuration")
    if not isinstance(original, dict) or not isinstance(owned, dict) or not original or not owned:
        return False, "The audit record does not contain complete rollback state."
    try:
        original_values = WindowsHardeningBackend._registry_values(action_id, original)
        owned_values = WindowsHardeningBackend._registry_values(action_id, owned)
        schema = record.get("rollback_snapshot_schema", 1)
        if isinstance(schema, bool) or not isinstance(schema, int) or schema not in (1, REGISTRY_SNAPSHOT_SCHEMA_VERSION):
            raise ValueError("The rollback snapshot schema is unsupported.")
        if original.get("schema_version", 1) != schema or owned.get("schema_version", 1) != schema:
            raise ValueError("The rollback snapshot schema metadata is inconsistent.")
        if schema == REGISTRY_SNAPSHOT_SCHEMA_VERSION:
            WindowsHardeningBackend._registry_keys(action_id, original); WindowsHardeningBackend._registry_keys(action_id, owned)
        for item in (*original_values.values(), *owned_values.values()):
            if not item.get("exists"): continue
            value_type, value = item.get("type"), item.get("value")
            if value_type == 4 and isinstance(value, int) and not isinstance(value, bool): continue
            if value_type == 1 and isinstance(value, str): continue
            raise ValueError("Rollback state contains an invalid registry value or type.")
    except (TypeError, ValueError) as exc:
        return False, str(exc)
    return True, "Value-level legacy rollback is available; registry keys will not be deleted." if schema == 1 else "Version 2 value and key rollback state is valid."


class HardeningEngine:
    def __init__(self, backend: HardeningBackend) -> None: self.backend = backend

    @staticmethod
    def _rollback_metadata(action_id: str, original: dict[str, Any], final_state: dict[str, Any], changed: bool) -> tuple[bool, int]:
        schema = original.get("schema_version", 1)
        if isinstance(schema, bool) or not isinstance(schema, int): schema = 1
        candidate = {"action_id": action_id, "rollback_available": bool(changed and final_state), "rollback_snapshot_schema": schema, "original_configuration": original, "requested_configuration": final_state}
        eligible, _ = rollback_record_eligibility(candidate)
        return eligible, schema

    @staticmethod
    def _token(action_id: str, state: dict[str, Any], management: ManagementState) -> str:
        token_data = json.dumps({"action": action_id, "state": state, "management": management.value}, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(token_data.encode("utf-8")).hexdigest()

    def preview(self, action_id: str) -> ActionPreview:
        if action_id not in ACTIONS: raise ValueError("Unsupported action identifier.")
        definition = ACTIONS[action_id]
        try:
            current = self.backend.capture(action_id); verified, verification_evidence = self.backend.verify(action_id)
            if hasattr(self.backend, "describe"): current_text, technical = self.backend.describe(action_id, current)
            else: current_text, technical = verification_evidence, json.dumps(current, indent=2, sort_keys=True)
        except Exception as exc:
            detail = str(exc)
            access_denied = "access" in detail.lower() or "denied" in detail.lower() or "unauthorized" in detail.lower()
            availability = ActionAvailability.REQUIRES_ELEVATION if access_denied else ActionAvailability.UNSUPPORTED
            explanation = "Administrator access is required to read the current configuration." if access_denied else "This configuration could not be queried with the supported backend."
            return self._preview(definition, availability, explanation, f"Query failure: {detail}", detail)
        management, management_evidence = self.backend.management_state(action_id)
        if verified: availability = ActionAvailability.ALREADY_COMPLIANT
        elif management == ManagementState.UNMANAGED: availability = ActionAvailability.AVAILABLE
        elif management == ManagementState.MANAGED: availability = ActionAvailability.MANAGED
        elif management == ManagementState.REQUIRES_ELEVATION: availability = ActionAvailability.REQUIRES_ELEVATION
        else: availability = ActionAvailability.MANUAL
        token = self._token(action_id, current, management)
        return self._preview(definition, availability, current_text, management_evidence, technical, token, datetime.now(timezone.utc).isoformat())

    @staticmethod
    def _preview(definition: ActionDefinition, availability: ActionAvailability, current: str, management: str,
                 technical: str = "", token: str = "", created_utc: str = "") -> ActionPreview:
        return ActionPreview(definition.action_id, definition.title, definition.finding, definition.severity, availability,
            current, definition.recommended, definition.rationale, definition.compatibility, definition.permissions,
            definition.exact_change, definition.verification, definition.rollback, management, technical, token, created_utc)

    def execute(self, action_id: str, confirmed: bool, expected_preview_token: str | None = None,
                preview_created_utc: str | None = None) -> ActionRecord:
        if action_id not in ACTIONS: raise ValueError("Unsupported action identifier.")
        if not confirmed: return ActionRecord.create(action_id, {}, {}, ActionOutcome.CANCELLED, "Explicit confirmation was not provided.", "No change attempted.", False)
        preview = self.preview(action_id)
        if preview.availability == ActionAvailability.ALREADY_COMPLIANT:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.CANCELLED, "No change was made because the action is already compliant.", preview.current_configuration, False)
        if not is_administrator(): return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "Administrator privileges are required.", "No change attempted.", False)
        if not expected_preview_token or not preview_created_utc:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "A current validated preview is required before applying this action.", "No change attempted.", False)
        try:
            created = datetime.fromisoformat(preview_created_utc.replace("Z", "+00:00"))
            if created.tzinfo is None: created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            age = 999999
        if age < -5 or age > 300 or preview.preview_token != expected_preview_token:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "The preview is stale or the configuration changed. Preview the action again.", "No change attempted.", False)
        if preview.availability != ActionAvailability.AVAILABLE:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, f"Action state is {preview.availability.value}.", preview.management_evidence, False)
        original = self.backend.capture(action_id)
        management, _ = self.backend.management_state(action_id)
        if self._token(action_id, original, management) != expected_preview_token:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "The configuration changed after preview. No change was attempted.", "Preview the action again.", False)
        try:
            self.backend.apply(action_id, original); verified, evidence = self.backend.verify(action_id)
        except Exception as exc:
            try: verified, evidence = self.backend.verify(action_id)
            except Exception as verify_exc: verified, evidence = False, f"Apply error: {exc}; verification error: {verify_exc}"
            try: final_state = self.backend.capture(action_id); changed = final_state != original
            except Exception: final_state, changed = {}, False
            rollback_available, rollback_schema = self._rollback_metadata(action_id, original, final_state, changed)
            outcome = ActionOutcome.PARTIAL if changed else ActionOutcome.FAILURE
            return ActionRecord.create(action_id, original, final_state if changed else {}, outcome, f"The action raised an error: {exc}", evidence, rollback_available, rollback_snapshot_schema=rollback_schema)
        try: final_state = self.backend.capture(action_id); changed = final_state != original
        except Exception: final_state, changed = {}, False
        rollback_available, rollback_schema = self._rollback_metadata(action_id, original, final_state, changed)
        outcome = ActionOutcome.SUCCESS if verified else ActionOutcome.PARTIAL if changed else ActionOutcome.FAILURE
        message = "The requested configuration was applied and verified." if verified else "The change completed, but verification did not confirm the full requested configuration."
        return ActionRecord.create(action_id, original, final_state if changed else {}, outcome, message, evidence, rollback_available, rollback_snapshot_schema=rollback_schema)

    def rollback(self, record: dict[str, Any], confirmed: bool) -> ActionRecord:
        action_id = str(record.get("action_id", ""))
        source_timestamp = str(record.get("timestamp_utc", ""))
        if action_id not in ACTIONS: raise ValueError("Unsupported action identifier.")
        if not confirmed or not is_administrator():
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.CANCELLED, "Rollback was not confirmed or lacks administrator privileges.", "No rollback attempted.", False, rollback_source_timestamp_utc=source_timestamp)
        eligible, reason = rollback_record_eligibility(record)
        if not eligible:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "This record is not eligible for automatic rollback.", reason, False, rollback_source_timestamp_utc=source_timestamp)
        original = dict(record.get("original_configuration") or {})
        owned = dict(record.get("requested_configuration") or {})
        if not original or not owned:
            return ActionRecord.create(action_id, {}, {}, ActionOutcome.FAILURE, "The rollback record lacks an exact owned state.", "No rollback attempted.", False, rollback_source_timestamp_utc=source_timestamp)
        try:
            successful, changed, evidence = self.backend.rollback(action_id, original, owned)
        except Exception as exc:
            successful, changed, evidence = False, False, f"Rollback failed: {exc}"
        outcome = ActionOutcome.SUCCESS if successful else ActionOutcome.PARTIAL if changed else ActionOutcome.FAILURE
        return ActionRecord.create(action_id, owned, original, outcome, evidence, evidence, False, "Completed" if successful else "Partial" if changed else "Failed", int(record.get("rollback_snapshot_schema", 1)), source_timestamp)
