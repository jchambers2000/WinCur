"""Modular, read-only Windows security checks.

Every probe uses a supported PowerShell cmdlet, Windows COM API, or documented
policy/registry value. Probe failures are data: they become Unknown results and
never become successful findings.
"""

from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from .models import CheckResult, CheckStatus
from .remediation import remediation_for


UPDATE_CLASSIFICATIONS = {
    "critical": "e6cf1350-c01b-414d-a61f-263d14d133b4",
    "definition": "e0789628-ce08-4437-be74-2495b842f43b",
    "driver": "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0",
    "feature": "b54e7d24-7add-428f-8b75-90a396fa584f",
    "security": "0fa1201d-4330-4fa8-8ae9-b877473b6441",
    "service_pack": "68c5b0a3-d1a6-4553-ae49-01d3a7827828",
    "tools": "b4832bd8-e735-4761-8daf-37f882276dab",
    "rollup": "28bc880e-0592-4cbf-8f95-c79b17911d5f",
    "updates": "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83",
    "upgrade": "3689bdc8-b205-4af4-8d4a-a63924c5e9d5",
}


def _strict_bool(value: Any) -> bool | None:
    if isinstance(value, bool): return value
    if isinstance(value, int) and value in (0, 1): return bool(value)
    if isinstance(value, str) and value.casefold() in ("true", "false"): return value.casefold() == "true"
    return None


def classify_windows_update_payload(data: Any) -> dict[str, Any]:
    """Classify bounded WUA metadata without treating every software update as OS quality."""
    if not isinstance(data, dict): raise ValueError("Windows Update Agent returned no structured result.")
    raw_updates = data.get("Updates")
    if raw_updates is None: raise ValueError("Windows Update Agent did not return update metadata.")
    updates = raw_updates if isinstance(raw_updates, list) else [raw_updates]
    counts = {name: 0 for name in ("required_security", "required_quality", "definitions", "optional", "drivers", "other", "ambiguous")}
    samples: dict[str, list[str]] = {name: [] for name in counts}

    def identify(update: dict[str, Any]) -> str:
        kb_values = update.get("KBArticleIDs") or []
        if not isinstance(kb_values, list): kb_values = [kb_values]
        kb = next((str(value).strip() for value in kb_values if str(value).strip()), "")
        kb = "".join(character for character in kb if character.isalnum() or character in "-._")[:40]
        if kb: return kb if kb.upper().startswith("KB") else f"KB{kb}"
        update_id = "".join(character for character in str(update.get("UpdateID") or "").strip() if character.isalnum() or character == "-")
        return f"Update {update_id[:8]}" if update_id else "Unidentified update"

    update_reboot_required = False
    for raw_update in updates:
        if not isinstance(raw_update, dict):
            counts["ambiguous"] += 1; samples["ambiguous"].append("Unreadable update metadata"); continue
        categories = raw_update.get("Categories")
        categories = categories if isinstance(categories, list) else [categories] if isinstance(categories, dict) else []
        category_ids = {str(category.get("Id") or "").casefold() for category in categories if isinstance(category, dict) and category.get("Id")}
        classifications = {name for name, category_id in UPDATE_CLASSIFICATIONS.items() if category_id in category_ids}
        browse_only = _strict_bool(raw_update.get("BrowseOnly")); update_type = raw_update.get("UpdateType")
        msrc_severity = str(raw_update.get("MsrcSeverity") or "").casefold()
        has_msrc_severity = msrc_severity in ("critical", "important", "moderate", "low")
        try: driver_type = int(update_type) == 2
        except (TypeError, ValueError): driver_type = str(update_type).casefold() == "driver"
        identifier = identify(raw_update)
        if _strict_bool(raw_update.get("UpdateRebootRequired")) is True: update_reboot_required = True
        if driver_type or classifications == {"driver"}: bucket = "drivers"
        elif classifications == {"definition"}: bucket = "definitions"
        elif len(classifications) > 1: bucket = "ambiguous"
        elif browse_only is True: bucket = "optional"
        elif browse_only is None: bucket = "ambiguous"
        elif classifications == {"security"} or (not classifications and has_msrc_severity): bucket = "required_security"
        elif classifications in ({"critical"}, {"updates"}, {"rollup"}): bucket = "required_quality"
        elif classifications.intersection({"feature", "service_pack", "tools", "upgrade"}): bucket = "other"
        else: bucket = "ambiguous"
        counts[bucket] += 1
        if len(samples[bucket]) < 5: samples[bucket].append(identifier)

    try: reported_total = int(data.get("Total", len(updates)))
    except (TypeError, ValueError): reported_total = len(updates); counts["ambiguous"] += 1
    if reported_total < len(updates): reported_total = len(updates); counts["ambiguous"] += 1
    omitted = max(0, reported_total - len(updates))
    if omitted: counts["ambiguous"] += omitted
    if bool(data.get("Truncated")) and not omitted: counts["ambiguous"] += 1
    reboot = _strict_bool(data.get("RebootRequired"))
    if reboot is None: counts["ambiguous"] += 1
    elif update_reboot_required: reboot = True
    return {**counts, "total": reported_total, "reboot_required": reboot, "samples": samples}


class ProbeError(RuntimeError):
    pass


def _safe_diagnostic(value: object, limit: int = 700) -> str:
    text = "".join(
        "" if ord(character) < 32 and character not in "\t\r\n" else character
        for character in str(value)
    ).split()
    return " ".join(text)[-limit:] or "No additional diagnostic detail was returned."


class PowerShellRunner:
    def json(self, script: str, timeout: int = 30) -> Any:
        command = (
            "$ErrorActionPreference='Stop'; "
            f"$result = & {{ {script} }}; "
            "$result | ConvertTo-Json -Compress -Depth 5"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise ProbeError(f"The Windows query timed out after {timeout} seconds.") from exc
        except OSError as exc:
            raise ProbeError(f"PowerShell could not be started: {_safe_diagnostic(exc)}") from exc
        except subprocess.SubprocessError as exc:
            raise ProbeError(f"The Windows query failed: {_safe_diagnostic(exc)}") from exc
        if completed.returncode != 0:
            detail = completed.stderr or completed.stdout or "PowerShell returned no details."
            raise ProbeError(_safe_diagnostic(detail))
        output = completed.stdout.strip()
        if not output:
            raise ProbeError("The Windows query returned no data.")
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise ProbeError(f"The Windows query returned unreadable data: {_safe_diagnostic(output, 300)}") from exc


def _definition(config: dict[str, Any], check_id: str) -> dict[str, Any]:
    return config["checks"][check_id]


def result(
    config: dict[str, Any],
    check_id: str,
    title: str,
    status: CheckStatus,
    evidence: str,
    explanation: str,
) -> CheckResult:
    definition = _definition(config, check_id)
    return CheckResult(
        check_id=check_id,
        title=title,
        category=definition["category"],
        status=status,
        evidence=evidence,
        explanation=explanation,
        weight=float(definition["weight"]),
        severity=str(definition["severity"]),
        remediation=remediation_for(check_id),
    )


def unknown(config: dict[str, Any], check_id: str, title: str, exc: Exception) -> CheckResult:
    return result(
        config,
        check_id,
        title,
        CheckStatus.UNKNOWN,
        "Status could not be read.",
        "The setting may be unavailable on this Windows edition, restricted by permissions, "
        f"or managed by another product. Details: {_safe_diagnostic(exc)}",
    )


def diagnostic_unknown(
    config: dict[str, Any], check_id: str, title: str, reason: str, detail: str, explanation: str
) -> CheckResult:
    """Return an Unknown result with a stable troubleshooting classification."""
    safe_detail = " ".join(str(detail).split())[:700] or "No additional detail was returned."
    return result(
        config, check_id, title, CheckStatus.UNKNOWN,
        f"Diagnostic reason: {reason}. {safe_detail}", explanation,
    )


def _collection_reason(exc: Exception) -> tuple[str, str]:
    detail = str(exc)
    folded = detail.casefold()
    if any(term in folded for term in ("access denied", "unauthorized", "permission")):
        return "Insufficient permissions", "The current assessment context could not read the required Windows information."
    if any(term in folded for term in ("not recognized", "not supported", "not available", "cannot find the command")):
        return "Unsupported detection", "This Windows environment did not expose the supported collection mechanism."
    return "Collection failure", "The Windows provider failed before WinCur could collect complete evidence."


def check_defender(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    ids = {
        "defender_realtime": "Defender real-time protection",
        "defender_cloud": "Defender cloud-delivered protection",
        "defender_tamper": "Defender Tamper Protection",
        "defender_signatures": "Defender signature freshness",
    }
    try:
        data = runner.json(
            "$s=Get-MpComputerStatus; $p=Get-MpPreference; "
            "[pscustomobject]@{AMServiceEnabled=$s.AMServiceEnabled;AntivirusEnabled=$s.AntivirusEnabled;"
            "RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;IsTamperProtected=$s.IsTamperProtected;"
            "AntivirusSignatureLastUpdated=$(if($s.AntivirusSignatureLastUpdated){$s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}else{$null});"
            "MAPSReporting=$p.MAPSReporting}"
        )
    except ProbeError as exc:
        # SecurityCenter2 is used only to distinguish replacement antivirus from an unreadable setting.
        try:
            products = runner.json(
                "@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
                "Select-Object displayName)"
            )
            products = products if isinstance(products, list) else [products]
            names = [str(item.get("displayName", "")) for item in products if item]
            non_microsoft = [name for name in names if name and "defender" not in name.lower()]
            if non_microsoft:
                evidence = "Registered antivirus product(s): " + ", ".join(non_microsoft)
                return [
                    result(config, check_id, title, CheckStatus.NOT_APPLICABLE, evidence,
                           "Microsoft Defender is not the active antivirus; evaluate the registered replacement product separately.")
                    for check_id, title in ids.items()
                ]
        except ProbeError:
            pass
        return [unknown(config, check_id, title, exc) for check_id, title in ids.items()]

    if not isinstance(data, dict):
        return [unknown(config, check_id, title, ValueError("Defender returned no structured status.")) for check_id, title in ids.items()]
    am_service = _strict_bool(data.get("AMServiceEnabled")); antivirus = _strict_bool(data.get("AntivirusEnabled"))
    if am_service is None or antivirus is None:
        return [unknown(config, check_id, title, ValueError("Defender did not report AMServiceEnabled and AntivirusEnabled.")) for check_id, title in ids.items()]
    active = am_service and antivirus
    if not active:
        try:
            products = runner.json("@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName)")
            products = products if isinstance(products, list) else [products]
            replacements = [str(item.get("displayName", "")) for item in products if item and "defender" not in str(item.get("displayName", "")).lower()]
        except ProbeError:
            replacements = []
        if replacements:
            explanation = "Microsoft Defender is inactive because another registered antivirus product may be responsible; assess that product separately."
            evidence = "Registered replacement antivirus product(s): " + ", ".join(replacements)
            return [result(config, check_id, title, CheckStatus.NOT_APPLICABLE, evidence, explanation) for check_id, title in ids.items()]
        evidence = "AMServiceEnabled or AntivirusEnabled is false; no replacement antivirus was confirmed."
        explanation = "Microsoft Defender is inactive and WinCur could not confirm a registered replacement antivirus product."
        return [result(config, check_id, title, CheckStatus.FAIL, evidence, explanation) for check_id, title in ids.items()]

    realtime = _strict_bool(data.get("RealTimeProtectionEnabled"))
    cloud_value = data.get("MAPSReporting")
    cloud = cloud_value in (1, 2, "1", "2") if cloud_value is not None else None
    tamper = _strict_bool(data.get("IsTamperProtected"))
    raw_date = data.get("AntivirusSignatureLastUpdated")
    signature_status = CheckStatus.UNKNOWN
    signature_evidence = f"Last updated: {raw_date or 'not reported'}"
    signature_explanation = "Defender did not report a usable signature timestamp."
    if raw_date:
        try:
            parsed = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            age_days = max(0.0, (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() / 86400)
            max_age = float(config.get("assessment_policy", {}).get("defender_signature_max_age_days", 7))
            signature_status = CheckStatus.PASS if age_days <= max_age else CheckStatus.FAIL
            signature_evidence = f"Security intelligence age: {age_days:.1f} days; last updated {raw_date}."
            signature_explanation = f"Signatures are within the {max_age:g}-day freshness threshold." if age_days <= max_age else f"Signatures are older than the {max_age:g}-day freshness threshold."
        except (TypeError, ValueError, OverflowError):
            pass
    return [
        result(config, "defender_realtime", ids["defender_realtime"], CheckStatus.UNKNOWN if realtime is None else CheckStatus.PASS if realtime else CheckStatus.FAIL,
               f"RealTimeProtectionEnabled={realtime if realtime is not None else 'not reported'}", "Defender did not report real-time protection state." if realtime is None else "Real-time monitoring is enabled." if realtime else "Real-time monitoring is disabled."),
        result(config, "defender_cloud", ids["defender_cloud"], CheckStatus.UNKNOWN if cloud is None else CheckStatus.PASS if cloud else CheckStatus.FAIL,
               f"MAPSReporting={cloud_value if cloud_value is not None else 'not reported'}", "Defender did not report cloud-protection policy." if cloud is None else "Cloud-delivered protection is enabled." if cloud else "Cloud-delivered protection is disabled."),
        result(config, "defender_tamper", ids["defender_tamper"], CheckStatus.UNKNOWN if tamper is None else CheckStatus.PASS if tamper else CheckStatus.FAIL,
               f"IsTamperProtected={tamper if tamper is not None else 'not reported'}", "Defender did not report Tamper Protection state." if tamper is None else "Tamper Protection is enabled." if tamper else "Tamper Protection is disabled or not active."),
        result(config, "defender_signatures", ids["defender_signatures"], signature_status, signature_evidence, signature_explanation),
    ]


def check_firewall(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    profile_ids = {"Domain": "firewall_domain", "Private": "firewall_private", "Public": "firewall_public"}
    try:
        data = runner.json("@(Get-NetFirewallProfile | Select-Object Name,Enabled)")
        profiles = data if isinstance(data, list) else [data]
        by_name = {str(item.get("Name")): item for item in profiles if isinstance(item, dict)}
        findings = []
        for name, check_id in profile_ids.items():
            if name not in by_name:
                findings.append(result(config, check_id, f"Windows Firewall - {name}", CheckStatus.UNKNOWN,
                                       "Profile was not reported.", "Windows did not return this firewall profile."))
                continue
            enabled = _strict_bool(by_name[name].get("Enabled"))
            if enabled is None:
                findings.append(result(config, check_id, f"Windows Firewall - {name}", CheckStatus.UNKNOWN,
                                       f"{name} profile Enabled was not reported.", "Windows returned the profile but not a usable enabled state.")); continue
            findings.append(result(config, check_id, f"Windows Firewall - {name}", CheckStatus.PASS if enabled else CheckStatus.FAIL,
                                   f"{name} profile Enabled={enabled}", "The firewall profile is enabled." if enabled else "The firewall profile is disabled."))
        return findings
    except ProbeError as exc:
        return [unknown(config, check_id, f"Windows Firewall - {name}", exc) for name, check_id in profile_ids.items()]


def check_bitlocker(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json("$v=Get-BitLockerVolume -MountPoint $env:SystemDrive; if($null -eq $v){$null}else{[pscustomobject]@{MountPoint=$v.MountPoint;VolumeStatus=$v.VolumeStatus.ToString();ProtectionStatus=$v.ProtectionStatus.ToString();EncryptionPercentage=$v.EncryptionPercentage;EncryptionMethod=$v.EncryptionMethod.ToString()}}")
        if not data:
            return [result(config, "bitlocker_system", "BitLocker system-drive protection", CheckStatus.NOT_APPLICABLE,
                           "No BitLocker volume object was returned for the operating-system drive.", "BitLocker or device encryption is not available for this configuration.")]
        if not isinstance(data, dict) or any(key not in data for key in ("ProtectionStatus", "VolumeStatus", "EncryptionPercentage")):
            return [unknown(config, "bitlocker_system", "BitLocker system-drive protection", ValueError("BitLocker returned incomplete volume metadata."))]
        protection = str(data.get("ProtectionStatus", "")); volume = str(data.get("VolumeStatus", "")); percentage = data.get("EncryptionPercentage")
        protected = protection.lower() == "on" or protection == "1"
        encrypted = volume.lower() in ("fullyencrypted", "encryptioninprogress") or (isinstance(percentage, (int, float)) and percentage > 0)
        passed = protected and volume.lower() == "fullyencrypted"
        evidence = f"Drive {data.get('MountPoint', os.environ.get('SystemDrive', 'system'))}: encryption={volume} ({percentage}%); protection={protection}; method={data.get('EncryptionMethod')}"
        if passed: explanation = "The operating-system drive is fully encrypted and BitLocker protection is on."
        elif encrypted and not protected: explanation = "The drive is encrypted, but protection is suspended or off."
        elif encrypted: explanation = "Drive encryption is present but not yet fully complete and protected."
        else: explanation = "No active operating-system drive encryption was reported."
        return [result(config, "bitlocker_system", "BitLocker system-drive protection", CheckStatus.PASS if passed else CheckStatus.FAIL, evidence, explanation)]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "bitlocker_system", "BitLocker system-drive protection", exc)]


def check_secure_boot_and_tpm(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    findings: list[CheckResult] = []
    try:
        data = runner.json("try {[pscustomobject]@{Value=(Confirm-SecureBootUEFI);Error=$null;ErrorId=$null}} catch {[pscustomobject]@{Value=$null;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId}}")
        if not isinstance(data, dict): raise ValueError("Secure Boot provider returned no structured state.")
        error = str(data.get("Error") or "")
        error_id = str(data.get("ErrorId") or "")
        if error and ("not supported" in error.lower() or "not supported" in error_id.lower()):
            findings.append(result(config, "secure_boot", "Secure Boot", CheckStatus.NOT_APPLICABLE, error, "Secure Boot is not supported by the current firmware mode."))
        elif error:
            permission = "access" in error.lower() or "unauthorized" in error_id.lower() or "privilege" in error.lower()
            findings.append(result(config, "secure_boot", "Secure Boot", CheckStatus.UNKNOWN, f"ErrorId={error_id}; {error}", "Access was denied while reading Secure Boot state." if permission else "Secure Boot state could not be read because the query failed."))
        else:
            enabled = _strict_bool(data.get("Value"))
            if enabled is None:
                findings.append(result(config, "secure_boot", "Secure Boot", CheckStatus.UNKNOWN, "Confirm-SecureBootUEFI returned no Boolean state.", "Secure Boot support or state could not be confirmed."))
            else:
                findings.append(result(config, "secure_boot", "Secure Boot", CheckStatus.PASS if enabled else CheckStatus.FAIL,
                                       f"Confirm-SecureBootUEFI={enabled}", "Secure Boot is enabled." if enabled else "Secure Boot is supported but disabled."))
    except (ProbeError, TypeError, ValueError) as exc:
        findings.append(unknown(config, "secure_boot", "Secure Boot", exc))
    try:
        data = runner.json("Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,ManufacturerVersion")
        if not isinstance(data, dict) or any(key not in data for key in ("TpmPresent", "TpmReady", "TpmEnabled")): raise ValueError("TPM provider returned incomplete state.")
        present, ready, enabled = _strict_bool(data.get("TpmPresent")), _strict_bool(data.get("TpmReady")), _strict_bool(data.get("TpmEnabled"))
        if present is None or ready is None or enabled is None: raise ValueError("TPM provider returned non-Boolean state.")
        evidence = f"Present={present}; Ready={ready}; Enabled={enabled}; ManufacturerVersion={data.get('ManufacturerVersion')}"
        if not present: explanation = "No TPM was detected by the supported Windows TPM provider."
        elif not enabled: explanation = "A TPM is present but disabled. WinCur will not change firmware or provision it."
        elif not ready: explanation = "A TPM is present and enabled but is not ready. WinCur will not clear, reset, or provision it."
        else: explanation = "The TPM is present, enabled, and ready."
        findings.append(result(config, "tpm", "Trusted Platform Module", CheckStatus.PASS if present and ready and enabled else CheckStatus.FAIL, evidence, explanation))
    except (ProbeError, TypeError, ValueError) as exc:
        detail = str(exc); explanation = "Access was denied while querying the TPM." if "access" in detail.lower() or "denied" in detail.lower() else "The TPM query failed, so WinCur cannot determine TPM state."
        findings.append(result(config, "tpm", "Trusted Platform Module", CheckStatus.UNKNOWN, detail, explanation))
    return findings


def check_windows_update(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "$session=New-Object -ComObject Microsoft.Update.Session; $searcher=$session.CreateUpdateSearcher(); "
            "$updates=$searcher.Search(\"IsInstalled=0 and IsHidden=0\").Updates; $items=@(); $limit=200; $selected=@($updates) | Select-Object -First $limit; "
            "foreach($u in $selected){$cats=@(); foreach($c in @($u.Categories)){$cats += [pscustomobject]@{Id=[string]$c.CategoryID;Name=[string]$c.Name;Type=[string]$c.Type}}; "
            "$items += [pscustomobject]@{UpdateID=[string]$u.Identity.UpdateID;RevisionNumber=$u.Identity.RevisionNumber;UpdateType=$(try{[int]$u.Type}catch{$null});BrowseOnly=$(try{[bool]$u.BrowseOnly}catch{$null});AutoSelectOnWebSites=$(try{[bool]$u.AutoSelectOnWebSites}catch{$null});IsDownloaded=$(try{[bool]$u.IsDownloaded}catch{$null});UpdateRebootRequired=$(try{[bool]$u.RebootRequired}catch{$null});MsrcSeverity=$(try{[string]$u.MsrcSeverity}catch{$null});KBArticleIDs=@($u.KBArticleIDs);Categories=@($cats)}}; "
            "$systemInfo=New-Object -ComObject Microsoft.Update.SystemInfo; $reboot=[bool]$systemInfo.RebootRequired; "
            "[pscustomobject]@{Updates=@($items);Total=$updates.Count;Truncated=($updates.Count -gt $limit);RebootRequired=$reboot}"
        , timeout=60)
        summary = classify_windows_update_payload(data); security = summary["required_security"]; quality = summary["required_quality"]; ambiguous = summary["ambiguous"]; reboot = summary["reboot_required"]
        failed = security > 0 or quality > 0 or reboot is True; status = CheckStatus.FAIL if failed else CheckStatus.UNKNOWN if ambiguous else CheckStatus.PASS
        evidence = (f"Pending: required security={security}; required quality={quality}; Defender definitions={summary['definitions']}; "
                    f"optional/preview={summary['optional']}; drivers={summary['drivers']}; feature/other={summary['other']}; "
                    f"unclassified={ambiguous}; total={summary['total']}; restart required={reboot}")
        sample_groups = []
        for key, label in (("required_security", "security"), ("required_quality", "quality"), ("definitions", "definitions"), ("optional", "optional"), ("ambiguous", "unclassified")):
            if summary["samples"][key]: sample_groups.append(f"{label}: {', '.join(summary['samples'][key])}")
        if sample_groups: evidence += "; identifiers: " + " | ".join(sample_groups)
        if status == CheckStatus.PASS: explanation = "No required Windows security/quality update or pending restart was detected. Defender definitions are assessed separately through signature freshness; optional updates, drivers, and feature/other offers do not fail this OS update check."
        elif status == CheckStatus.FAIL: explanation = "A required Windows security/quality update or pending restart was confirmed. Defender definition updates are assessed separately through signature freshness."
        else: explanation = "Windows Update returned incomplete, contradictory, or unclassified metadata, so WinCur cannot confirm that required OS updates are absent."
        return [result(config, "windows_update", "Windows Update status", status, evidence, explanation)]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "windows_update", "Windows Update status", exc)]


def check_uac(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop")
        if not isinstance(data, dict) or any(key not in data for key in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop")): raise ValueError("UAC policy metadata was incomplete.")
        enabled = int(data["EnableLUA"]) == 1
        prompt = int(data["ConsentPromptBehaviorAdmin"])
        secure = int(data["PromptOnSecureDesktop"]) == 1
        passed = enabled and prompt != 0 and secure
        return [result(config, "uac", "User Account Control", CheckStatus.PASS if passed else CheckStatus.FAIL,
                       f"EnableLUA={int(enabled)}; ConsentPromptBehaviorAdmin={prompt}; PromptOnSecureDesktop={int(secure)}",
                       "UAC elevation prompts use the secure desktop." if passed else "UAC is disabled, silently elevates administrators, or does not use the secure desktop.")]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "uac", "User Account Control", exc)]


def check_accounts(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "$guest=$null;$guestStatus='Success';$guestError=$null; "
            "try{$guest=Get-LocalUser -ErrorAction Stop|Where-Object{$_.SID.Value -match '-501$'}|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;Enabled=$_.Enabled;SID=[string]$_.SID.Value}}}catch{$guestStatus='CollectionFailure';$guestError=$_.Exception.Message}; "
            "$members=@();$adminStatus='Success';$adminError=$null;$provider='LocalAccounts';$groupName=$null; "
            "try{$group=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop;$groupName=[string]$group.Name;"
            "$members=@(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=[string]$_.Name;ObjectClass=[string]$_.ObjectClass;PrincipalSource=[string]$_.PrincipalSource;SID=$(if($_.SID){[string]$_.SID.Value}else{$null});Direct=$true}})}"
            "catch{$primaryError=$_.Exception.Message;try{$provider='CIM fallback';$group=Get-CimInstance Win32_Group -Filter \"SID='S-1-5-32-544' AND LocalAccount=True\" -ErrorAction Stop;if(-not $group){throw 'The built-in Administrators group was not returned.'};$groupName=[string]$group.Name;"
            "$members=@(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser -ResultClassName Win32_Account -ErrorAction Stop|ForEach-Object{[pscustomobject]@{Name=$(if($_.Caption){[string]$_.Caption}elseif($_.Name){[string]$_.Name}else{$null});ObjectClass=[string]$_.CimClass.CimClassName;PrincipalSource=$(if($_.LocalAccount){'Local'}else{'Domain or Microsoft account'});SID=[string]$_.SID;Direct=$true}})}"
            "catch{$adminStatus='CollectionFailure';$adminError=\"LocalAccounts: $primaryError; CIM fallback: $($_.Exception.Message)\"}}; "
            "[pscustomobject]@{Guest=$guest;GuestStatus=$guestStatus;GuestError=$guestError;Administrators=$members;AdministratorStatus=$adminStatus;AdministratorError=$adminError;AdministratorProvider=$provider;AdministratorGroup=$groupName;AdministratorGroupSID='S-1-5-32-544'}"
        )
        if not isinstance(data, dict): raise ValueError("Local account providers returned no structured data.")
        findings = []
        guest_status = str(data.get("GuestStatus", "Success"))
        guest = data.get("Guest")
        if guest_status != "Success":
            detail = str(data.get("GuestError") or "The local-user provider did not complete.")
            reason, explanation = _collection_reason(ProbeError(detail))
            findings.append(diagnostic_unknown(config, "guest_account", "Built-in Guest account", reason, detail, explanation))
        elif not guest:
            findings.append(result(config, "guest_account", "Built-in Guest account", CheckStatus.NOT_APPLICABLE,
                                   "No local account with RID 501 was returned.", "The built-in Guest account was not present."))
        else:
            enabled = _strict_bool(guest.get("Enabled")) if isinstance(guest, dict) else None
            if enabled is None: findings.append(result(config, "guest_account", "Built-in Guest account", CheckStatus.UNKNOWN, "The RID-501 account was returned without a usable Enabled state.", "The built-in Guest account state could not be confirmed."))
            else: findings.append(result(config, "guest_account", "Built-in Guest account", CheckStatus.FAIL if enabled else CheckStatus.PASS,
                                        f"Account={guest.get('Name')}; Enabled={enabled}; SID ends in -501", "The built-in Guest account is disabled." if not enabled else "The built-in Guest account is enabled."))
        admin_status = str(data.get("AdministratorStatus", "Success" if "Administrators" in data else "CollectionFailure"))
        if admin_status != "Success" or "Administrators" not in data:
            detail = str(data.get("AdministratorError") or "Administrator membership was not returned.")
            reason, explanation = _collection_reason(ProbeError(detail))
            findings.append(diagnostic_unknown(config, "local_admins", "Local Administrators membership", reason, detail, explanation)); return findings
        members = data.get("Administrators") or []
        members = members if isinstance(members, list) else [members]
        parsed: list[dict[str, str]] = []; incomplete = False
        for member in members:
            if not isinstance(member, dict): incomplete = True; continue
            name = str(member.get("Name") or "").strip(); sid = str(member.get("SID") or "").strip()
            if not name and not sid: incomplete = True; continue
            if member.get("Direct", True) is not True: incomplete = True
            parsed.append({"name": name, "sid": sid, "type": str(member.get("ObjectClass") or "Unknown"), "source": str(member.get("PrincipalSource") or "Unknown")})
        provider = str(data.get("AdministratorProvider") or "Windows local-account provider")
        group_name = str(data.get("AdministratorGroup") or "localized name not reported")
        group_sid = str(data.get("AdministratorGroupSID") or "S-1-5-32-544")
        rendered = []
        for member in parsed:
            identity = member["name"] or f"Unresolved SID {member['sid']}"
            builtin = "; built-in Administrator" if member["sid"].endswith("-500") else ""
            rendered.append(f"{identity} [SID={member['sid'] or 'not reported'}; type={member['type']}; source={member['source']}; direct=yes{builtin}]")
        evidence = f"Enumeration succeeded via {provider}; group={group_name} ({group_sid}); direct members={len(parsed)}: " + ("; ".join(rendered) if rendered else "none")
        unresolved = [member for member in parsed if not member["name"]]
        if incomplete:
            findings.append(diagnostic_unknown(config, "local_admins", "Local Administrators membership", "Ambiguous configuration", evidence + "; one or more member records were incomplete.", "Administrator membership was only partially enumerated, so WinCur cannot determine whether it satisfies the configured authorization policy.")); return findings
        names = [member["name"] for member in parsed if member["name"]]
        approved = [str(name).casefold() for name in config.get("assessment_policy", {}).get("approved_local_administrators", [])]
        if unresolved:
            findings.append(diagnostic_unknown(config, "local_admins", "Local Administrators membership", "Ambiguous configuration", evidence, "Membership was enumerated, but one or more account names could not be resolved. An unresolved identity is not treated as confirmed unauthorized access."))
        elif approved:
            unexpected = [member["name"] for member in parsed if member["name"].casefold() not in approved and member["sid"].casefold() not in approved]
            findings.append(result(config, "local_admins", "Local Administrators membership", CheckStatus.FAIL if unexpected else CheckStatus.PASS,
                                   evidence + (f"; unexpected: {', '.join(unexpected)}" if unexpected else "; all members are approved"),
                                   "Membership was compared with the approved_local_administrators policy in scoring_config.json."))
        else:
            findings.append(result(config, "local_admins", "Local Administrators membership", CheckStatus.UNKNOWN,
                                   evidence, "Membership was enumerated, but the approved_local_administrators policy is empty, so WinCur will not guess whether these administrators are authorized."))
        return findings
    except (ProbeError, TypeError, ValueError) as exc:
        reason, explanation = _collection_reason(exc)
        return [diagnostic_unknown(config, "guest_account", "Built-in Guest account", reason, str(exc), explanation), diagnostic_unknown(config, "local_admins", "Local Administrators membership", reason, str(exc), explanation)]


def check_smb1(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName,State")
        if not isinstance(data, dict): raise ValueError("The optional-feature provider returned no structured state.")
        state = str(data.get("State", ""))
        enabled = state.lower().startswith("enabled") or state == "2"
        disabled = state.lower().startswith("disabled") or state in ("0", "4")
        status = CheckStatus.FAIL if enabled else CheckStatus.PASS if disabled else CheckStatus.UNKNOWN
        return [result(config, "smb1", "SMBv1 optional feature", status, f"Feature state={state}",
                       "SMBv1 is disabled." if status == CheckStatus.PASS else "SMBv1 is enabled or its state could not be interpreted.")]
    except (ProbeError, TypeError, ValueError) as exc:
        text = str(exc).lower()
        status = CheckStatus.NOT_APPLICABLE if "feature name" in text and "unknown" in text else CheckStatus.UNKNOWN
        return [result(config, "smb1", "SMBv1 optional feature", status, "Feature state was not returned.", str(exc))]


def check_remote_desktop(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "$ts=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'; "
            "$rdp=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'; "
            "[pscustomobject]@{Deny=$ts.fDenyTSConnections;NLA=$rdp.UserAuthentication}"
        )
        if not isinstance(data, dict) or any(key not in data for key in ("Deny", "NLA")): raise ValueError("Remote Desktop policy metadata was incomplete.")
        disabled = int(data["Deny"]) == 1
        nla = int(data["NLA"]) == 1
        passed = disabled or nla
        evidence = f"Remote Desktop enabled={not disabled}; Network Level Authentication={nla}"
        explanation = "Remote Desktop is disabled." if disabled else ("Remote Desktop is enabled with Network Level Authentication." if nla else "Remote Desktop is enabled without Network Level Authentication.")
        return [result(config, "remote_desktop", "Remote Desktop configuration", CheckStatus.PASS if passed else CheckStatus.FAIL, evidence, explanation)]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "remote_desktop", "Remote Desktop configuration", exc)]


def check_smartscreen(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "function Read-WinCurValue([string]$Path,[string]$Name){try{if(-not(Test-Path -LiteralPath $Path -ErrorAction Stop)){return [pscustomobject]@{KeyExists=$false;ValueExists=$false;Value=$null;Error=$null}};$item=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop;$property=$item.PSObject.Properties[$Name];if($null -eq $property){return [pscustomobject]@{KeyExists=$true;ValueExists=$false;Value=$null;Error=$null}};return [pscustomobject]@{KeyExists=$true;ValueExists=$true;Value=$property.Value;Error=$null}}catch{return [pscustomobject]@{KeyExists=$null;ValueExists=$null;Value=$null;Error=$_.Exception.Message}}}; "
            "$pe=Read-WinCurValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' 'EnableSmartScreen';$pl=Read-WinCurValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' 'ShellSmartScreenLevel';$machine=Read-WinCurValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' 'SmartScreenEnabled'; "
            "[pscustomobject]@{PolicyKeyExists=$pe.KeyExists;PolicyValueExists=$pe.ValueExists;PolicyEnabled=$pe.Value;PolicyError=$pe.Error;PolicyLevelValueExists=$pl.ValueExists;PolicyLevel=$pl.Value;PolicyLevelError=$pl.Error;MachineKeyExists=$machine.KeyExists;MachineValueExists=$machine.ValueExists;MachineSetting=$machine.Value;MachineError=$machine.Error;Scope='Windows Explorer reputation-based SmartScreen'}"
        )
        if not isinstance(data, dict): raise ValueError("SmartScreen policy providers returned no structured state.")
        policy_enabled = data.get("PolicyEnabled"); level = str(data.get("PolicyLevel") or "")
        machine = data.get("MachineSetting", data.get("UserSetting")); machine_text = str(machine or "")
        policy_exists = data.get("PolicyValueExists", policy_enabled is not None)
        machine_exists = data.get("MachineValueExists", machine is not None and machine_text != "")
        policy_key = data.get("PolicyKeyExists", "not reported"); machine_key = data.get("MachineKeyExists", "not reported")
        errors = [str(value) for value in (data.get("PolicyError"), data.get("PolicyLevelError"), data.get("MachineError")) if value]
        evidence = f"Scope=Windows Explorer SmartScreen; policy key exists={policy_key}; EnableSmartScreen exists={policy_exists}, value={policy_enabled if policy_exists else 'not present'}; ShellSmartScreenLevel={level or 'not present'}; machine Explorer key exists={machine_key}; SmartScreenEnabled exists={machine_exists}, value={machine_text or 'not present'}"
        if errors:
            detail = "; ".join(errors); reason, explanation = _collection_reason(ProbeError(detail))
            return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", reason, evidence + "; provider error: " + detail, explanation)]
        if not policy_exists and not machine_exists:
            return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", "Not configured / insufficient evidence", evidence, "SmartScreen could not be conclusively assessed. The inspected configuration values are not present, so WinCur cannot determine the effective protection state from this evidence.")]
        if policy_enabled in (0, "0"):
            enabled = False; explanation = "Machine policy explicitly disables SmartScreen; the machine Explorer value cannot override that managed policy."
        elif policy_enabled in (1, "1"):
            if level.casefold() not in ("warn", "block"):
                return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", "Ambiguous configuration", evidence, "Machine policy enables SmartScreen, but its enforcement level is missing or unsupported, so the configured protection requirement cannot be confirmed.")]
            enabled = True; explanation = "Windows Explorer SmartScreen is explicitly enabled by machine policy with a recognized enforcement level."
        elif policy_exists:
            return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", "Ambiguous configuration", evidence, "EnableSmartScreen contains an unsupported value, so WinCur cannot determine the effective protection state.")]
        else:
            normalized = machine_text.casefold()
            if normalized in ("warn", "requireadmin", "block"):
                enabled = True; explanation = "Windows Explorer SmartScreen is explicitly enabled by the machine Explorer configuration."
            elif normalized in ("off", "disabled"):
                enabled = False; explanation = "The machine Explorer configuration explicitly disables Windows Explorer SmartScreen."
            else:
                return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", "Ambiguous configuration", evidence, "SmartScreenEnabled contains an unsupported value, so WinCur cannot determine the effective protection state.")]
        return [result(config, "smartscreen", "Microsoft Defender SmartScreen", CheckStatus.PASS if enabled else CheckStatus.FAIL,
                       evidence, explanation)]
    except (ProbeError, TypeError, ValueError) as exc:
        reason, explanation = _collection_reason(exc)
        return [diagnostic_unknown(config, "smartscreen", "Microsoft Defender SmartScreen", reason, str(exc), explanation)]


def check_powershell_logging(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "function Read-WinCurValue([string]$Path,[string]$Name){try{if(-not(Test-Path -LiteralPath $Path -ErrorAction Stop)){return [pscustomobject]@{Value=$null;Error=$null}};$item=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop;$property=$item.PSObject.Properties[$Name];return [pscustomobject]@{Value=$(if($null -eq $property){$null}else{$property.Value});Error=$null}}catch{return [pscustomobject]@{Value=$null;Error=$_.Exception.Message}}}; "
            "$sb=Read-WinCurValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' 'EnableScriptBlockLogging'; "
            "$ml=Read-WinCurValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' 'EnableModuleLogging'; "
            "$mn=Read-WinCurValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames' '*'; "
            "[pscustomobject]@{ScriptBlock=$sb.Value;Module=$ml.Value;ModuleWildcard=$mn.Value;Errors=@(@($sb.Error;$ml.Error;$mn.Error)|Where-Object{$_})}"
        )
        if not isinstance(data, dict): raise ValueError("PowerShell policy providers returned no structured state.")
        errors = data.get("Errors") or []
        errors = errors if isinstance(errors, list) else [errors]
        if errors: raise ProbeError("; ".join(_safe_diagnostic(item, 250) for item in errors))
        script_block = data.get("ScriptBlock") in (1, "1")
        module = data.get("Module") in (1, "1")
        wildcard = bool(data.get("ModuleWildcard"))
        passed = script_block and module and wildcard
        return [result(config, "powershell_logging", "PowerShell audit logging", CheckStatus.PASS if passed else CheckStatus.FAIL,
                       f"Script Block Logging={script_block}; Module Logging={module}; Module wildcard configured={wildcard}", "Script Block Logging and Module Logging for all modules are enabled." if passed else "Script Block Logging, Module Logging, and the all-modules policy are not all enabled.")]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "powershell_logging", "PowerShell audit logging", exc)]


def check_autorun(runner: PowerShellRunner, config: dict[str, Any]) -> list[CheckResult]:
    try:
        data = runner.json(
            "function Read-WinCurValue([string]$Path,[string]$Name){try{if(-not(Test-Path -LiteralPath $Path -ErrorAction Stop)){return [pscustomobject]@{Value=$null;Error=$null}};$item=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop;$property=$item.PSObject.Properties[$Name];return [pscustomobject]@{Value=$(if($null -eq $property){$null}else{$property.Value});Error=$null}}catch{return [pscustomobject]@{Value=$null;Error=$_.Exception.Message}}}; "
            "$md=Read-WinCurValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoDriveTypeAutoRun'; $ma=Read-WinCurValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoAutorun'; "
            "$ud=Read-WinCurValue 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoDriveTypeAutoRun'; $ua=Read-WinCurValue 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoAutorun'; "
            "[pscustomobject]@{MachineDrive=$md.Value;MachineNoAutorun=$ma.Value;UserDrive=$ud.Value;UserNoAutorun=$ua.Value;Errors=@(@($md.Error;$ma.Error;$ud.Error;$ua.Error)|Where-Object{$_})}"
        )
        if not isinstance(data, dict): raise ValueError("AutoRun policy providers returned no structured state.")
        errors = data.get("Errors") or []
        errors = errors if isinstance(errors, list) else [errors]
        if errors: raise ProbeError("; ".join(_safe_diagnostic(item, 250) for item in errors))
        machine_drive, machine_command = data.get("MachineDrive"), data.get("MachineNoAutorun"); user_drive, user_command = data.get("UserDrive"), data.get("UserNoAutorun")
        machine_disabled = machine_drive in (255, "255") and machine_command in (1, "1"); user_disabled = user_drive in (255, "255") and user_command in (1, "1"); disabled = machine_disabled or user_disabled
        return [result(config, "autorun", "AutoRun policy", CheckStatus.PASS if disabled else CheckStatus.FAIL,
                       f"Machine NoDriveTypeAutoRun={machine_drive}; Machine NoAutorun={machine_command}; User NoDriveTypeAutoRun={user_drive}; User NoAutorun={user_command}", "AutoRun commands are disabled for all drive types by explicit policy." if disabled else "A complete all-drive AutoRun policy requires NoDriveTypeAutoRun=255 and NoAutorun=1 at the machine or current-user scope.")]
    except (ProbeError, TypeError, ValueError) as exc:
        return [unknown(config, "autorun", "AutoRun policy", exc)]


CHECK_GROUPS: tuple[Callable[[PowerShellRunner, dict[str, Any]], list[CheckResult]], ...] = (
    check_defender,
    check_firewall,
    check_bitlocker,
    check_secure_boot_and_tpm,
    check_windows_update,
    check_uac,
    check_accounts,
    check_smb1,
    check_remote_desktop,
    check_smartscreen,
    check_powershell_logging,
    check_autorun,
)

CHECK_GROUP_OUTPUTS: dict[Callable[..., list[CheckResult]], tuple[tuple[str, str], ...]] = {
    check_defender: (("defender_realtime", "Defender real-time protection"), ("defender_cloud", "Defender cloud-delivered protection"), ("defender_tamper", "Defender Tamper Protection"), ("defender_signatures", "Defender signature freshness")),
    check_firewall: (("firewall_domain", "Windows Firewall - Domain"), ("firewall_private", "Windows Firewall - Private"), ("firewall_public", "Windows Firewall - Public")),
    check_bitlocker: (("bitlocker_system", "BitLocker system-drive protection"),),
    check_secure_boot_and_tpm: (("secure_boot", "Secure Boot"), ("tpm", "Trusted Platform Module")),
    check_windows_update: (("windows_update", "Windows Update"),),
    check_uac: (("uac", "User Account Control"),),
    check_accounts: (("guest_account", "Guest account"), ("local_admins", "Local administrator membership")),
    check_smb1: (("smb1", "SMBv1 protocol"),),
    check_remote_desktop: (("remote_desktop", "Remote Desktop configuration"),),
    check_smartscreen: (("smartscreen", "Microsoft Defender SmartScreen"),),
    check_powershell_logging: (("powershell_logging", "PowerShell audit logging"),),
    check_autorun: (("autorun", "AutoRun policy"),),
}


def _run_check_group(check: Callable[..., list[CheckResult]], runner: PowerShellRunner,
                     config: dict[str, Any]) -> list[CheckResult]:
    try:
        findings = check(runner, config)
        if not isinstance(findings, list) or not all(isinstance(item, CheckResult) for item in findings):
            raise TypeError("The check returned an invalid result collection.")
        return findings
    except Exception as exc:
        return [unknown(config, check_id, title, exc) for check_id, title in CHECK_GROUP_OUTPUTS[check]]


def run_all_checks(config: dict[str, Any], runner: PowerShellRunner | None = None) -> list[CheckResult]:
    runner = runner or PowerShellRunner()
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="wincur-check") as pool:
        groups = list(pool.map(lambda check: _run_check_group(check, runner, config), CHECK_GROUPS))
    results = [finding for group in groups for finding in group]
    order = {check_id: index for index, check_id in enumerate(config["checks"])}
    return sorted(results, key=lambda finding: order.get(finding.check_id, 999))
