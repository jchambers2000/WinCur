"""Local JSONL scan history and self-contained HTML report export."""

from __future__ import annotations

import html
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .models import ScanRecord
from .presentation import sanitize_display_text
from .storage import atomic_write_text, exclusive_write_text


def default_history_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "WinCur" / "scan_history.jsonl"


def save_history(record: ScanRecord, path: Path | None = None) -> Path:
    destination = path or default_history_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = record.to_dict()
    needs_separator = False
    if destination.exists() and destination.stat().st_size:
        with destination.open("rb") as existing:
            existing.seek(-1, os.SEEK_END); needs_separator = existing.read(1) not in (b"\n", b"\r")
    with destination.open("a", encoding="utf-8") as handle:
        if needs_separator: handle.write("\n")
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        handle.flush(); os.fsync(handle.fileno())
    saved = load_history(destination, limit=1)
    if not saved or saved[-1] != payload:
        raise OSError("The assessment history record could not be verified after saving.")
    return destination


def load_history(path: Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    source = path or default_history_path()
    if not source.exists():
        return []
    records: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
                if isinstance(record, dict): records.append(record)
            except json.JSONDecodeError:
                continue
    return records[-limit:]


def replace_history(records: list[dict[str, Any]], path: Path | None = None) -> Path:
    """Atomically replace scan history without touching snapshots or action history."""
    destination = path or default_history_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return destination


def delete_history_indices(indices: set[int], path: Path | None = None) -> tuple[Path, list[dict[str, Any]]]:
    """Delete exact zero-based records and return the path and removed records."""
    records = load_history(path, limit=1_000_000)
    valid = {index for index in indices if 0 <= index < len(records)}
    removed = [record for index, record in enumerate(records) if index in valid]
    retained = [record for index, record in enumerate(records) if index not in valid]
    return replace_history(retained, path), removed


def clear_history(path: Path | None = None) -> tuple[Path, list[dict[str, Any]]]:
    """Remove all saved assessments while preserving other WinCur stores."""
    records = load_history(path, limit=1_000_000)
    return replace_history([], path), records


def unique_report_path(directory: Path, filename: str) -> Path:
    """Return a non-existing HTML report path without changing an explicit later choice."""
    name = Path(filename).name
    if not name.lower().endswith(".html"): name += ".html"
    candidate = directory / name
    if not candidate.exists(): return candidate
    stem = Path(name).stem; match = re.fullmatch(r"(.*?)(?: \((\d+)\))?", stem); base = match.group(1) if match else stem; number = int(match.group(2) or 0) + 1 if match else 1
    while True:
        candidate = directory / f"{base} ({number}).html"
        if not candidate.exists(): return candidate
        number += 1


def assessment_report_filename(computer_name: str, timestamp_utc: str) -> str:
    """Return the report base name derived from the assessment's stored UTC date."""
    return f"WinCur-{computer_name}-{timestamp_utc[:10]}.html"


def export_html(record: ScanRecord, config: dict[str, Any], destination: Path, *, exclusive: bool = False) -> Path:
    def esc(value: object) -> str:
        return html.escape(sanitize_display_text(value), quote=True)

    score = "Not scored" if record.assessment.score is None else f"{record.assessment.score:.1f}%"
    category_rows = "".join(
        "<tr>"
        f"<td>{esc(category.category)}</td>"
        f"<td>{'Not scored' if category.score is None else f'{category.score:.1f}%'}</td>"
        f"<td>{category.coverage:.1f}%</td>"
        f"<td>{category.passed}</td><td>{category.failed}</td><td>{category.unknown}</td><td>{category.not_applicable}</td>"
        "</tr>"
        for category in record.assessment.categories
    )
    finding_rows = []
    for finding in record.results:
        remediation = finding.remediation
        recommendation = remediation.summary if remediation else "No recommendation is defined."
        disposition = record.assessment.dispositions.get(finding.check_id, "Scored")
        disposition_explanation = record.assessment.disposition_explanations.get(finding.check_id, "")
        remediation_detail = ""
        if remediation:
            remediation_detail = (
                f"<div><b>Permissions:</b> {esc(remediation.required_permissions)}</div>"
                f"<div><b>Impact:</b> {esc(remediation.impact)}</div>"
                f"<div><b>Verification:</b> {esc(remediation.verification)}</div>"
                f"<div><b>Rollback:</b> {esc(remediation.rollback)}</div>"
            )
        finding_rows.append(
            f"<section class='finding {esc(finding.status.value.lower().replace(' ', '-'))}'>"
            f"<h3>{esc(finding.title)} <span>{esc(finding.status.value)} · {esc(finding.severity)}</span></h3>"
            f"<p><b>Category:</b> {esc(finding.category)} &nbsp; <b>Within-category weight:</b> {finding.weight:g}</p>"
            f"<p><b>Scoring treatment:</b> {esc(disposition)}. {esc(disposition_explanation)}</p>"
            f"<p><b>Evidence:</b> {esc(finding.evidence)}</p>"
            f"<p><b>Explanation:</b> {esc(finding.explanation)}</p>"
            f"<p><b>Recommendation:</b> {esc(recommendation)}</p>{remediation_detail}</section>"
        )
    weights = ", ".join(f"{name} {values['weight']}%" for name, values in config["categories"].items())
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>WinCur Security Assessment</title>
<style>
body{{font:14px Tahoma,Arial,sans-serif;color:#17324d;background:#edf3f9;margin:0}}header{{color:white;padding:24px 32px;background:linear-gradient(#4f91ef,#0642ae)}}main{{max-width:1050px;margin:auto;padding:24px}}.score{{display:flex;gap:18px}}.metric,.finding{{background:white;border:1px solid #9aaec1;border-radius:6px;padding:14px;margin:12px 0}}.metric strong{{font-size:28px;color:#164a8e}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{border:1px solid #aebdcc;padding:8px;text-align:left}}th{{background:#d9e9fb}}h3 span{{float:right;font-size:13px}}.pass{{border-left:7px solid #36a430}}.fail{{border-left:7px solid #c84032}}.unknown{{border-left:7px solid #d18d00}}.not-applicable{{border-left:7px solid #73879b}}footer{{color:#536b7e;margin-top:24px}}@media print{{body{{background:white}}}}
</style></head><body><header><h1>WinCur Endpoint Security Assessment</h1><div>Configuration-hardening report · WinCur {esc(record.application_version)}</div></header><main>
<p><b>Computer:</b> {esc(record.computer_name)}<br><b>Windows:</b> {esc(record.windows_version)}<br><b>Scan time (UTC):</b> {esc(record.timestamp_utc)}<br><b>Assessment privilege:</b> {esc(record.assessment_privilege)}<br><b>Assessment profile:</b> {esc(record.assessment.profile)}<br><b>Scoring policy version:</b> {esc(record.assessment.policy_version)}<br><b>Assessment source:</b> {esc(record.assessment_source)}</p>
<div class="score"><div class="metric"><div>Assessed security score</div><strong>{score}</strong></div><div class="metric"><div>Assessment coverage</div><strong>{record.assessment.coverage:.1f}%</strong></div></div>
<p><b>Important:</b> This is a configuration-hardening score, not a guarantee that the device is secure. Unknown checks do not count as passes and reduce coverage. Not Applicable checks are excluded.</p>
<h2>Category summary</h2><table><thead><tr><th>Category</th><th>Score</th><th>Coverage</th><th>Pass</th><th>Fail</th><th>Unknown</th><th>N/A</th></tr></thead><tbody>{category_rows}</tbody></table>
<h2>Detailed findings and recommendations</h2>{''.join(finding_rows)}
<h2>Scoring methodology</h2><p>{esc(config.get('description', ''))}</p><p>Category weights: {esc(weights)}. Within each category, check weights are normalized across applicable, known results. Unknown results are excluded from the score calculation but reduce coverage. Entirely Not Applicable categories are excluded from overall weighting.</p>
<footer>Generated locally by WinCur. The report contains configuration evidence and the computer name, but no passwords, keys, tokens, file contents, or browsing data.</footer>
</main></body></html>"""
    if exclusive:
        exclusive_write_text(destination, document)
    else:
        atomic_write_text(destination, document)
    return destination

