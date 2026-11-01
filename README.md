# WinCur

WinCur is a Windows 11 endpoint security assessment and hardening research
project built with Python and PySide6. It presents selected Windows security
configuration checks in a native desktop interface, explains how results affect
an assessment score, and provides tightly scoped remediation previews for a
small set of settings.

This repository is published as a source-code portfolio project. WinCur is
still under security review and is **not currently recommended for public
binary distribution or production endpoint management**.

## Project status

- Application version: **1.0.0 development candidate**
- Scoring policy: **2.1**
- Platform: Windows 11
- Interface: native PySide6/Qt desktop UI
- Publication scope: source code, tests, documentation, and development tools
- Executables, virtual environments, build outputs, and user data are excluded

The assessment engine is read-only. WinCur also contains three opt-in hardening
workflows—AutoRun policy, PowerShell audit logging, and Windows Firewall
profiles—which can modify Windows after preview, confirmation, and UAC. Known
limitations in the elevated-helper and rollback trust boundaries are documented
in [SECURITY.md](SECURITY.md); do not use those workflows on production systems.

## Highlights

- Read-only checks for Microsoft Defender, Windows Firewall, BitLocker, Secure
  Boot, TPM, Windows Update, UAC, local accounts, SMBv1, Remote Desktop,
  SmartScreen, PowerShell logging, and AutoRun policy.
- Explainable configuration-hardening score and assessment coverage.
- Standard, Advanced, and Enterprise assessment profiles.
- Clear Pass, Fail, Unknown, Not Applicable, and informational treatment.
- Local assessment history, saved snapshots, comparison and drift analysis.
- HTML report export with escaped and sanitized evidence.
- Light, Dark, and Windows-system appearance modes.
- Preview-first hardening workspace with explicit confirmation, UAC,
  precondition revalidation, post-change verification, and rollback safeguards.
- Portable PyInstaller development workflow with build IDs and manifest hashes.

The score measures selected configuration-hardening settings. It is not a
guarantee that a computer is secure and does not replace endpoint protection,
patch management, backups, monitoring, or organizational security policy.

## Technology

- Python 3.11 or newer
- PySide6 / Qt 6
- Windows PowerShell and supported Windows cmdlets
- Documented Windows registry settings and Windows APIs
- `unittest` with mocked Windows providers
- PyInstaller for internal one-directory build evaluation

## Architecture

| Area | Key modules | Responsibility |
|---|---|---|
| Application entry | `main.py` | GUI startup and narrowly scoped helper dispatch |
| Desktop UI | `wincur/ui.py`, `wincur/theme.py`, `wincur/branding.py` | Navigation, views, themes, dialogs, and worker coordination |
| Assessment checks | `wincur/checks.py` | Read-only Windows evidence collection and result classification |
| Scoring | `wincur/scoring.py`, `wincur/scoring_config.json` | Profile-aware scoring and coverage policy |
| Models | `wincur/models.py` | Findings, assessments, previews, and action records |
| Snapshots and comparison | `wincur/baselines.py`, `wincur/baseline_comparison.py`, `wincur/drift.py` | Local reference snapshots and observed differences |
| Hardening | `wincur/hardening.py`, `wincur/helper.py`, `wincur/privileges.py` | Preview, UAC helper, verification, audit, and rollback logic |
| Persistence and reports | `wincur/storage.py`, `wincur/reporting.py`, `wincur/action_history.py` | Local durable storage and HTML export |
| Packaging | `WinCur.spec`, `tools/` | Internal Windows build, verification, and promotion tools |

The ordinary test suite contains 261 test methods. An additional 10 Windows
registry integration tests are deliberately excluded from normal discovery and
must only be run in a disposable VM.

## Development setup

Use a Windows 11 development machine or disposable VM. From the repository
root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Launching the application does not automatically scan or change Windows.
Choose **Scan PC** to run the read-only assessment.

## Tests

Run the mocked regression suite without elevation:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

The separate registry integration harness writes only beneath a uniquely owned
`HKEY_CURRENT_USER\Software\WinCur\IntegrationTests` namespace. Its source and
safety gates are in `tests/integration/registry_rollback_windows.py`. Use it
only in a disposable VM after reviewing the file.

## Safety and data handling

- Assessments do not intentionally modify Windows configuration.
- Hardening actions are separate, explicit, and administrator-authorized.
- WinCur does not collect BitLocker recovery keys, passwords, browsing history,
  or file contents.
- Assessment history, snapshot data, preferences, hardening history, and logs
  are stored locally below `%LOCALAPPDATA%\WinCur`.
- Stored evidence can include the computer name, Windows version, local account
  names and SIDs, security-product names, update identifiers, timestamps, and
  configuration values.
- WinCur has no telemetry client. The Windows Update assessment uses the
  Windows Update Agent, which may contact the update service configured on the
  device.

See [SECURITY.md](SECURITY.md) before evaluating elevated helpers or hardening
features.

## Screenshots

No publication-ready application screenshots are currently included. The
portrait and icon under `wincur/assets/` are runtime branding assets, not UI
screenshots, and should be published only after their copyright and likeness
permissions are confirmed.

## Packaging

[PACKAGING.md](PACKAGING.md) documents the internal PyInstaller evaluation
workflow. Build outputs are intentionally excluded from this source-only
repository. No executable is being offered or recommended through this GitHub
publication.

## License

WinCur is free and open-source software licensed under the
**GNU General Public License, version 3 only** (`GPL-3.0-only`). See
[`LICENSE`](LICENSE) for the complete terms and [`NOTICE.md`](NOTICE.md) for
contributor, branding-asset, and dependency notices.

Copyright in individual contributions remains with the respective
contributors. The project does not claim exclusive copyright in the
AI-generated portrait artwork.

