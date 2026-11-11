# WinCur

WinCur is a native Windows 11 security assessment
application built with Python and PySide6. It evaluates selected endpoint
security configurations, explains each result, and turns technical evidence
into an understandable hardening score, assessment coverage, and prioritized
next steps.

WinCur 1.0.0 is an assessment-only release for Windows 11 x64. The portable
build runs without Python installed, does not request administrator elevation,
and never applies or rolls back Windows configuration changes.

<p align="center">
  <img src="docs/screenshots/01-dashboard.png" alt="WinCur Overview dashboard showing the configuration-hardening score, assessment coverage, and priority findings" width="100%">
</p>

<p align="center"><em>The Overview dashboard summarizes assessed configuration strength, assessment coverage, and confirmed findings without presenting the score as a guarantee of security.</em></p>

## Project status

- Application version: **1.0.0**
- Scoring policy: **2.1**
- Platform: Windows 11 x64
- Interface: native PySide6/Qt desktop UI
- Distribution: portable, one-directory ZIP (no installer or updater)

The release application is assessment-only. **Administrator Scan, automated
remediation, and automated rollback are unavailable in v1.0.0.** Legacy
hardening research modules are
retained in the source tree for review and future development, but are not
reachable from the application entry point or bundled into the release build.

## Download and run

The public release is a portable Windows 11 x64 ZIP:

1. Download the ZIP from the GitHub release.
2. Extract the complete archive to a folder you can read and write. Do not run
   `WinCur.exe` from inside the ZIP.
3. Keep `WinCur.exe` beside its `_internal` folder and the included notices.
4. Launch `WinCur.exe`, then choose **Scan PC**.

WinCur 1.0.0 is unsigned. Windows SmartScreen or antivirus software may warn
about a newly downloaded, unsigned application. Verify the release checksum
and repository provenance before continuing. Do not disable SmartScreen,
antivirus, or other Windows protections to run WinCur.

No installation, Python runtime, service, or administrator account is
required. Moving the extracted folder is supported as long as the entire
folder is moved together.

## Capabilities

- **Windows security assessments:** read-only checks for Microsoft Defender,
  Windows Firewall, BitLocker, Secure Boot, TPM, Windows Update, UAC, local
  accounts, SMBv1, Remote Desktop, SmartScreen, PowerShell logging, and AutoRun
  policy.
- **Explainable results:** a configuration-hardening score, assessment coverage,
  severity, plain-language findings, evidence, and recommended next steps.
- **Assessment profiles:** Standard, Advanced, and Enterprise expectations with
  explicit informational and Not Applicable treatment.
- **Standard-user scans:** assessments run in the current process without
  requesting administrator elevation. Checks that cannot be evaluated are
  reported as Unknown rather than treated as passing. Secure Boot, TPM,
  BitLocker, local-administrator membership, SMBv1, SmartScreen, and other
  protected providers may be unavailable or incomplete depending on Windows
  edition, permissions, management policy, and installed security products.
- **Saved snapshots:** user-selected reference assessments for baseline
  comparison and observed configuration-difference analysis.
- **Local history and reporting:** persistent assessment history, hardening audit
  records, and HTML report export with escaped and sanitized evidence.
- **Native desktop experience:** Light, Dark, and Windows-system appearance modes
  in a PySide6/Qt interface.
- **Release engineering:** a portable PyInstaller development workflow with
  unique build IDs, manifest hashes, packaging probes, and distribution checks.

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
| Application entry | `main.py` | GUI startup and the non-security packaging probe |
| Desktop UI | `wincur/ui.py`, `wincur/theme.py`, `wincur/branding.py` | Navigation, views, themes, dialogs, and worker coordination |
| Assessment checks | `wincur/checks.py` | Read-only Windows evidence collection and result classification |
| Scoring | `wincur/scoring.py`, `wincur/scoring_config.json` | Profile-aware scoring and coverage policy |
| Models | `wincur/models.py` | Findings, assessments, previews, and action records |
| Snapshots and comparison | `wincur/baselines.py`, `wincur/baseline_comparison.py`, `wincur/drift.py` | Local reference snapshots and observed differences |
| Legacy hardening research | `wincur/hardening.py`, `wincur/helper.py`, `wincur/privileges.py` | Source-only research retained for review; excluded from the assessment-only executable |
| Persistence and reports | `wincur/storage.py`, `wincur/reporting.py`, `wincur/action_history.py` | Local durable storage and HTML export |
| Packaging | `WinCur.spec`, `tools/` | Internal Windows build, verification, and promotion tools |

The ordinary test suite covers assessment, scoring, persistence, UI, reporting,
and release-boundary behavior. An additional 10 Windows
registry integration tests are deliberately excluded from normal discovery and
must only be run in a disposable VM.

## Using reports and local data

Use **Export Report** after a scan to choose a destination for a local HTML
report. Reports can contain the device name, Windows version, local account
names or SIDs, security-product names, update identifiers, timestamps, and
configuration evidence. Review a report before sharing it.

WinCur stores preferences, scan history, saved snapshots, legacy read-only
hardening history, and logs below `%LOCALAPPDATA%\WinCur`. Removing the portable
application folder does not remove this data. WinCur does not upload it and has
no telemetry client.

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
- The release application has no automated hardening or rollback controls.
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

See [SECURITY.md](SECURITY.md) for the assessment-only release boundary and the
limitations of legacy source-only hardening research.

## Screenshots

### Security Issues

The checklist separates confirmed results from informational, unavailable, and
unassessed checks. Selecting a row opens its explanation and recommended next
step without crowding the table with raw evidence.

![WinCur Security Issues checklist with status, severity, summaries, and selected finding details](docs/screenshots/02-security-issues.png)

### Saved snapshot comparison

A saved assessment can be used as a reference for later comparisons. Results
distinguish observed improvements, regressions, unchanged checks, and cases
that require review because evidence or assessment visibility differs.

![WinCur Saved Snapshot Comparison showing summary counts and detailed check-by-check differences](docs/screenshots/04-snapshots.png)

### Activity history

Assessment and legacy action history remain local. Scan history records timestamp,
privilege, profile, score, and coverage while clearly treating saved assessments
as historical rather than current device state.

![WinCur Activity page showing locally persisted assessment history](docs/screenshots/05-activity.png)

## Packaging and redistribution

[PACKAGING.md](PACKAGING.md) documents the internal PyInstaller assessment-only
workflow. Release builds exclude the legacy mutation and elevation modules and
explicitly reject their former command-line modes.

Binary redistribution also requires the notices in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). The maintained build excludes
unused Qt PDF, QML, Quick, and Virtual Keyboard chains. WinCur uses the GPLv3
option for the remaining Qt/PySide components, so matching Qt 6.12.0 and Qt for
Python 6.12.0 corresponding source must be made available with the release.
Do not publish a binary if the release checklist in `PACKAGING.md` is incomplete.

## License

WinCur is free and open-source software licensed under the
**GNU General Public License, version 3 only** (`GPL-3.0-only`). See
[`LICENSE`](LICENSE) for the complete terms and [`NOTICE.md`](NOTICE.md) for
contributor, branding-asset, and dependency notices.

Copyright in individual contributions remains with the respective
contributors. The project does not claim exclusive copyright in the
AI-generated portrait artwork.

