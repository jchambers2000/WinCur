# Security Policy

## Release status

WinCur 1.0.0 is a consumer-focused, assessment-only Windows security utility.
The public portable build is intended for Windows 11 x64 and is not an endpoint
management agent, compliance authority, or substitute for independent security
review.

The configuration-hardening score covers selected settings only. It does not
guarantee system security.

## Assessment-only release boundary

The WinCur 1.0.0 release application performs read-only assessments in the
current user context. It does not request UAC elevation and does not expose
remediation or rollback controls. Former internal `--helper-*` modes are
rejected by the entry point, and the legacy mutation/elevation modules are
excluded from the PyInstaller distribution.

## Legacy source limitations

### Elevated-helper path boundary

The retained source-only elevated helper modes accept request, record, and
output paths through command-line arguments. Those paths are not yet fully
canonicalized and constrained to WinCur's trusted pending directory, including
protection against traversal and Windows reparse-point attacks.

An explicitly UAC-approved invocation of that legacy source could therefore
misuse the helper as a privileged file-operation proxy. These modules must not
be reconnected to a public build until the boundary is replaced and
independently tested.

### Rollback-record trust

Legacy hardening action history is stored as user-writable JSONL. Rollback validation
checks schema, action identifiers, and current configuration state, but the
record itself is not cryptographically authenticated or loaded from an
administrator-protected authoritative store.

A locally modified record could influence a later UAC-approved rollback if the
legacy workflow were restored. The assessment-only application displays any
existing action history read-only and provides no rollback action.

### Local evidence and Windows services

Local history and reports may contain computer names, account names and SIDs,
security-product names, update identifiers, and configuration evidence. Files
are stored below `%LOCALAPPDATA%\WinCur` and are not encrypted by WinCur.

WinCur contains no telemetry client. Its Windows Update check uses the Windows
Update Agent, which may communicate with the update service configured on the
device.

## Safe evaluation

- Review the source before running it.
- Use a disposable Windows 11 VM with a restorable snapshot.
- Run ordinary tests without elevation.
- Treat assessments as advisory and validate important findings independently.
- Do not reconnect or invoke legacy remediation or rollback workflows on
  production systems.
- Verify the published SHA-256 checksum before running a downloaded archive.
- WinCur 1.0.0 is unsigned. Treat an unexpected UAC prompt as a release-
  integrity failure and cancel it; do not disable SmartScreen or antivirus.

## Reporting a vulnerability

Do not include exploit details, local evidence, or personal information in a
public issue. After the GitHub repository exists, use GitHub's private
vulnerability-reporting or Security Advisory feature if it is enabled. If it
is not enabled, contact the repository owner privately through the owner's
GitHub profile before disclosing details publicly.

When reporting, include the affected version or commit, expected security
boundary, reproduction conditions, and impact. Do not attach real endpoint
history, rollback records, logs, or exported reports without removing personal
and device information.

## Supported versions

The latest published 1.0.x assessment-only release is supported for security
reports. Legacy source-only hardening workflows and unpublished development
builds are not supported for endpoint modification.

