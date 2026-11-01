# Security Policy

## Development status

WinCur is a development-stage Windows security assessment project. This public
repository is intended for source review, education, and portfolio evaluation.
It is not currently recommended for public binary distribution, deployment on
production endpoints, or use as an organizational compliance authority.

The configuration-hardening score covers selected settings only. It does not
guarantee system security.

## Known security limitations

### Elevated-helper path boundary

WinCur's internal elevated helper modes currently accept request, record, and
output paths through command-line arguments. Those paths are not yet fully
canonicalized and constrained to WinCur's trusted pending directory, including
protection against traversal and Windows reparse-point attacks.

An explicitly UAC-approved invocation could therefore misuse the helper as a
privileged file-operation proxy. Do not invoke internal `--helper-*` modes
directly and do not treat the current executable as safe for public
distribution until this boundary is corrected and independently tested.

### Rollback-record trust

Hardening action history is stored as user-writable JSONL. Rollback validation
checks schema, action identifiers, and current configuration state, but the
record itself is not cryptographically authenticated or loaded from an
administrator-protected authoritative store.

A locally modified record could influence a later UAC-approved rollback. Do
not rely on automatic rollback on production systems. Restore disposable VM
snapshots or use independently reviewed administrative procedures instead.

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
- Do not approve UAC prompts unless you intentionally initiated and reviewed
  the exact operation.
- Do not use remediation or rollback workflows on production systems.
- Do not publish or redistribute a binary until the documented security
  limitations and third-party license obligations are resolved.

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

No production version is currently supported. Security fixes will be developed
and validated in new release candidates before any binary distribution is
considered.

