WinCur 1.0.0 - Windows 11 x64 portable release
================================================

1. Extract the complete ZIP to a folder.
2. Keep WinCur.exe and the _internal folder together.
3. Launch WinCur.exe and choose Scan PC.

WinCur 1.0.0 performs read-only standard-user security assessments. It does
not provide Administrator Scan, automated remediation, or automated rollback,
and normal use must not produce a UAC prompt. Results marked Unknown were not
confirmed as passing; protected settings may be unavailable to a standard-user
scan.

Use Export Report to save an HTML report to a location you choose. Preferences,
scan history, snapshots, and logs remain under %LOCALAPPDATA%\WinCur even if
the portable folder is removed.

This unsigned executable is not digitally signed. Windows SmartScreen or antivirus may
display a warning. Verify the published SHA-256 checksum and release provenance.
Do not disable Windows security protections to run WinCur.

The configuration-hardening score covers selected settings and is not a
guarantee of device security.

License and notices
-------------------

See LICENSE, NOTICE.md, THIRD_PARTY_NOTICES.md, and the licenses folder included
with this package. build_info.json, validated_toolchain.json, and
frozen_dependency_inventory.json identify the build and runtime; the separately
published BUILD_MANIFEST.json records release hashes.

Project documentation and source: see the repository URL on the GitHub release.
