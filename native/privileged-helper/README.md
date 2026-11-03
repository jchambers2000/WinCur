# WinCur native privileged helper — Phase 2B

This directory contains the C++20/Win32 skeleton for the future
`WinCur.PrivilegedHelper.exe`. It implements strict protocol parsing, the
global operation mutex, protected transaction results, embedded metadata, an
Administrator manifest, and a non-mutating stub backend.

The helper is **not connected to WinCur, not signed, and not suitable for
distribution**. A syntactically valid request records an explicit `Failed` /
`NotImplemented` result beneath the protected 64-bit
`HKLM\SOFTWARE\WinCur\Transactions` namespace, displays `NotImplemented`, and
returns protocol exit code `0` because the completed protected result is
authoritative. It does not read or modify Windows security configuration and
does not create rollback state.

The controlling specifications are:

- [`ADR-0001`](../../docs/architecture/0001-portable-native-privileged-helper.md)
- [Protocol version 1](../../docs/architecture/privileged-helper-protocol-v1.md)
- [Threat model and plan](../../docs/architecture/privileged-helper-threat-model-and-plan.md)

## Pinned build inputs

- Visual Studio Build Tools 2026 (18.x) with the MSVC v143 x64 tools
- MSVC v143, x64 host and target tools
- Windows 11 SDK 10.0.26100.0
- CMake 3.25 or newer
- C++20 and the static multithreaded Microsoft runtime (`/MT` in Release)

Phase 2A verification used MSVC 19.44.35229, CMake 4.3.1-msvc1, and the
Windows 11 SDK 10.0.26100.0 tool directory (installed SDK product build
10.0.26100.9457).

The preset enables warnings as errors, SDL checks, stack protection, Control
Flow Guard, ASLR, high-entropy ASLR, DEP, CET compatibility, deterministic
compiler/linker output, and System32-only dependent DLL resolution metadata.
It builds serially to reduce nondeterministic build scheduling. Exact compiler,
SDK, CMake, and linker versions must be recorded with release evidence; this
project does not claim cross-toolchain bit-for-bit reproducibility.

## Configure, build, and test

Run these commands from this directory in an MSVC x64 Developer PowerShell.
The preset uses the bundled Ninja generator so it also works with Build Tools
installations that do not expose a discoverable Visual Studio IDE instance:

```powershell
cmake --preset msvc-x64-release
cmake --build --preset msvc-x64-release
ctest --preset msvc-x64-release
```

Generated files are placed under `build/`, which is excluded by the repository
`.gitignore`.

## Developer inspection

After a successful Release build:

```powershell
$binary = 'build\msvc-x64-release\WinCur.PrivilegedHelper.exe'
dumpbin /headers $binary
dumpbin /imports $binary
mt.exe -inputresource:"$binary;#1" -out:embedded-manifest.xml
Get-Content .\embedded-manifest.xml
```

Expected properties:

- AMD64 machine type.
- `/MT` static CRT; no `VCRUNTIME*.dll`, `MSVCP*.dll`, Python, Qt, PowerShell,
  or application DLL imports.
- ASLR, high-entropy VA, DEP, CFG, and CET-compatible image flags.
- `requireAdministrator`, `uiAccess=false`, and Common Controls v6 in the
  embedded manifest.
- File/helper version `1.0.0.0` and protocol version `1` in VERSIONINFO.

Do not invoke the helper merely to test parsing on a development machine. The
parser unit-test executable links the same parser and stub backend without an
Administrator manifest or UAC prompt.

## Phase 2B boundary

The executable contains no:

- Windows security-setting provider;
- registry configuration read/write code;
- firewall COM client;
- rollback transport or rollback execution;
- filesystem request/result transport;
- Python, Qt, PowerShell, shell, or external-process execution; or
- integration with the PySide6 application or production packaging.

Protected results use an exact protected DACL: SYSTEM and Administrators have
full control, Built-in Users have read access, and inheritance is disabled.
Existing parents are accepted only when their owner and DACL exactly match the
compiled policy. Result records use bounded fields and write `Complete=1` last.
Readers reject incomplete, malformed, unexpected, or untrusted records.

Helper-owned action confirmation, signing, UI integration, rollback capsules,
and every security-setting action remain future milestones. Process exit alone
is never an operation outcome; future clients must read and validate the
completed protected result.

## Disposable-VM registry integration tests

The ordinary CTest suite performs no HKLM writes. Both real-registry harnesses
are excluded by default and must never run on a development PC. Build them only
for a disposable Windows 11 VM:

```powershell
cmake --preset msvc-x64-release `
  -DWINCUR_BUILD_REGISTRY_INTEGRATION_TESTS=ON
cmake --build --preset msvc-x64-release `
  --target WinCur.PrivilegedHelper.RegistryIntegrationTests `
           WinCur.PrivilegedHelper.ProductionPathAcceptanceTests
```

The broad harness uses only the dedicated
`HKLM\SOFTWARE\WinCurNativeHelperTests` namespace. It refuses a preexisting
test root in either registry view, exercises weak-parent rejection, protected
results, replay rejection, 32/64-bit view isolation, interrupted and malformed
records, and then deletes only its fixed known keys with non-recursive APIs:

```powershell
$env:WINCUR_RUN_NATIVE_REGISTRY_INTEGRATION = `
  'DISPOSABLE_WINDOWS_11_VM_ONLY_I_ACCEPT_HKLM_WRITES'
.\build\msvc-x64-release\WinCur.PrivilegedHelper.RegistryIntegrationTests.exe
```

The minimal production-path acceptance harness is separate. It refuses any
preexisting `HKLM\SOFTWARE\WinCur` root in either registry view, uses an
exclusive protected-root create to close the absence-check race, performs one
protected write/read, and deliberately never deletes the resulting state:

```powershell
$env:WINCUR_RUN_PRODUCTION_PATH_ACCEPTANCE = `
  'DISPOSABLE_WINDOWS_11_VM_ONLY_I_ACCEPT_PRODUCTION_PATH_HKLM_WRITES'
.\build\msvc-x64-release\WinCur.PrivilegedHelper.ProductionPathAcceptanceTests.exe
```

Run either executable from an elevated console only after taking a VM snapshot.
Revert the VM after every run, including failures. Neither executable has a
`requireAdministrator` manifest; it intentionally refuses rather than prompting
when launched from a non-elevated console.

Completion-last now includes a registry flush before and after the completion
marker. Abrupt power-loss behavior, stale-incomplete recovery, retention under
crash flooding, and concurrent Administrator interference still require
disposable-VM fault injection and independent security review.
