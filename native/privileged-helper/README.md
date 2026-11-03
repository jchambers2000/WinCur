# WinCur native privileged helper — Phase 2C-2

This directory contains the C++20/Win32 skeleton for the future
`WinCur.PrivilegedHelper.exe`. It implements strict protocol parsing, the
global operation mutex, protected transaction results, embedded metadata, an
Administrator manifest, native read-only preview providers for the three
existing hardening actions, and a helper-owned confirmation boundary.

The helper is **not connected to WinCur, not signed, and not suitable for
distribution**. A valid `preview` request reads only compiled Windows targets
and writes a bounded result beneath the protected 64-bit
`HKLM\SOFTWARE\WinCur\Transactions` namespace. An eligible `apply` request
displays a native action-specific dialog, binds the response to the exact
request, and repeats read-only inspection before reaching the explicit
`Failed` / `NotImplemented` stub. `rollback` remains blocked because no
protected capsule exists. The helper performs no Windows security configuration
writes and creates no rollback state.

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

## Phase 2C boundary

The preview implementation reads only:

- the fixed 64-bit HKLM AutoRun values `NoDriveTypeAutoRun` and `NoAutorun`;
- the fixed 64-bit HKLM Script Block Logging, Module Logging, and `ModuleNames`
  wildcard policy values; and
- effective Domain, Private, and Public profile state through `INetFwPolicy2`,
  plus its documented `LocalPolicyModifyState` evidence.

The executable contains no:

- Windows security-configuration writer;
- remediation or rollback provider;
- rollback transport or rollback execution;
- filesystem request/result transport;
- Python, Qt, PowerShell, shell, or external-process execution; or
- integration with the PySide6 application or production packaging.

Protected results use an exact protected DACL: SYSTEM and Administrators have
full control, Built-in Users have read access, and inheritance is disabled.
Existing parents are accepted only when their owner and DACL exactly match the
compiled policy. Result records use bounded fields and write `Complete=1` last.
Readers reject incomplete, malformed, unexpected, or untrusted records.

Registry policy value locations do not identify whether a local administrator,
Local Group Policy, domain Group Policy, or MDM authored a value. Exact
compliance is reportable, but explicit conflicting values are blocked as
ambiguous instead of being called safely remediable. For firewall, a documented
Group Policy override is managed evidence; a non-override result is not claimed
as proof that a future profile write is authorized. Target-specific MDM source
attribution remains unresolved.

Phase 2C-2 adds a helper-owned Task Dialog for future apply and rollback
authorization. The fixed content names the action, proposed change, affected
setting, and security implications. Cancel, Escape, window closure, timeout,
dialog failure, binding mismatch, and reuse all deny authorization. Managed or
ambiguous evidence blocks before the dialog and again during the mandatory
post-confirmation read-only revalidation.

Signing, UI integration, rollback capsules, and every security-setting mutation
remain future milestones. Process exit alone is never an operation outcome;
future clients must read and validate the completed protected result. A complete
result does not imply confirmation or success. Protected transaction
pre-reservation remains required before any mutation backend is enabled.

## Disposable-VM confirmation dialog test

The optional confirmation harness embeds the same Administrator manifest and
uses the production native presenter, but it has no inspection or transaction
storage behavior and cannot change a security setting:

```powershell
cmake --preset msvc-x64-release `
  -DWINCUR_BUILD_CONFIRMATION_INTEGRATION_TESTS=ON
cmake --build --preset msvc-x64-release `
  --target WinCur.PrivilegedHelper.ConfirmationIntegrationTests

$env:WINCUR_RUN_CONFIRMATION_INTEGRATION = `
  'DISPOSABLE_WINDOWS_11_VM_NATIVE_DIALOG'
.\build\msvc-x64-release\WinCur.PrivilegedHelper.ConfirmationIntegrationTests.exe
```

Run it only in a disposable Windows 11 VM. Accept UAC, inspect the exact fixed
text, and exercise Confirm, Cancel, Escape, and title-bar Close in separate
invocations. Confirm exits 0; cancellation and closure exit 10. The five-minute
timeout may be checked in a dedicated invocation. No protected transaction is
created by this harness.

## Disposable-VM read-only inspection test

The optional integration executable calls the three native collectors directly.
It does not create a protected transaction or write registry state:

```powershell
cmake --preset msvc-x64-release `
  -DWINCUR_BUILD_INSPECTION_INTEGRATION_TESTS=ON
cmake --build --preset msvc-x64-release `
  --target WinCur.PrivilegedHelper.InspectionIntegrationTests
$env:WINCUR_RUN_READ_ONLY_INSPECTION_INTEGRATION = `
  'DISPOSABLE_WINDOWS_11_VM_READ_ONLY_INSPECTION'
.\build\msvc-x64-release\WinCur.PrivilegedHelper.InspectionIntegrationTests.exe
```

Run it in both standard and elevated VM sessions. Compare its stable message
codes with independent read-only registry and firewall queries. It prints no
raw policy values, user identity, or management enrollment details.

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
