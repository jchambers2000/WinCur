# ADR-0001: Portable native privileged helper

- Status: Accepted; M1-M3 and Phase 2D transaction foundation implemented
- Date: 2026-11-01
- Application version: WinCur 1.0.0 development candidate
- Scoring policy: 2.1 (unchanged)

Companion specifications:

- [Privileged-helper protocol version 1](privileged-helper-protocol-v1.md)
- [Threat model and implementation plan](privileged-helper-threat-model-and-plan.md)

## Context

WinCur is distributed as a portable Windows 11 x64 ZIP. The PySide6 interface
runs without elevation and requests UAC only for an Administrator assessment,
an individually confirmed hardening action, or rollback.

The current frozen Python helper accepts request, record, and result paths on
its command line. Those paths are not constrained with reparse-safe Windows
APIs, result files are under a user-writable directory, and automatic rollback
treats fields loaded from user-writable JSONL as captured prior state. An
elevated PyInstaller onedir process also loads Python, Qt, application modules,
and native libraries from the user-writable extraction directory.

These are security-boundary defects. Signing the current executable, comparing
path strings, or adding an unprotected hash to JSONL does not repair them.

## Decision

WinCur will use two processes with different trust roles:

- `WinCur.exe` remains a normal-integrity Python/PySide6 application. It is not
  trusted to authorize an Administrator change.
- `WinCur.PrivilegedHelper.exe` will be a separately built, Authenticode-signed,
  self-contained native Windows x64 executable. It will load no executable
  component from the portable application directory.

The native helper will:

- accept only a versioned protocol, fixed operation, allowlisted action, and
  canonical UUIDs;
- accept no filesystem path, registry path, command, script, configuration
  snapshot, preview token, or serialized request;
- independently capture configuration, determine management state, revalidate
  preconditions, and verify results;
- display its own high-integrity, action-specific confirmation before mutation
  or rollback;
- implement only the three existing hardening actions;
- use a protected fixed HKLM namespace for results and rollback authority;
- treat LocalAppData history as display data only; and
- fail closed when policy ownership, protected state, helper version, or
  verification is ambiguous.

The UI will launch the helper with `ShellExecuteExW` and `runas`, request a
process handle with `SEE_MASK_NOCLOSEPROCESS`, wait without blocking Qt, and
reconcile results from protected registry state. UAC denial or cancellation
must not change configuration.

## Native implementation choice

The preferred implementation is a small C++20 Win32 x64 program built with the
Microsoft toolchain and static CRT. It directly supports the Registry, COM,
ACL, Authenticode, UAC, and Task Dialog APIs without an additional runtime.

Rust with static CRT and a narrowly pinned Windows API crate is acceptable if
the maintainers can support its toolchain and license inventory. Python,
PyInstaller one-file, ordinary .NET self-contained, registered COM, scheduled
task, and installed-service helpers are rejected. C# is acceptable only if a
reviewed NativeAOT build loads no application-directory runtime. The final
language choice must be recorded before implementation.

## Trust boundaries

### Normal-integrity UI

The UI may request an allowlisted operation and display a preview. It is not
authoritative for management ownership, current configuration, confirmation,
rollback state, helper outcome, or rollback eligibility. UI compromise may
mislead the display or cause UAC prompts, but cannot expand the helper catalog.

### UAC and the user

The user must verify the expected publisher in UAC and then review the helper's
exact action confirmation. The helper confirmation is part of authorization
because another normal-integrity process can invoke the authentic helper.

### Native helper

The signed helper is the sole mutation authority. It must not delegate mutation
to Python, PowerShell, scripts, or an application-directory DLL.

### Protected machine state

Authoritative state is beneath a fixed 64-bit HKLM registry namespace.
Ordinary users can read only minimal result and index metadata. Rollback
capsules are accessible only to Administrators and SYSTEM.

## Supported privileged behavior

| Action ID | Preview | Apply | Automatic rollback |
|---|---:|---:|---:|
| `disable_autorun` | Yes | Yes | Yes |
| `enable_powershell_logging` | Yes | Yes | Yes |
| `enable_firewall_profiles` | Yes | Yes | No |

Protocol version 1 reproduces current semantics. It adds no security check,
hardening action, scoring rule, or batch operation.

## Helper integrity requirements

The helper must:

- be x64 with an explicit `requireAdministrator` manifest;
- be Authenticode-signed using SHA-256 and an RFC 3161 timestamp;
- embed code, strings, action definitions, icons, and protocol metadata;
- use static CRT and documented Windows system DLLs only;
- enable ASLR, DEP, stack protection, Control Flow Guard, and high-entropy ASLR;
- restrict optional DLL loading to System32 and never use unqualified names;
- ignore current directory and environment configuration;
- contain no general shell, script, file-copy, registry-path, or PowerShell
  facility;
- use bounded parsing, strings, and results;
- serialize operations through a global mutex; and
- enforce a protected minimum protocol and helper version.

Before launch, the UI should hold the helper open without write/delete sharing,
verify its embedded signature with `WinVerifyTrust`, require the expected
signer public-key identity, and retain the handle until `ShellExecuteExW`
starts the process. This is defense in depth; the user-visible boundary remains
UAC plus the helper confirmation because the UI is user-writable.

## Consequences

### Positive

- Assessments remain portable and non-elevated.
- UAC occurs only for explicit privileged operations.
- No elevated process imports Python or Qt from the ZIP.
- Privileged input contains no path or caller-defined state.
- JSONL tampering cannot authorize rollback.
- Existing hardening semantics and scoring policy remain unchanged.

### Costs

- The project gains a native toolchain and security-critical component.
- A trusted signing certificate and protected signing process are release
  prerequisites.
- Hardening creates protected machine state even though the app is portable.
- Python presentation and native enforcement catalogs require build-time
  generation or strict parity tests; the helper never loads the catalog at
  runtime.
- Existing JSONL rollback records become display-only and cannot be promoted
  into trusted rollback authority.

## Alternatives rejected

- **Elevated PyInstaller onedir:** loads user-writable dependencies.
- **PyInstaller one-file helper:** still extracts or dynamically loads a large
  Python/native runtime.
- **Signed Python app with path IPC:** signing does not constrain paths,
  authenticate results, or protect rollback authority.
- **Installed service or COM broker:** violates download, extract, and run.
- **Signed LocalAppData rollback records:** a portable UI-accessible key cannot
  authenticate data against another same-user process.

## Remaining limitations

- Same-user malware can alter the UI and display history or cause authentic UAC
  prompts.
- The user must reject an unexpected publisher and review helper confirmation.
- Administrators, SYSTEM, kernel and offline attackers, and signing-key
  compromise are outside this boundary.
- Protected rollback state remains after the ZIP is deleted.
- Signed downgrade protection works only after a protected minimum exists and
  therefore must be present in the first public helper.
- Policy APIs may remain ambiguous; ambiguity blocks mutation.
- The helper must not interpret appended unsigned PE content.
- Phase 2C-2 supplies one-use, exactly bound helper confirmation and repeats
  read-only inspection after confirmation. No mutation backend or rollback
  capsule exists. Before mutation is implemented, the transaction UUID must be
  reserved in protected state before the dialog so a second helper process
  cannot reuse a completed or in-flight identifier. Phase 2D implements that
  reservation and fail-closed interruption recovery, but no mutation backend.
- Registry ACLs prevent ordinary users from transitioning protected state. They
  cannot distinguish the authentic helper from another Administrator; existing
  Administrators remain outside the stated attacker boundary.
- Phase 2E-1 implements private, versioned pre-change capsules and read-only
  reconciliation. Capsules preserve fixed-target key/value absence, registry
  type, and exact bytes, but are not yet wired to apply or rollback.
- Firewall effective state and modify authority are readable through documented
  COM interfaces, but rollback-grade local per-profile state is not established.
  Firewall mutation stays disabled rather than treating effective state as
  locally owned configuration.
- Phase 2E-2 integrates unique capsule creation, durability verification,
  protected transaction binding, capsule-bound confirmation, post-confirmation
  exact-state comparison, and immediate pre-boundary reread. Because current
  ownership evidence remains ambiguous, production apply fails closed before
  confirmation. The only backend remains non-mutating and rollback remains
  unavailable.

## References

- [Running with Administrator Privileges](https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-administrator-privileges)
- [ShellExecuteEx](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa)
- [WinVerifyTrust example](https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file)
- [Registry key security](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2)
