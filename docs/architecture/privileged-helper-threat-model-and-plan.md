# Portable privileged helper: threat model and implementation plan

This turns ADR-0001 and protocol version 1 into implementation and test work.
M1 and M2 are implemented as a development foundation. Phase 2C-1 implemented
fixed-target read-only inspection. Phase 2C-2 adds helper-owned confirmation,
one-use binding, cancellation handling, and post-confirmation revalidation
without enabling a security-configuration write.
Phase 2D adds protected pre-operation reservation, explicit lifecycle
transitions, and no-retry interruption recovery. Security-setting mutation and
rollback execution remain absent.

- [Architecture decision record](0001-portable-native-privileged-helper.md)
- [Protocol version 1](privileged-helper-protocol-v1.md)

## Security objectives

1. Keep assessments and PySide6 at normal integrity.
2. Require UAC only for Administrator operations.
3. Prevent a normal user process from choosing privileged paths, commands,
   registry targets, or rollback data.
4. Independently revalidate and confirm every mutation in a recognizable signed
   helper.
5. Preserve exact-state rollback without trusting user-writable history.
6. Fail closed on interruption, ambiguity, management, staleness, partial
   changes, or failed verification.
7. Preserve scoring policy 2.1 and the three current action semantics.

## Assets

- Windows security configuration changed by WinCur.
- Administrator token and the operations performed with it.
- Original and operation-owned rollback state.
- Integrity of helper outcomes and hardening audit claims.
- Signing key and publisher identity.
- Availability of rollback after a confirmed WinCur change.
- User understanding of the exact authorized action.

Ordinary assessment history and preferences require durability but are not
privileged authorization assets.

## Attacker model

### In scope

A malicious process running as the same unelevated user may:

- read, modify, replace, or delete the extracted portable folder;
- modify `%LOCALAPPDATA%\WinCur`, including JSONL;
- inspect command lines and environment variables;
- invoke the authentic helper and cause UAC prompts;
- precreate objects in user-writable locations;
- race files and create junctions, links, or alternate data streams where
  permitted;
- spoof UI content and local history;
- terminate the UI or deny portable-file access; and
- supply malformed, oversized, stale, duplicated, or replayed identifiers.

The user may accidentally approve a WinCur UAC request. The helper therefore
shows the exact action again after elevation and before mutation.

### Assumptions

- Windows 11 x64, UAC, code integrity, registry ACLs, and system DLL protections
  work correctly.
- The user rejects an unexpected UAC publisher.
- The signing key is not compromised.
- The authentic helper was built from reviewed source and signed after review.

### Out of scope

- Existing Administrator, SYSTEM, kernel, or equivalent policy authority.
- Offline modification or a compromised Windows installation.
- Signing-key theft or misuse.
- Social engineering that obtains approval for an unexpected publisher and a
  clearly described unwanted action.
- Availability attacks that delete the app or prevent UAC.

These exclusions must be disclosed and not described as WinCur protections.

## Abuse cases

| Abuse case | Required control |
|---|---|
| Protected or UNC path supplied | Protocol accepts no path |
| Registry target/value supplied | Targets and values are compiled |
| JSONL rollback forged | Helper loads protected capsule by UUID |
| Helper invoked directly | UAC plus helper-owned exact confirmation |
| Helper replaced | Authenticode, pinned signer check, held file handle, UAC publisher |
| Older valid helper substituted | Protected minimum version checked by every public helper |
| Result spoofed | Protected HKLM result; no result file |
| Transaction replayed | Existing protected UUID is rejected |
| Apply and rollback race | Global mutex and lifecycle state machine |
| State changes after UI preview | Helper captures immediately before mutation |
| State changes before rollback | Exact equality with protected owned state |
| Crash after a write | Write-ahead capsule and fail-closed recovery |
| Managed state ambiguous | Block without mutation |

## Native helper requirements

### Build

- x64 release build with pinned compiler/toolchain.
- Static CRT or equivalent self-contained runtime.
- No plugin discovery, scripting, runtime package manager, or dynamic config.
- Reproducible source manifest and dependency/license inventory.
- Warnings as errors, static analysis, and import inspection.
- Private debug symbols scrubbed of developer-local paths before optional use.

### Process

- Explicit `requireAdministrator` manifest and Unicode entry point.
- Strict argument parser and no inherited request handles.
- No standard-output protocol, caller-selected log, network, or filesystem IPC.
- No secrets or raw original state in public results.
- Structured handling at every Windows API boundary.
- Bounded operation time without forced termination after mutation.
- Process exit alone is never interpreted as success.

### Windows API use

- Registry operations use `KEY_WOW64_64KEY` and least access.
- Protected keys have explicit DACLs validated on reuse.
- Firewall uses documented COM interfaces and fixed profiles.
- MDM or Group Policy uncertainty fails closed.
- UI uses `ShellExecuteExW`, retains the process handle, and stays responsive.
- Signature validation pins signer identity while the helper is held against
  replacement.

### Signing

- Publicly trusted code-signing certificate.
- Hardware-backed or managed key custody.
- SHA-256 signature and RFC 3161 timestamp.
- Sign after final build and before manifest hashing.
- Verify on the build machine, independent verifier, extracted ZIP, and VM.
- Document emergency certificate revocation and replacement.

## Implementation milestones

### M0 — Resolve prerequisites

- [ ] Choose C++20 or Rust and record the choice.
- [ ] Pin toolchain versions and license policy.
- [ ] Establish publisher identity and certificate custody.
- [ ] Approve protocol IDs, limits, exit codes, ACLs, and retention.
- [ ] Decide Python/native action-catalog generation and parity checks.
- [ ] Define supported Windows 11 editions and minimum build.

### M1 — Non-mutating skeleton

- [ ] Add hardened x64 native project.
- [ ] Embed manifest, version, icon, protocol, and action catalog.
- [ ] Implement strict parser with a backend that cannot access settings.
- [ ] Implement global mutex.
- [ ] Implement cancellation-only Task Dialog prototype.
- [ ] Inspect signature, imports, and dependencies in developer tooling.
- [ ] Prove it loads only protected Windows system DLLs.

M1 must not read or change security configuration.

### M2 — Protected result transport

- [ ] Create and validate HKLM root and ACLs.
- [ ] Implement transaction schema and Complete-last rule.
- [ ] Bound result cleanup without touching rollback capsules.
- [ ] Add normal-integrity read-only result client prototype.
- [ ] Test alternate-credential UAC and multi-user reads.

M2 writes only WinCur's protected protocol registry namespace.

### M3 — Read-only native preview

- [x] Port fixed-target capture for all three actions.
- [x] Produce bounded human-readable descriptions without raw dictionaries.
- [ ] Compare native results with Python backend fixtures and VM evidence.
- [x] Block ambiguous, inaccessible, malformed, and unsupported evidence.
- [ ] Add target-specific positive Group Policy/MDM attribution for registry
  actions only where a documented Windows provider is sufficiently reliable.

Phase 2C-1 intentionally does not infer organization management from domain
join, MDM enrollment alone, or the mere presence of a registry policy value.
Those signals do not prove which authority owns the selected target. Exact
compliance remains observable; conflicting existing values are ambiguous and
cannot authorize a future mutation. Firewall Group Policy override is accepted
only from the documented `INetFwPolicy2::LocalPolicyModifyState` result.

### M4 — Apply and verification

- [x] Implement helper-owned action-specific confirmation and cancellation.
- [x] Bind a one-use receipt to operation, action, transaction, rollback ID,
  and an unpredictable challenge.
- [x] Revalidate read-only evidence after apply confirmation.
- [x] Reserve the protected transaction UUID before inspection or confirmation.
- [x] Reject every preexisting UUID before confirmation, regardless of whether
  its record is complete, incomplete, malformed, or legacy.
- [x] Implement exact-binding lifecycle transitions and no-retry interruption
  recovery while mutation backends remain disabled.
- [ ] Port AutoRun apply and verification.
- [ ] Port PowerShell logging apply and verification.
- [ ] Port firewall COM apply and verification.
- [ ] Write protected state before registry mutation.
- [ ] Preserve partial and failed verification reporting.

Phase 2C-2 uses a native Task Dialog in the elevated helper. Cancel, Escape,
window closure, five-minute timeout, dialog creation failure, receipt mismatch,
and receipt reuse all deny authorization. The dialog content is compiled into
the helper; the Python UI supplies none of it. Initial managed or ambiguous
evidence blocks before the dialog, and fresh managed or ambiguous evidence
blocks after confirmation. Apply still ends at the non-mutating backend.

Rollback confirmation cannot be offered by the executable until a protected
capsule resolves the action and proves exact owned state. Rollback therefore
returns `BlockedPrecondition` in this phase. Unit tests exercise the future
binding path without creating or trusting rollback state.

### Phase 2D — transaction reservation and interruption

The helper exclusively creates the protected transaction key and durably writes
its exact binding before reading an action target or displaying confirmation.
Reservation failure, duplicate UUID, weak ACL, malformed parent state, or a
partial reservation stops the request. An abandoned but structurally valid
reservation is converted to a completed `Interrupted` record only after a later
helper acquires the global mutex. It is never resumed or retried.

The ordinary-user boundary is enforced by the exact protected DACL and by
validating it on every open. Windows registry ACLs do not authenticate a
specific executable against another Administrator. Administrator/SYSTEM
tampering remains out of scope and is an explicit limitation, not a claimed
helper-only guarantee.

Recovery enumerates at most 4,096 fixed-namespace transaction children. Valid
interrupted records are eligible for the existing completed-result count
retention. Partial, malformed, noncanonical, and untrusted records are retained;
they can cause bounded denial of service but cannot authorize or retry a change.

Before the first mutation backend is implemented, crash recovery for
`Executing` and `Verifying` must be redesigned around a durable pre-change
capsule and exact current-state reconciliation. Phase 2D's generic Interrupted
classification is intentionally limited to the current non-mutating helper.

### M5 — Protected rollback

- [ ] Implement capsule slots and lifecycle.
- [ ] Implement exact-state precondition.
- [ ] Implement AutoRun and PowerShell logging rollback.
- [ ] Implement interruption reconciliation.
- [ ] Expose read-only rollback index.
- [ ] Make legacy JSONL non-actionable.

### M6 — PySide6 integration

- [ ] Add explicit internal-to-protocol action mapping.
- [ ] Verify helper signer, version, architecture, and protocol.
- [ ] Hold helper against verify/launch replacement.
- [ ] Launch with process-handle `ShellExecuteExW`.
- [ ] Read protected transactions asynchronously.
- [ ] Reconcile results into local audit display.
- [ ] Remove privileged Python-helper use from packaged execution.
- [ ] Preserve preview/apply separation and scan behavior.

### M7 — Release engineering

- [ ] Publish helper source, licenses, and build scripts.
- [ ] Add signing and post-sign verification.
- [ ] Record helper hash, protocol, signer, version, and source commit.
- [ ] Bundle third-party notices.
- [ ] Verify ZIP extraction and relocation.
- [ ] Complete independent review and clean-VM acceptance.

## Test plan

### Parser and protocol

- Valid grammar for each operation.
- Missing, duplicate, reordered, extra, unknown, abbreviated, positional, and
  response-file arguments.
- Unsupported protocol/action, non-ASCII, embedded-NUL handling, and overlong
  input.
- Braced, uppercase, zero, malformed, duplicate, and replayed UUIDs.
- Rollback containing a caller-supplied action fails.
- No field is interpreted as a path.

### Protected state

- Exact schemas and every legal lifecycle transition.
- Every illegal transition, extra/missing value, wrong type, overlong string,
  and unsupported schema.
- Complete marker written last.
- Reservation marker written last and flushed before action-specific work.
- Exact lifecycle transitions and immutable binding validation.
- Valid abandoned reservations become Interrupted without retry.
- Partial/malformed reservations remain retained and non-authoritative.
- Sanitization and length bounds.
- Minimum version increases but never decreases.

### ACL integration on disposable Windows 11

- Standard user cannot create, modify, rename, or delete transactions.
- Standard user reads only public metadata and cannot read capsules.
- Administrator/SYSTEM rights match the specification.
- Inheritance is disabled.
- Weak, extra-writer, corrupt, missing, or wrong-owner ACL fails closed.
- No shadow authority exists in the 32-bit registry view.
- Multi-user and alternate-credential UAC behavior is verified.

Most destructive registry integration tests compile the production storage
implementation against the dedicated 64-bit
`HKLM\SOFTWARE\WinCurNativeHelperTests` namespace. They refuse any preexisting
test root in either registry view and clean only fixed, harness-owned names with
non-recursive deletion. A separate minimal acceptance executable uses
`HKLM\SOFTWARE\WinCur`, refuses any preexisting root, creates the root
exclusively, never deletes production-path state, and must be followed by a VM
snapshot revert.

### Phase 2B hardening review boundaries

- Registry handles are opened with `REG_OPTION_OPEN_LINK` and the 64-bit view.
  Owner and exact DACL validation occurs after every create-or-open operation.
  Subsequent child creation is relative to the validated open handle, so a
  standard user cannot redirect the path between validation and use.
- An Administrator or SYSTEM process can still change or replace protected
  state and is outside the stated attacker boundary. Independent review must
  confirm that this assumption is suitable for release messaging.
- Result values are flushed before publishing `Complete=1`, and the completion
  marker is flushed before persistence success. This is not yet evidence of
  behavior under abrupt VM power-off, host failure, hive recovery, or storage
  fault. Those cases require fault-injection testing.
- Incomplete records are never considered successful or automatically deleted.
  Repeated helper crashes can therefore accumulate records and eventually
  exhaust the 4,096-key enumeration safety bound. Recovery classification and
  bounded cleanup remain future work and must run only while holding the global
  operation mutex.
- Retention re-reads a completed candidate before deletion, but independent
  review and concurrent fault injection are still required for key replacement,
  rename, deletion-pending handles, and registry notification races.

### Helper integrity

- Valid signer/timestamp and rejection of unsigned, modified, wrong-signer,
  wrong-architecture, revoked, and wrong-version helpers.
- Replacement attempt between verification and launch.
- Older signed helper rejected after protected minimum advances.
- Import table permits only approved system DLLs.
- Process Monitor finds no executable load from the ZIP except helper image.
- PATH, current directory, environment, and planted adjacent DLLs have no
  effect.

### Adversarial invocation

- Direct invocation still requires UAC and exact helper confirmation.
- Path-like, UNC, device, ADS, traversal, junction, symlink, and hardlink text is
  rejected.
- Malformed invocation has no filesystem or security-setting effect.
- Transaction flooding is bounded.
- Concurrent operations fail Busy or serialize.
- Lower-integrity automation cannot confirm the elevated dialog.
- UAC denial, cancellation, helper cancellation, crash, hang, and UI exit never
  claim success.
- Confirmation receipts are process-local and one-use. Cross-process replay is
  prevented by exclusive protected transaction reservation.
- Global mutex abandonment permits recovery but does not itself authenticate
  helper identity or survive process termination.

### Action compatibility

- Mocked and VM cases for compliant, absent, malformed, conflicting, managed,
  denied, partial, failed verification, and external change.
- AutoRun requires both exact DWORD values.
- PowerShell logging requires both enable values and wildcard rule.
- Firewall changes only disabled profiles and never offers rollback.
- Group Policy or MDM ambiguity blocks mutation.
- Scoring and assessment results remain unchanged.

### Rollback adversarial tests

- Forged, edited, duplicated, deleted, and corrupt JSONL has no eligibility
  effect.
- Unknown, absent, consumed, partial, interrupted, discarded, and wrong-schema
  capsules are rejected.
- State differing from owned blocks writes.
- Existing and absent values restore exactly.
- Unrelated values and subkeys survive.
- Created keys are removed only when empty.
- Crash injection before and after every lifecycle and target write.
- Replay after success, partial result, and restart.
- Prepared recovery classifies original, desired, and mixed state correctly.

### UI integration

- Standard assessments never invoke helper.
- Preview and Apply remain separate.
- UAC cancellation preserves displayed assessment and preview state.
- Only completed protected transactions are accepted.
- No arbitrary path reaches native arguments.
- Audit history stores identifiers, not rollback authority.
- Legacy records are historical and non-rollbackable.
- UI remains responsive while waiting on process handle.

### Packaging and clean VM

- ZIP has one signed native helper and no helper runtime dependency.
- Manifest records post-sign hashes and source commit.
- License inventory covers native and Python distributions.
- Extract, relocate, assess, approve/cancel UAC, restart, and reconcile on clean
  Windows 11 x64 VMs.
- Test spaces, Unicode, long paths, read-only folders, and 100/125/150% DPI.
- Verify all changes with independent read-only Windows commands.

## Exit criteria

The remediation-enabled portable release remains blocked until the helper and
UI meet ADR-0001, protected state and action backends pass adversarial VM tests,
an independent reviewer examines helper/signing/ACL/lifecycle changes, no
Python mutation helper is reachable in the public build, redistribution notices
are complete, and the exact signed ZIP passes clean-VM acceptance.

## Unresolved questions

1. C++20 or Rust?
2. Which publisher identity and certificate custody process?
3. Which Windows 11 builds and editions are supported?
4. One generated action catalog or independently maintained catalogs with
   strict parity tests?
5. Is minimal transaction metadata readable by all Built-in Users acceptable?
6. What retention and discard UX applies to protected capsules?
7. Can native firewall APIs establish management ownership across the supported
   matrix, or must some environments remain manual-only?
8. Who performs independent native security review?

## Recommended first implementation task

Resolve M0, then implement only M1: a hardened x64 native executable with an
Administrator manifest, embedded version/protocol, strict parser, global mutex,
and cancellation-only Task Dialog. Its backend must be a stub unable to read or
change security configuration. Tests must prove invalid input has no side
effects and the helper imports no application-directory runtime.
