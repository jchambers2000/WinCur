# WinCur privileged-helper protocol version 1

This specifies the proposed interface between normal-integrity `WinCur.exe`
and the future native `WinCur.PrivilegedHelper.exe`. It is a design contract,
not an implemented or supported interface.

This specification implements the decision in
[ADR-0001](0001-portable-native-privileged-helper.md). The associated
[threat model and plan](privileged-helper-threat-model-and-plan.md) defines the
required implementation and adversarial validation work.

## Invariants

1. Command-line data consists only of identifiers.
2. The helper accepts no path or caller-supplied configuration state.
3. Every mutation is allowlisted, revalidated, and confirmed after elevation.
4. Results and rollback authority exist only in protected HKLM state.
5. The helper does not trust LocalAppData, JSONL, Python, current directory,
   environment configuration, or a UI preview.
6. Unknown or ambiguous input fails before a security setting is changed.

## Character and size rules

- Switches and identifiers are ASCII.
- Action and operation identifiers use lowercase letters and hyphens.
- UUIDs are canonical lowercase `8-4-4-4-12` strings without braces.
- The complete command line is limited to 1,024 UTF-16 code units.
- Duplicate, unknown, abbreviated, positional, response-file, and alternate
  switch forms are rejected.
- Required switches appear exactly once; forbidden switches appear zero times.
- Environment variables are not expanded.

## Invocation grammar

```text
helper := WinCur.PrivilegedHelper.exe common operation-arguments

common :=
    --protocol 1
    --operation OPERATION
    --transaction UUID

OPERATION := preview | apply | rollback

preview := common --action ACTION_ID
apply   := common --action ACTION_ID
rollback := common --rollback-id UUID

ACTION_ID :=
    disable-autorun |
    enable-powershell-logging |
    enable-firewall-profiles
```

No other combination is valid. Rollback obtains its action from the protected
capsule; it never accepts one from the caller. The UI may keep its underscore
IDs but must use one explicit mapping to protocol IDs.

## Operation behavior

### Preview

- Used only when normal access cannot establish state.
- Reads configuration and management evidence.
- Performs no mutation and creates no rollback capsule.
- Writes a bounded sanitized result.
- Phase 2C-1 reports exact selected-value compliance separately from management
  authority. A completed result means collection finished and was durably
  recorded; only the `Outcome` and `MessageCode` describe whether inspection
  was conclusive.

### Apply

- Re-reads current state and management ownership.
- Refuses already compliant, managed, ambiguous, unsupported, or stale state.
- Displays the helper's exact action-specific confirmation. The fixed dialog
  identifies the operation, action, proposed change, affected Windows setting,
  and security implications. Its default is Cancel, Escape/window closure is
  cancellation, and the development timeout is five minutes.
- Binds the in-process confirmation receipt to the operation, action,
  transaction UUID, optional rollback UUID, and an unpredictable one-use
  challenge. A mismatch or reuse is denial.
- Re-reads the relevant evidence after confirmation. A newly compliant,
  managed, ambiguous, inaccessible, unsupported, or failed state blocks the
  operation.
- Writes protected pre-change state before mutation.
- Applies one compiled action, verifies, and records the outcome.
- Never starts an assessment.

### Rollback

- Loads a protected capsule by `--rollback-id`.
- Reads no rollback state from JSONL or command-line data.
- Requires available lifecycle and exact current owned state.
- Displays exact restoration in a helper-owned confirmation.
- Restores only fixed targets and verifies.
- Rejects firewall rollback because no firewall capsule exists.

### Phase 2C-2 implementation boundary

Preview remains read-only and never displays confirmation. Apply performs the
initial inspection, helper-owned confirmation, and post-confirmation inspection,
then returns the explicit non-mutating `NotImplemented` result. Managed or
ambiguous evidence never reaches the dialog. Rollback is blocked before a
dialog because protected rollback capsules are not implemented; the shared
confirmation state machine already supports a future resolved AutoRun or
PowerShell rollback binding.

Cancellation, timeout, dialog failure, binding mismatch, and validation blocks
are representable as complete protected results. `Complete=1` means only that
the result record is durably and structurally complete. It does not mean the
user confirmed or that a change succeeded.

Phase 2D reserves the transaction UUID before inspection, confirmation, or any
future privileged operation. The in-process one-use receipt and protected
reservation are both required: the receipt prevents reuse inside one helper,
while exclusive protected-key creation rejects cross-process UUID replay.

## Exit codes

Exit codes are diagnostic. A completed protected result is authoritative.

| Code | Symbol | Meaning |
|---:|---|---|
| 0 | `SUCCESS` | Completed; inspect result outcome |
| 10 | `USER_CANCELLED` | Helper confirmation cancelled |
| 11 | `INVALID_ARGUMENTS` | Invocation did not match grammar |
| 12 | `UNSUPPORTED_PROTOCOL` | Protocol or helper version unsupported |
| 13 | `BLOCKED` | Managed, ambiguous, compliant, or precondition block |
| 14 | `FAILED` | Failed without confirmed partial change |
| 15 | `PARTIAL` | Change occurred but verification was incomplete |
| 16 | `PROTECTED_STATE_ERROR` | Protected state unavailable or unsafe |
| 17 | `BUSY` | Another operation owns the mutex |
| 18 | `INTERNAL_ERROR` | Bounded unexpected failure |

UAC cancellation occurs before startup and creates no helper result.

## Protected registry layout

All access uses the 64-bit registry view and fixed compiled roots:

```text
HKLM\SOFTWARE\WinCur
    Security
    Transactions\{transaction UUID}
    Rollback\{rollback UUID}
    RollbackIndex\{rollback UUID}
```

### ACLs

Private keys (`Security` and `Rollback`):

```text
Owner: BUILTIN\Administrators
SYSTEM: Full Control
BUILTIN\Administrators: Full Control
Ordinary users: no access
Inheritance: disabled
```

Read-only container and public keys (`WinCur`, `Transactions`, and
`RollbackIndex`):

```text
Owner: BUILTIN\Administrators
SYSTEM: Full Control
BUILTIN\Administrators: Full Control
BUILTIN\Users: Read, Query, and Enumerate only
Inheritance: disabled
```

The helper validates owner and effective DACL before use. An unexpected writer,
owner, object type, or unreadable security descriptor blocks the operation.
Version 1 does not silently repair ambiguous ACLs.

The root grants ordinary users only the access needed to open and enumerate the
public result/index containers. `Security`, `Rollback`, and every capsule use a
protected child DACL that removes ordinary-user access. Capsule UUIDs are not
authorization secrets.

### Security values

```text
SchemaVersion          REG_DWORD  1
MinimumProtocolVersion REG_DWORD  1
MinimumHelperVersion   REG_SZ     canonical dotted numeric version
```

The helper refuses when its embedded version is lower than the protected
minimum. A reviewed newer helper may raise but never lower the minimum.

## Transaction result schema

Each transaction is a direct UUID child of `Transactions`. Existing children
are rejected. Required values are:

### Reservation metadata

The helper exclusively creates `Transactions\{UUID}` and writes these bounded
values before doing anything action-specific:

```text
ReservationSchemaVersion   REG_DWORD  1
ReservationProtocolVersion REG_DWORD  1
ReservationTransactionId   REG_SZ     canonical UUID
ReservationOperation       REG_SZ     preview | apply | rollback
ReservationActionId        REG_SZ     required except rollback
ReservationRollbackId      REG_SZ     required only for rollback
ReservationHelperVersion   REG_SZ     embedded helper version
ReservationBuildId         REG_SZ     bounded build identifier
ReservationCreatedUtc      REG_SZ     UTC RFC 3339 timestamp
ReservationUpdatedUtc      REG_SZ     UTC RFC 3339 timestamp
Lifecycle                  REG_SZ     lifecycle enum
ReservationComplete        REG_DWORD  1; written last for reservation
```

All binding and metadata values precede `ReservationComplete`. The key is
flushed before and after that marker. A missing marker is a partial reservation;
its UUID remains permanently unavailable unless a future reviewed repair policy
can authenticate every required field. Partial or malformed reservations are
never deleted automatically and never authorize an operation.

### Completed result

After reservation, the existing result values are written into the same key:

```text
SchemaVersion       REG_DWORD  1
ProtocolVersion     REG_DWORD  1
TransactionId       REG_SZ     canonical UUID
Operation           REG_SZ     preview | apply | rollback
ActionId            REG_SZ     protocol action ID when known
Outcome             REG_SZ     stable outcome enum
MessageCode         REG_SZ     stable machine-readable code
DisplayMessage      REG_SZ     sanitized; maximum 2,048 characters
VerificationSummary REG_SZ     sanitized; maximum 4,096 characters
HelperVersion       REG_SZ     embedded helper version
BuildId             REG_SZ     bounded build identifier
TimestampUtc        REG_SZ     UTC RFC 3339 timestamp
RollbackId          REG_SZ     optional canonical UUID
Complete            REG_DWORD  1; written last
```

The Windows registry writer flushes all preceding values before writing
`Complete=1`, then flushes the completion marker before reporting persistence
success. A reader still validates the complete schema and never treats the
marker alone as success. This ordering narrows the unexpected-termination
window, but VM power-cut and host-crash fault injection remain required before
claiming durable crash recovery across the supported Windows build matrix.

Outcomes are `Succeeded`, `Cancelled`, `AlreadyCompliant`, `BlockedManaged`,
`BlockedAmbiguous`, `BlockedPrecondition`, `Failed`, `Partial`, and
`Interrupted`.

The UI ignores a result without `Complete=1`. Public results contain no raw
original values, secrets, local paths, user names, SIDs, command output, or
stack traces. An incomplete result may be marked Interrupted only after a later
helper owns the mutex and proves no prior helper remains active.

## Transaction lifecycle

Lifecycle values are:

```text
Reserved
AwaitingConfirmation
Confirmed
Executing
Verifying
Completed
Interrupted
Failed
```

Normal transitions are:

```text
Reserved -> AwaitingConfirmation | Executing | Completed | Failed
AwaitingConfirmation -> Confirmed | Completed | Failed
Confirmed -> Executing | Completed | Failed
Executing -> Verifying | Completed | Failed
Verifying -> Completed | Failed
any non-Interrupted state without Complete -> Interrupted during recovery
Completed | Interrupted | Failed with Complete -> terminal
```

Every transition re-reads and validates the immutable operation/action/UUID/
rollback binding and expected current lifecycle. `ReservationUpdatedUtc` is
written first, `Lifecycle` second, and the key is flushed. A crash may therefore
leave the prior lifecycle with a newer timestamp, which is safe because the
timestamp grants no authority. Replayed, skipped, backward, mismatched, or
terminal transitions fail closed.

For completion, bounded result fields are written first. The terminal lifecycle
is flushed next. `Complete=1` remains the final write and is flushed before the
helper reports persistence success. A terminal lifecycle without `Complete=1`
is still incomplete and cannot be interpreted as success.

### Recovery

Recovery runs only after acquiring the fixed global mutex. That proves no
cooperating helper process currently owns the operation, but it is not a crash
proof against an unrelated Administrator. Each structurally valid reservation
without a valid completed result is finalized once as `Interrupted`. Recovery:

- never displays confirmation;
- never retries inspection, confirmation, mutation, verification, or rollback;
- never converts incomplete evidence into `Succeeded`;
- preserves the exact compiled binding; and
- records that no successful outcome can be inferred.

This generic recovery is safe only while all mutation backends are disabled.
Before a backend can write a Windows setting, `Executing` and `Verifying`
recovery must reconcile protected rollback state and current configuration;
generic terminalization alone will not be sufficient.

Partial reservation metadata and malformed or untrusted records are retained
unchanged and continue to block their UUID. Valid recovered `Interrupted`
records become ordinary completed retention candidates. Only fully parsed
completed records beyond the fixed count bound may be pruned. If enumeration
exceeds the 4,096-key safety bound, the helper blocks rather than deleting data.

## Rollback capsule schema

Private capsules never store caller-provided registry paths or value names.
Fixed numbered slots map to the action's compiled targets.

Metadata:

```text
SchemaVersion REG_DWORD  1
RollbackId    REG_SZ     canonical UUID
OperationId   REG_SZ     originating transaction UUID
ActionId      REG_SZ     compiled action ID
HelperVersion REG_SZ     creator helper version
CreatedUtc    REG_SZ     UTC RFC 3339 timestamp
UpdatedUtc    REG_SZ     UTC RFC 3339 timestamp
Lifecycle     REG_SZ     lifecycle enum
TargetCount   REG_DWORD  exact compiled target count
```

Fixed subkeys:

```text
Original\Target0
Owned\Target0
OriginalKeys\Key0
OwnedKeys\Key0
```

A target slot contains only:

```text
Exists     REG_DWORD  0 | 1
ValueType  REG_DWORD  REG_DWORD | REG_SZ when present
DwordData  REG_DWORD  only for REG_DWORD
StringData REG_SZ     only for REG_SZ; bounded length
```

A key slot contains `Exists` as `0` or `1`. Count mismatch, extra or missing
slot, bad type, overlong string, or schema mismatch invalidates the capsule.

## Rollback index

The public index exposes no raw configuration:

```text
SchemaVersion REG_DWORD  1
RollbackId    REG_SZ     canonical UUID
ActionId      REG_SZ     protocol action ID
CreatedUtc    REG_SZ     timestamp
Lifecycle     REG_SZ     public lifecycle
DisplayLabel  REG_SZ     bounded label
```

The index is presentation only; the private capsule is authoritative.

## Capsule lifecycle

```text
Nonexistent -> Prepared -> Available | NoChange | Interrupted

Available -> RollbackInProgress
    -> Consumed
    -> Available      only if no write occurred and owned state is proven
    -> Partial
    -> Interrupted

Partial | Interrupted | Consumed | NoChange | Discarded -> terminal
```

### Apply ordering

1. Capture and validate original state.
2. Create a `Prepared` capsule and index.
3. Apply only fixed desired state.
4. Capture current state.
5. On full verification, record owned state and transition to `Available`.
6. If unchanged, transition to `NoChange`.
7. If mixed or uncertain, transition to `Interrupted`; rollback is unavailable.

Prepared recovery classifies exact original as `NoChange`, exact complete desired
state as `Available` after capturing owned state, and everything else as
`Interrupted`. It never guesses when or why a change occurred.

### Rollback ordering

1. Require `Available`.
2. Require current state to equal protected owned state.
3. Show exact restoration confirmation.
4. Transition to `RollbackInProgress`.
5. Restore fixed values and safe key structure.
6. Capture and verify original state.
7. Full verification transitions to `Consumed`.
8. No write plus proven owned state returns to `Available`.
9. Any write without full verification transitions to `Partial`.
10. Indeterminate completion transitions to `Interrupted`.

Partial and Interrupted capsules are not automatically retryable.

## JSONL history

- JSONL remains local display/export data.
- It may contain transaction and rollback UUIDs.
- It cannot provide original state, owned state, lifecycle, or eligibility.
- Editing, deleting, duplicating, or fabricating JSONL cannot enable rollback.
- Legacy records remain visible but are permanently ineligible for automatic
  rollback.

## Compiled actions

### Disable AutoRun

- Fixed HKLM `NoDriveTypeAutoRun` DWORD `255`.
- Fixed HKLM `NoAutorun` DWORD `1`.
- Exact value, type, absence, and key existence are preserved.
- Operation-created keys are removed only when still empty.
- Preview reads only these two values in the 64-bit HKLM view. Both missing is
  `RemediationRequired` without asserting that the machine is unmanaged. Exact
  DWORD compliance is `AlreadyCompliant`; malformed, mixed, or explicit
  conflicting policy evidence is ambiguous unless a reliable provider proves
  management authority.

### Enable PowerShell audit logging

- `EnableScriptBlockLogging` DWORD `1`.
- `EnableModuleLogging` DWORD `1`.
- `ModuleNames\*` string `*`.
- The helper never executes PowerShell.
- Preview requires exact DWORD values and the exact REG_SZ wildcard. All three
  missing is `RemediationRequired` without asserting that policy ownership is
  absent. Mixed, malformed, or conflicting policy evidence fails closed.

### Enable firewall profiles

- Uses `INetFwPolicy2` through COM.
- Enables only disabled Domain, Private, and Public profiles.
- Blocks Group Policy override, MDM management, and ambiguous ownership.
- Verifies all three profiles.
- Creates no rollback capsule.
- Preview reads effective Domain, Private, and Public enablement through
  `INetFwPolicy2`. `NET_FW_MODIFY_STATE_GP_OVERRIDE` is positive Group Policy
  evidence. `NET_FW_MODIFY_STATE_OK` is not treated as proof that changing the
  profile-enable property would be authoritative, because the documented API
  describes local rule/group modification state.

## Concurrency and retention

- One fixed global mutex serializes operations and has an explicit descriptor.
- The mutex is cooperative serialization, not durable ownership. It disappears
  on process termination and does not exclude an Administrator that bypasses
  the helper. Exclusive registry-key creation remains the replay boundary.
- Results may be pruned only by fixed age/count bounds in the helper.
- Only fully parsed completed results are retention candidates. Incomplete,
  malformed, untrusted, and currently open records are retained fail-closed.
  A mutex-owned recovery pass terminalizes only structurally valid abandoned
  reservations as Interrupted. It retains partial and malformed records.
- Available rollback capsules are never removed automatically.
- Version 1 retains consumed and terminal capsules until a separately reviewed
  cleanup policy is approved.
