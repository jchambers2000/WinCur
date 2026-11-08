# Read-only remediation eligibility engine

- Phase: 2F-3
- Nature: deterministic advisory evaluation
- Protocol impact: none
- Mutation authorization: none

## Purpose and trust boundary

The eligibility engine combines an existing fixed-action inspection status,
fixed-target management-posture evidence, an explicit local-ownership evidence
grade, and rollback-evidence quality. It performs no Windows API call and has
no filesystem, registry, firewall, process, confirmation, transaction, capsule,
or rollback side effect.

`EligibleForLocalRemediationCandidate` is an advisory classification only. It
is not a confirmation receipt, capsule authorization, transaction transition,
or permission to write. Every result explicitly carries `advisory_only=true`
and `authorizes_mutation=false`. No production mutation or authorization path
calls this evaluator in Phase 2F-3.

## Fixed inputs

Only the three compiled `ActionId` values are accepted: Disable AutoRun, enable
PowerShell logging, and enable Windows Firewall profiles. The engine accepts no
registry path, value name, WMI query, command, policy name, or other
caller-selected target. Registry actions use only the five ordered
`FixedPolicyTarget` entries from the management-posture provider.

The additional evidence grades are strongly typed:

- Local ownership: `NotEstablished` or
  `VerifiedLocalBySupportedProvider`.
- Rollback evidence: `ExactPreChangeState`, `Insufficient`, `Unsupported`, or
  `Malformed`.

The current Windows providers do not produce
`VerifiedLocalBySupportedProvider`. Workgroup membership, MDM-unregistered
status, missing Local GPO entries, and absent RSoP records never create that
grade.

## Classifications

- `EligibleForLocalRemediationCandidate`: synthetic evidence contains a valid
  remediation-required AutoRun inspection, current non-matching management
  evidence, a separate positive local-ownership attestation, and exact rollback
  evidence. It still authorizes nothing.
- `AlreadyCompliant`: the fixed-target inspection observed the required
  configuration. This says nothing about ownership and is never a write
  candidate.
- `ManagedByPolicy`: inspection or positive target attribution reports managed
  policy.
- `AmbiguousOwnership`: evidence is inaccessible, partial, contradictory,
  stale, malformed, provider-failed, or lacks positive local ownership.
- `UnsupportedConfiguration`: a required inspection or management provider, or
  rollback representation, is unsupported.
- `InsufficientRollbackEvidence`: ownership may otherwise be synthetically
  adequate, but exact restoration evidence is absent or the action's current
  rollback/effective-state model is unresolved.

## Deterministic precedence

1. Reject unknown enum values and malformed input as `AmbiguousOwnership`.
2. A valid `Compliant` inspection returns `AlreadyCompliant`. Management
   context is not converted into an ownership claim because no write is needed.
3. Inspection-level managed evidence returns `ManagedByPolicy`.
4. Unsupported inspection returns `UnsupportedConfiguration`.
5. Ambiguous, inaccessible, or partial inspection returns
   `AmbiguousOwnership`.
6. For AutoRun and PowerShell, validate the complete bounded management result,
   fixed target order, provider health, diagnostics, and RSoP freshness.
7. A positive fixed-target policy match takes precedence and returns
   `ManagedByPolicy`.
8. Provider failures and ambiguous target evidence return
   `AmbiguousOwnership`; unsupported evidence returns
   `UnsupportedConfiguration`.
9. PowerShell logging and Firewall return `InsufficientRollbackEvidence` for a
   remediation-required observation because effective-state attribution,
   ownership, or exact rollback evidence remains unresolved.
10. AutoRun requires a separate positive local-ownership attestation. Merely
    observing no matching policy remains `AmbiguousOwnership`.
11. AutoRun then requires exact pre-change rollback evidence. Missing or
    malformed evidence returns `InsufficientRollbackEvidence`; unsupported
    representation returns `UnsupportedConfiguration`.
12. Only the remaining synthetic combination is a candidate, and it remains
    non-authorizing.

## Current real-world outcome

No current real-world evidence path can safely produce
`EligibleForLocalRemediationCandidate`:

- Production RSoP freshness is intentionally `Unknown`, so absence cannot be
  treated as current proof.
- The management-posture provider does not positively attest local ownership.
- PowerShell logging effective-state/ownership and all-modules rollback
  authority remain unresolved.
- Firewall effective/local profile ownership and exact rollback-grade state
  remain unresolved.

These requirements are not weakened to manufacture an eligible result.

## Testing and future validation

Unit tests use only synthetic bounded evidence and cover every classification,
precedence conflicts, provider failures, partial inspection, unsupported and
malformed evidence, unknown RSoP freshness, missing ownership, and rollback
quality. They also assert that every result remains advisory and non-authorizing.

A disposable VM can compare advisory results against independently captured
read-only evidence, but Phase 2F-3 does not require an elevated integration
binary because the evaluator itself invokes no Windows API. Any future adapter
must be tested separately and must not map policy absence to verified local
ownership.
