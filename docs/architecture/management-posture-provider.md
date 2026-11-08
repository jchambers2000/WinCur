# Native management-posture provider

- Phase: 2F-2
- Nature: read-only evidence collection
- Protocol impact: none
- Remediation authorization: none

## Purpose

The provider collects bounded evidence about Windows management posture and
fixed registry-policy attribution. It does not decide that a setting is safe
to change. `NoMatchingPolicyObserved` means only that the queried provider
returned no matching record; it is not proof that a setting is unmanaged.

The provider covers only the fixed machine targets already compiled into the
three existing WinCur actions:

1. AutoRun `NoDriveTypeAutoRun`.
2. AutoRun `NoAutorun`.
3. Windows PowerShell Script Block Logging.
4. Windows PowerShell Module Logging.
5. Windows PowerShell `ModuleNames\*`.

Firewall policy-store ownership remains separate research. Phase 2F-2 does not
change firewall inspection, capsule capture, or authorization.

## Documented Windows interfaces

| Evidence | Interface | Access |
|---|---|---|
| Domain/workgroup membership | `NetGetJoinInformation` | Read-only |
| MDM registration | `IsDeviceRegisteredWithManagement` | Read-only; no UPN requested |
| Default Local Computer GPO | Dedicated STA thread using `IGroupPolicyObject::OpenLocalMachineGPO` with both `GPO_OPEN_READ_ONLY` and `GPO_OPEN_LOAD_REGISTRY`, then `GetRegistryKey` | Read-only |
| Applied registry-policy attribution | WMI `ROOT\RSOP\Computer:RSOP_RegistryPolicySetting` through `IWbemServices::ExecQuery` | Read-only |

The helper executes no command, PowerShell script, external executable, WMI
method, CSP write, registry setter, or Group Policy save operation.

### Local GPO COM apartment

`GPEdit.dll` is apartment-threaded, and `IGroupPolicyObject::GetRegistryKey`
returns an `HKEY` that cannot be marshalled safely across COM apartments.
Disposable Windows 11 VM diagnostics confirmed that MTA activation returned
`E_NOINTERFACE`, while STA activation and read-only collection completed
successfully in both the standard-user and elevated validation sessions.
Production Local GPO collection therefore runs on a dedicated
`COINIT_APARTMENTTHREADED` thread. The `IGroupPolicyObject`, the `HKEY`, all
fixed-target queries, and their cleanup remain on that thread. Only bounded
booleans and provider diagnostics cross the thread boundary.

COM initialization failure, including `RPC_E_CHANGED_MODE`, is a provider
failure. Standard-user `E_ACCESSDENIED` from `OpenLocalMachineGPO` remains a
provider error and never becomes evidence that policy is absent. The optional
integration harness retains an MTA-versus-STA comparison for regression
diagnosis; the MTA attempt is not used for production classification.

## Evidence model

Provider health is recorded independently from its observation:

- `Healthy`
- `Unsupported`
- `AccessDenied`
- `Failed`

RSoP freshness is represented separately as `Current`, `Unknown`, or `Stale`.
The production collector deliberately reports `Unknown`: Microsoft documents
the `creationTime` property but does not define it as proof that an absent
target reflects the latest policy refresh. A positive matching RSoP record is
managed evidence and blocks future writes. An absent record with unknown
freshness remains ambiguous.

The public evidence classifications are:

- `Managed`: positive fixed-target Local GPO or RSoP evidence, or a managed
  device-level posture such as domain membership or MDM registration.
- `NoMatchingPolicyObserved`: a complete simulated/provider result with no
  fixed-target match and authoritative-current freshness. The current Windows
  RSoP collector does not claim this globally because freshness is unknown.
- `Ambiguous`: contradictory evidence, target attribution unavailable in a
  managed environment, or freshness unknown/stale.
- `Unsupported`: a required documented provider is unavailable.
- `ProviderError`: access denial, failed query, incomplete enumeration, or a
  bounded-provider error.

Domain membership and MDM registration are environment signals, not
target-specific attribution. A domain-joined or MDM-registered result therefore
does not claim that a particular policy owns a target. It does prevent a future
authorization engine from treating absence as unmanaged evidence.

## Bounds and privacy

- Exactly five compiled targets are represented by an enum and fixed arrays.
- RSoP enumeration is capped at 4,096 objects.
- Registry paths, value names, and attribution strings are bounded before use.
- No policy value data, domain/workgroup name, UPN, user name, GPO name, GPO ID,
  SOM path, or raw WMI object is returned or logged.
- Malformed attribution for a matching fixed target is a provider error.
- All WMI queries are forward-only and time-bounded per enumeration call.
- Local GPO diagnostics bind health and error values to a bounded failure
  stage; contradictory diagnostics are classified as ambiguous.

## Fail-closed limitations

1. RSoP logging can be disabled, inaccessible, stale, or incomplete. Missing
   RSoP records never prove ownership absence.
2. Only computer-scope RSoP and the default Local Computer GPO are inspected.
   User-scope policy is not inspected in this phase.
3. `IsDeviceRegisteredWithManagement(false)` proves only that the API did not
   report active MDM registration. It does not prove that no residual CSP state
   or other SYSTEM management agent exists.
4. Device-scope MDM Bridge target attribution normally requires LocalSystem.
   The portable helper remains Administrator and does not cross that boundary.
5. Domain membership does not prove that a fixed target is domain-managed, and
   workgroup membership does not prove that it is unmanaged.
6. Local Administrators and SYSTEM remain inside the architecture's trusted
   computing base and can race or replace management evidence.
7. The provider is not connected to apply, confirmation, capsule authority, or
   rollback. The mutation backend remains `NotImplemented`.

## Disposable-VM validation

The optional `ManagementPostureIntegrationTests` executable performs only the
four read-only collections. It requires an exact environment opt-in and prints
enum values and target-match booleans without identity data.

Validate at least:

1. Standalone workgroup, no Local GPO matches.
2. Local GPO AutoRun match after `gpupdate`.
3. Local GPO Windows PowerShell logging matches.
4. Standard and elevated executions.
5. RSoP logging disabled or namespace inaccessible.
6. Domain and MDM scenarios only in their respective test labs.

The validated standalone VM behavior is: MTA activation fails with
`E_NOINTERFACE`, while STA collection completes in both tested privilege
sessions. This apartment-behavior observation is not permission to authorize
remediation; access denial on other systems remains a blocking provider error.

The test must not be interpreted as remediation authorization. No integration
test should modify policy merely to exercise this provider outside a disposable
snapshot.

## Authoritative references

- [NetGetJoinInformation](https://learn.microsoft.com/en-us/windows/desktop/api/lmjoin/nf-lmjoin-netgetjoininformation)
- [IsDeviceRegisteredWithManagement](https://learn.microsoft.com/en-us/windows/win32/api/mdmregistration/nf-mdmregistration-isdeviceregisteredwithmanagement)
- [IGroupPolicyObject::OpenLocalMachineGPO](https://learn.microsoft.com/en-us/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-openlocalmachinegpo)
- [RSOP_RegistryPolicySetting](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting)
- [Developing an RSoP management tool](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/developing-an-rsop-management-tool)
- [WMI IWbemServices::ExecQuery](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery)
