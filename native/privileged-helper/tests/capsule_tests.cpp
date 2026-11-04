#include "wincur/helper/capsule.hpp"
#include "wincur/helper/stub_backend.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {
using namespace wincur::helper;

constexpr wchar_t kId[] = L"01234567-89ab-4cde-8f01-23456789abcd";

class MemoryStorage final : public CapsuleStorage {
public:
    CapsuleCreateStatus begin{CapsuleCreateStatus::Created};
    std::size_t fail_after{1000};
    std::size_t writes{0};
    int flushes{0};
    std::vector<CapsuleValue> values;
    CapsuleCreateStatus Begin(std::wstring_view) noexcept override { return begin; }
    bool Write(const CapsuleValue& value) noexcept override {
        if (writes++ >= fail_after) return false;
        values.push_back(value);
        return true;
    }
    bool Flush() noexcept override { ++flushes; return true; }
    bool Read(std::vector<CapsuleValue>& output) noexcept override {
        output = values; return true;
    }
};

RegistryValueState Dword(std::uint32_t value) {
    RegistryValueState state{true, true, REG_DWORD, {}};
    state.data.resize(sizeof(value));
    std::memcpy(state.data.data(), &value, sizeof(value));
    return state;
}

PreChangeCapsule AutoRun() {
    PreChangeCapsule capsule{};
    capsule.capsule_id = kId;
    capsule.transaction_id = kId;
    capsule.action = ActionId::DisableAutoRun;
    capsule.helper_version = L"1.0.0";
    capsule.build_identity = std::wstring(kCapsuleBuildIdentity);
    capsule.created_utc = L"2026-11-03T12:00:00Z";
    capsule.authority = PolicyAuthority::NoReliableManagedOverrideEvidence;
    capsule.target_count = 2;
    capsule.registry_values[0] = {true, false, 0, {}};
    capsule.registry_values[1] = {false, false, 0, {}};
    return capsule;
}

PreChangeCapsule Firewall() {
    PreChangeCapsule capsule = AutoRun();
    capsule.action = ActionId::EnableFirewallProfiles;
    capsule.kind = ExactStateKind::Firewall;
    capsule.target_count = 3;
    for (auto& profile : capsule.firewall_profiles) {
        profile = {ObservedState::Disabled, ObservedState::Disabled};
    }
    return capsule;
}

PreChangeCapsule PowerShell() {
    PreChangeCapsule capsule = AutoRun();
    capsule.action = ActionId::EnablePowerShellLogging;
    capsule.target_count = 3;
    capsule.registry_values[0] = {true, false, 0, {}};
    capsule.registry_values[1] = {false, false, 0, {}};
    capsule.registry_values[2] = {true, true, REG_EXPAND_SZ, {37, 0, 0, 0}};
    return capsule;
}

bool Check(bool condition, const char* message) {
    if (!condition) std::cerr << "FAILED: " << message << '\n';
    return condition;
}

}  // namespace

int wmain() {
    bool ok = true;
    const PreChangeCapsule original = AutoRun();
    Request request{};
    request.operation = Operation::Apply;
    request.transaction_id = kId;
    request.action = ActionId::DisableAutoRun;
    ok &= Check(ExecuteStub(request) == BackendOutcome::NotImplemented,
                "apply backend remains explicitly non-mutating");
    ok &= Check(CapsuleMatchesRequest(original, request, kId),
                "capsule binds to exact apply transaction and action");
    auto substituted_request = request;
    substituted_request.transaction_id =
        L"11234567-89ab-4cde-8f01-23456789abcd";
    ok &= Check(!CapsuleMatchesRequest(original, substituted_request, kId),
                "cross-transaction capsule substitution is rejected");
    substituted_request = request;
    substituted_request.action = ActionId::EnablePowerShellLogging;
    ok &= Check(!CapsuleMatchesRequest(original, substituted_request, kId),
                "cross-action capsule substitution is rejected");
    auto serialized = SerializeCapsule(original);
    ok &= Check(serialized.has_value(), "serialize exact absent state");
    serialized->push_back({L"CapsuleComplete", CapsuleValueType::Dword, 1, {}, {}});
    auto parsed = ParseCapsule(*serialized, kId, kId, Operation::Apply,
                               ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::Success,
                "parse completed capsule");
    ok &= Check(!parsed.capsule->registry_values[0].value_exists &&
                parsed.capsule->registry_values[0].key_exists &&
                !parsed.capsule->registry_values[1].key_exists,
                "preserve key and value absence separately");

    PreChangeCapsule exotic = original;
    exotic.registry_values[0] = {true, true, REG_MULTI_SZ, {1, 2, 0, 0}};
    auto exotic_values = SerializeCapsule(exotic);
    exotic_values->push_back({L"CapsuleComplete", CapsuleValueType::Dword, 1, {}, {}});
    parsed = ParseCapsule(*exotic_values, kId, kId, Operation::Apply,
                          ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::Success &&
                parsed.capsule->registry_values[0].type == REG_MULTI_SZ &&
                parsed.capsule->registry_values[0].data ==
                    std::vector<std::uint8_t>({1, 2, 0, 0}),
                "preserve registry type and bytes exactly");

    const PreChangeCapsule powershell = PowerShell();
    auto powershell_values = SerializeCapsule(powershell);
    ok &= Check(powershell_values.has_value(),
                "serialize all three PowerShell policy targets");
    powershell_values->push_back(
        {L"CapsuleComplete", CapsuleValueType::Dword, 1, {}, {}});
    parsed = ParseCapsule(*powershell_values, kId, kId, Operation::Apply,
                          ActionId::EnablePowerShellLogging);
    ok &= Check(parsed.status == CapsuleParseStatus::Success &&
                    parsed.capsule->target_count == 3 &&
                    parsed.capsule->registry_values[2].type == REG_EXPAND_SZ,
                "preserve PowerShell absence and malformed/original types");
    const auto powershell_intended = MakeIntendedPostChange(powershell);
    ok &= Check(powershell_intended.has_value() &&
                    powershell_intended->registry_values[0].type == REG_DWORD &&
                    powershell_intended->registry_values[1].type == REG_DWORD &&
                    powershell_intended->registry_values[2].type == REG_SZ,
                "compiled PowerShell intended state includes all-modules rule");

    parsed = ParseCapsule(*serialized,
        L"11234567-89ab-4cde-8f01-23456789abcd", kId,
        Operation::Apply, ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::BindingMismatch,
                "reject capsule binding mismatch");
    auto wrong_build = *serialized;
    for (auto& value : wrong_build) {
        if (value.name == L"BuildIdentity") value.string_value = L"other-build";
    }
    parsed = ParseCapsule(wrong_build, kId, kId, Operation::Apply,
                          ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::BindingMismatch,
                "reject helper build identity mismatch");
    auto incomplete = *serialized;
    incomplete.pop_back();
    parsed = ParseCapsule(incomplete, kId, kId, Operation::Apply,
                          ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::Incomplete,
                "completion-last rejects interrupted capsule");
    auto corrupt = *serialized;
    corrupt.push_back(corrupt.front());
    parsed = ParseCapsule(corrupt, kId, kId, Operation::Apply,
                          ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::Malformed,
                "reject duplicate/corrupt values");
    auto unsupported = *serialized;
    for (auto& value : unsupported) {
        if (value.name == L"CapsuleSchemaVersion") value.dword_value = 99;
    }
    parsed = ParseCapsule(unsupported, kId, kId, Operation::Apply,
                          ActionId::DisableAutoRun);
    ok &= Check(parsed.status == CapsuleParseStatus::Malformed,
                "reject unsupported capsule version");

    MemoryStorage storage;
    ok &= Check(PersistCapsule(storage, original) == CapsulePersistStatus::Success &&
                storage.flushes == 2 &&
                storage.values.back().name == L"CapsuleComplete",
                "persist completion marker last with durability boundaries");
    MemoryStorage duplicate_storage;
    duplicate_storage.begin = CapsuleCreateStatus::Duplicate;
    ok &= Check(PersistCapsule(duplicate_storage, original) == CapsulePersistStatus::Duplicate,
                "reject duplicate/replayed capsule");
    MemoryStorage exhausted_storage;
    exhausted_storage.begin = CapsuleCreateStatus::Exhausted;
    ok &= Check(PersistCapsule(exhausted_storage, original) == CapsulePersistStatus::Exhausted,
                "bounded storage fails closed without pruning");
    MemoryStorage partial_storage;
    partial_storage.fail_after = 3;
    ok &= Check(PersistCapsule(partial_storage, original) == CapsulePersistStatus::PartialWrite,
                "partial write never completes");

    auto intended = MakeIntendedPostChange(original);
    ok &= Check(intended.has_value(), "construct compiled intended state");
    ok &= Check(ReconcileState(original, original, *intended) ==
                    ReconciliationClassification::Unchanged,
                "reconcile unchanged");
    ok &= Check(ReconcileState(original, *intended, *intended) ==
                    ReconciliationClassification::IntendedStateObserved,
                "reconcile intended state");
    PreChangeCapsule partial = original;
    partial.registry_values[0] = intended->registry_values[0];
    ok &= Check(ReconcileState(original, partial, *intended) ==
                    ReconciliationClassification::PartiallyChanged,
                "reconcile partial state");
    ok &= Check(EvaluateCapsuleAuthorization(original) ==
                    CapsuleAuthorizationStatus::Eligible,
                "unambiguously local rollback-grade capsule is eligible");
    ok &= Check(CompareCapturedState(original, original) ==
                    CapsuleAuthorizationStatus::Eligible,
                "unchanged post-confirmation evidence remains eligible");
    ok &= Check(CompareCapturedState(original, partial) ==
                    CapsuleAuthorizationStatus::Changed,
                "changed configuration after confirmation fails closed");
    PreChangeCapsule external = original;
    external.registry_values[0] = Dword(7);
    ok &= Check(ReconcileState(original, external, *intended) ==
                    ReconciliationClassification::ExternallyModified,
                "reconcile unexpected external state");
    external.authority = PolicyAuthority::Managed;
    ok &= Check(ReconcileState(original, external, *intended) ==
                    ReconciliationClassification::ManagedOrPolicyControlled,
                "managed evidence fails closed");
    ok &= Check(CompareCapturedState(original, external) ==
                    CapsuleAuthorizationStatus::Managed,
                "changed management evidence blocks authorization");
    external.authority = PolicyAuthority::Ambiguous;
    ok &= Check(ReconcileState(original, external, *intended) ==
                    ReconciliationClassification::ManagedOrPolicyControlled,
                "ambiguous management evidence fails closed");
    external.authority = PolicyAuthority::Unsupported;
    ok &= Check(EvaluateCapsuleAuthorization(external) ==
                    CapsuleAuthorizationStatus::Unsupported,
                "unsupported policy authority fails closed");

    const auto recovery = AssessRecovery(MutationBoundary::MutationMayHaveStarted,
        original, partial, *intended);
    ok &= Check(recovery.reconciliation ==
                    ReconciliationClassification::PartiallyChanged &&
                !recovery.may_retry && !recovery.may_automatically_rollback,
                "interruption is classify-only, never retry or rollback");
    for (const auto boundary : {
             MutationBoundary::MutationNotStarted,
             MutationBoundary::MutationMayHaveStarted,
             MutationBoundary::MutationCompletedNotVerified,
             MutationBoundary::VerifiedCompletion,
             MutationBoundary::InterruptedOrIndeterminate}) {
        const auto assessed = AssessRecovery(boundary, original, original, *intended);
        ok &= Check(!assessed.may_retry && !assessed.may_automatically_rollback,
                    "every mutation boundary prohibits automatic action");
    }

    PreChangeCapsule firewall = Firewall();
    auto firewall_intended = MakeIntendedPostChange(firewall);
    ok &= Check(firewall_intended.has_value(), "construct firewall intended state");
    firewall.firewall_profiles[0].local = ObservedState::NotEstablished;
    ok &= Check(ReconcileState(Firewall(), firewall, *firewall_intended) ==
                    ReconciliationClassification::Indeterminate,
                "unknown local firewall state is indeterminate");

    std::cout << (ok ? "Capsule tests passed\n" : "Capsule tests failed\n");
    return ok ? 0 : 1;
}
