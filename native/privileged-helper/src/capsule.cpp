#include "wincur/helper/capsule.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace wincur::helper {
namespace {

[[nodiscard]] std::size_t RequiredTargets(const ActionId action) noexcept {
    return action == ActionId::DisableAutoRun ? 2U : 3U;
}

[[nodiscard]] bool IsBoundedText(const std::wstring& value) noexcept {
    return !value.empty() && value.size() <= 128;
}

[[nodiscard]] bool ValidCapsule(const PreChangeCapsule& capsule) noexcept {
    if (capsule.schema_version != kCapsuleSchemaVersion ||
        capsule.protocol_version != kProtocolVersion ||
        !IsCanonicalTransactionUuid(capsule.capsule_id) ||
        !IsCanonicalTransactionUuid(capsule.transaction_id) ||
        capsule.operation != Operation::Apply ||
        capsule.target_count != RequiredTargets(capsule.action) ||
        !IsBoundedText(capsule.helper_version) ||
        !IsBoundedText(capsule.build_identity) ||
        !IsBoundedText(capsule.created_utc)) {
        return false;
    }
    const bool firewall = capsule.action == ActionId::EnableFirewallProfiles;
    if ((firewall && capsule.kind != ExactStateKind::Firewall) ||
        (!firewall && capsule.kind != ExactStateKind::Registry)) {
        return false;
    }
    if (!firewall) {
        for (std::size_t i = 0; i < capsule.target_count; ++i) {
            const auto& value = capsule.registry_values[i];
            if (!value.key_exists && value.value_exists) {
                return false;
            }
            if (!value.value_exists && (value.type != 0 || !value.data.empty())) {
                return false;
            }
            if (value.data.size() > kMaximumCapsuleValueBytes) {
                return false;
            }
        }
    }
    return true;
}

[[nodiscard]] std::wstring OperationText(Operation value) {
    return std::wstring(OperationName(value));
}
[[nodiscard]] std::wstring ActionText(ActionId value) {
    return std::wstring(ActionName(value));
}

[[nodiscard]] std::uint32_t AuthorityNumber(PolicyAuthority value) noexcept {
    return static_cast<std::uint32_t>(value);
}

[[nodiscard]] bool RegistryEqual(
    const RegistryValueState& left,
    const RegistryValueState& right
) noexcept {
    return left.key_exists == right.key_exists &&
           left.value_exists == right.value_exists && left.type == right.type &&
           left.data == right.data;
}

[[nodiscard]] bool FirewallEqual(
    const FirewallProfileSnapshot& left,
    const FirewallProfileSnapshot& right
) noexcept {
    return left.effective == right.effective && left.local == right.local;
}

[[nodiscard]] bool SameBinding(
    const PreChangeCapsule& left,
    const PreChangeCapsule& right
) noexcept {
    return left.schema_version == right.schema_version &&
           left.protocol_version == right.protocol_version &&
           left.capsule_id == right.capsule_id &&
           left.transaction_id == right.transaction_id &&
           left.operation == right.operation && left.action == right.action &&
           left.kind == right.kind && left.target_count == right.target_count;
}

[[nodiscard]] bool ReliableAuthority(PolicyAuthority authority) noexcept {
    return authority == PolicyAuthority::NoReliableManagedOverrideEvidence;
}

[[nodiscard]] std::optional<std::uint32_t> Dword(
    const std::map<std::wstring, const CapsuleValue*>& map,
    const std::wstring& name
) {
    const auto found = map.find(name);
    if (found == map.end() || found->second->type != CapsuleValueType::Dword) {
        return std::nullopt;
    }
    return found->second->dword_value;
}

[[nodiscard]] std::optional<std::wstring> String(
    const std::map<std::wstring, const CapsuleValue*>& map,
    const std::wstring& name
) {
    const auto found = map.find(name);
    if (found == map.end() || found->second->type != CapsuleValueType::String) {
        return std::nullopt;
    }
    return found->second->string_value;
}

[[nodiscard]] std::optional<ActionId> ParseAction(std::wstring_view value) {
    for (const ActionId action : {ActionId::DisableAutoRun,
                                  ActionId::EnablePowerShellLogging,
                                  ActionId::EnableFirewallProfiles}) {
        if (ActionName(action) == value) {
            return action;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool IsUnavailable(const PreChangeCapsule& state) noexcept {
    if (state.kind == ExactStateKind::Firewall) {
        for (std::size_t i = 0; i < state.target_count; ++i) {
            if (state.firewall_profiles[i].effective == ObservedState::Unavailable ||
                state.firewall_profiles[i].local == ObservedState::Unavailable ||
                state.firewall_profiles[i].local == ObservedState::NotEstablished) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

std::optional<std::vector<CapsuleValue>> SerializeCapsule(
    const PreChangeCapsule& capsule
) {
    if (!ValidCapsule(capsule)) {
        return std::nullopt;
    }
    std::vector<CapsuleValue> values;
    values.reserve(14 + capsule.target_count * 4);
    auto dword = [&values](std::wstring name, std::uint32_t value) {
        values.push_back({std::move(name), CapsuleValueType::Dword, value, {}, {}});
    };
    auto string = [&values](std::wstring name, std::wstring value) {
        CapsuleValue item{};
        item.name = std::move(name);
        item.type = CapsuleValueType::String;
        item.string_value = std::move(value);
        values.push_back(std::move(item));
    };
    dword(L"CapsuleSchemaVersion", capsule.schema_version);
    dword(L"ProtocolVersion", capsule.protocol_version);
    string(L"CapsuleId", capsule.capsule_id);
    string(L"TransactionId", capsule.transaction_id);
    string(L"Operation", OperationText(capsule.operation));
    string(L"Action", ActionText(capsule.action));
    string(L"HelperVersion", capsule.helper_version);
    string(L"BuildIdentity", capsule.build_identity);
    string(L"CreatedUtc", capsule.created_utc);
    dword(L"Authority", AuthorityNumber(capsule.authority));
    dword(L"StateKind", static_cast<std::uint32_t>(capsule.kind));
    dword(L"TargetCount", static_cast<std::uint32_t>(capsule.target_count));
    for (std::size_t i = 0; i < capsule.target_count; ++i) {
        const std::wstring prefix = L"Target" + std::to_wstring(i);
        if (capsule.kind == ExactStateKind::Registry) {
            const auto& target = capsule.registry_values[i];
            dword(prefix + L"KeyExists", target.key_exists ? 1U : 0U);
            dword(prefix + L"ValueExists", target.value_exists ? 1U : 0U);
            dword(prefix + L"ValueType", target.type);
            CapsuleValue data{};
            data.name = prefix + L"Data";
            data.type = CapsuleValueType::Binary;
            data.binary_value = target.data;
            values.push_back(std::move(data));
        } else {
            dword(prefix + L"Effective", static_cast<std::uint32_t>(
                capsule.firewall_profiles[i].effective));
            dword(prefix + L"Local", static_cast<std::uint32_t>(
                capsule.firewall_profiles[i].local));
        }
    }
    return values;
}

CapsuleParseResult ParseCapsule(
    std::span<const CapsuleValue> values,
    std::wstring_view expected_capsule_id,
    std::wstring_view expected_transaction_id,
    Operation expected_operation,
    ActionId expected_action
) {
    std::map<std::wstring, const CapsuleValue*> map;
    for (const auto& value : values) {
        if (value.name.empty() || !map.emplace(value.name, &value).second) {
            return {CapsuleParseStatus::Malformed, std::nullopt};
        }
    }
    const auto complete = Dword(map, L"CapsuleComplete");
    if (!complete.has_value()) {
        return {CapsuleParseStatus::Incomplete, std::nullopt};
    }
    if (*complete != 1) {
        return {CapsuleParseStatus::Malformed, std::nullopt};
    }
    const auto schema = Dword(map, L"CapsuleSchemaVersion");
    const auto protocol = Dword(map, L"ProtocolVersion");
    const auto capsule_id = String(map, L"CapsuleId");
    const auto transaction_id = String(map, L"TransactionId");
    const auto operation = String(map, L"Operation");
    const auto action_text = String(map, L"Action");
    const auto helper = String(map, L"HelperVersion");
    const auto build = String(map, L"BuildIdentity");
    const auto created = String(map, L"CreatedUtc");
    const auto authority = Dword(map, L"Authority");
    const auto kind = Dword(map, L"StateKind");
    const auto count = Dword(map, L"TargetCount");
    if (!schema || !protocol || !capsule_id || !transaction_id || !operation ||
        !action_text || !helper || !build || !created || !authority || !kind ||
        !count) {
        return {CapsuleParseStatus::Malformed, std::nullopt};
    }
    if (*schema != kCapsuleSchemaVersion || *protocol != kProtocolVersion) {
        return {CapsuleParseStatus::Malformed, std::nullopt};
    }
    const auto action = ParseAction(*action_text);
    if (!action || *capsule_id != expected_capsule_id ||
        *transaction_id != expected_transaction_id || *operation != L"apply" ||
        expected_operation != Operation::Apply || *action != expected_action ||
        *helper != kHelperVersion || *build != kCapsuleBuildIdentity) {
        return {CapsuleParseStatus::BindingMismatch, std::nullopt};
    }
    if (*authority > static_cast<std::uint32_t>(PolicyAuthority::Unsupported) ||
        *kind > static_cast<std::uint32_t>(ExactStateKind::Firewall) ||
        *count != RequiredTargets(*action)) {
        return {CapsuleParseStatus::Malformed, std::nullopt};
    }
    PreChangeCapsule capsule{};
    capsule.schema_version = *schema;
    capsule.protocol_version = *protocol;
    capsule.capsule_id = *capsule_id;
    capsule.transaction_id = *transaction_id;
    capsule.operation = Operation::Apply;
    capsule.action = *action;
    capsule.helper_version = *helper;
    capsule.build_identity = *build;
    capsule.created_utc = *created;
    capsule.authority = static_cast<PolicyAuthority>(*authority);
    capsule.kind = static_cast<ExactStateKind>(*kind);
    capsule.target_count = *count;
    std::set<std::wstring> expected{
        L"CapsuleSchemaVersion", L"ProtocolVersion", L"CapsuleId",
        L"TransactionId", L"Operation", L"Action", L"HelperVersion",
        L"BuildIdentity", L"CreatedUtc", L"Authority", L"StateKind",
        L"TargetCount", L"CapsuleComplete"};
    for (std::size_t i = 0; i < capsule.target_count; ++i) {
        const std::wstring prefix = L"Target" + std::to_wstring(i);
        if (capsule.kind == ExactStateKind::Registry) {
            const auto key = Dword(map, prefix + L"KeyExists");
            const auto exists = Dword(map, prefix + L"ValueExists");
            const auto type = Dword(map, prefix + L"ValueType");
            const auto data = map.find(prefix + L"Data");
            if (!key || !exists || !type || *key > 1 || *exists > 1 ||
                data == map.end() || data->second->type != CapsuleValueType::Binary ||
                data->second->binary_value.size() > kMaximumCapsuleValueBytes) {
                return {CapsuleParseStatus::Malformed, std::nullopt};
            }
            capsule.registry_values[i] = {
                *key == 1, *exists == 1, *type, data->second->binary_value};
            expected.insert(prefix + L"KeyExists");
            expected.insert(prefix + L"ValueExists");
            expected.insert(prefix + L"ValueType");
            expected.insert(prefix + L"Data");
        } else {
            const auto effective = Dword(map, prefix + L"Effective");
            const auto local = Dword(map, prefix + L"Local");
            if (!effective || !local ||
                *effective > static_cast<std::uint32_t>(ObservedState::NotEstablished) ||
                *local > static_cast<std::uint32_t>(ObservedState::NotEstablished)) {
                return {CapsuleParseStatus::Malformed, std::nullopt};
            }
            capsule.firewall_profiles[i] = {
                static_cast<ObservedState>(*effective),
                static_cast<ObservedState>(*local)};
            expected.insert(prefix + L"Effective");
            expected.insert(prefix + L"Local");
        }
    }
    if (map.size() != expected.size() || !ValidCapsule(capsule)) {
        return {CapsuleParseStatus::Malformed, std::nullopt};
    }
    return {CapsuleParseStatus::Success, std::move(capsule)};
}

CapsulePersistStatus PersistCapsule(
    CapsuleStorage& storage,
    const PreChangeCapsule& capsule
) {
    const auto serialized = SerializeCapsule(capsule);
    if (!serialized) {
        return CapsulePersistStatus::InvalidRecord;
    }
    switch (storage.Begin(capsule.capsule_id)) {
        case CapsuleCreateStatus::Created: break;
        case CapsuleCreateStatus::Duplicate: return CapsulePersistStatus::Duplicate;
        case CapsuleCreateStatus::Exhausted: return CapsulePersistStatus::Exhausted;
        case CapsuleCreateStatus::Untrusted: return CapsulePersistStatus::Untrusted;
        case CapsuleCreateStatus::AccessDenied:
            return CapsulePersistStatus::AccessDenied;
        case CapsuleCreateStatus::Error: return CapsulePersistStatus::Error;
    }
    for (const auto& value : *serialized) {
        if (!storage.Write(value)) {
            return CapsulePersistStatus::PartialWrite;
        }
    }
    if (!storage.Flush()) {
        return CapsulePersistStatus::PartialWrite;
    }
    CapsuleValue complete{L"CapsuleComplete", CapsuleValueType::Dword, 1, {}, {}};
    if (!storage.Write(complete) || !storage.Flush()) {
        return CapsulePersistStatus::PartialWrite;
    }
    return CapsulePersistStatus::Success;
}

ReconciliationClassification ReconcileState(
    const PreChangeCapsule& original,
    const PreChangeCapsule& current,
    const PreChangeCapsule& intended
) noexcept {
    if (!ValidCapsule(original) || !ValidCapsule(current) ||
        !ValidCapsule(intended) || !SameBinding(original, current) ||
        !SameBinding(original, intended)) {
        return ReconciliationClassification::Indeterminate;
    }
    if (!ReliableAuthority(current.authority)) {
        return current.authority == PolicyAuthority::Managed ||
                       current.authority == PolicyAuthority::Ambiguous
                   ? ReconciliationClassification::ManagedOrPolicyControlled
                   : ReconciliationClassification::Indeterminate;
    }
    if (IsUnavailable(current)) {
        return ReconciliationClassification::Indeterminate;
    }
    std::size_t originals = 0;
    std::size_t intendeds = 0;
    std::size_t others = 0;
    for (std::size_t i = 0; i < original.target_count; ++i) {
        bool is_original = false;
        bool is_intended = false;
        if (original.kind == ExactStateKind::Registry) {
            is_original = RegistryEqual(current.registry_values[i],
                                        original.registry_values[i]);
            is_intended = RegistryEqual(current.registry_values[i],
                                        intended.registry_values[i]);
        } else {
            is_original = FirewallEqual(current.firewall_profiles[i],
                                        original.firewall_profiles[i]);
            is_intended = FirewallEqual(current.firewall_profiles[i],
                                        intended.firewall_profiles[i]);
        }
        if (is_original) ++originals;
        else if (is_intended) ++intendeds;
        else ++others;
    }
    if (originals == original.target_count) {
        return ReconciliationClassification::Unchanged;
    }
    if (intendeds == original.target_count) {
        return ReconciliationClassification::IntendedStateObserved;
    }
    if (others == 0 && originals > 0 && intendeds > 0) {
        return ReconciliationClassification::PartiallyChanged;
    }
    return ReconciliationClassification::ExternallyModified;
}

RecoveryAssessment AssessRecovery(
    MutationBoundary boundary,
    const PreChangeCapsule& original,
    const PreChangeCapsule& current,
    const PreChangeCapsule& intended
) noexcept {
    return {boundary, ReconcileState(original, current, intended), false, false};
}

std::optional<PreChangeCapsule> MakeIntendedPostChange(
    const PreChangeCapsule& pre_change
) {
    if (!ValidCapsule(pre_change)) {
        return std::nullopt;
    }
    PreChangeCapsule intended = pre_change;
    if (intended.kind == ExactStateKind::Registry) {
        auto dword = [](std::uint32_t value) {
            RegistryValueState result{true, true, REG_DWORD, {}};
            result.data.resize(sizeof(value));
            std::memcpy(result.data.data(), &value, sizeof(value));
            return result;
        };
        if (intended.action == ActionId::DisableAutoRun) {
            intended.registry_values[0] = dword(255);
            intended.registry_values[1] = dword(1);
        } else if (intended.action == ActionId::EnablePowerShellLogging) {
            intended.registry_values[0] = dword(1);
            intended.registry_values[1] = dword(1);
            const std::wstring star = L"*";
            RegistryValueState all{true, true, REG_SZ, {}};
            all.data.resize((star.size() + 1) * sizeof(wchar_t));
            std::memcpy(all.data.data(), star.c_str(), all.data.size());
            intended.registry_values[2] = std::move(all);
        }
    } else {
        for (auto& profile : intended.firewall_profiles) {
            profile.effective = ObservedState::Enabled;
            profile.local = ObservedState::Enabled;
        }
    }
    return intended;
}

}  // namespace wincur::helper
