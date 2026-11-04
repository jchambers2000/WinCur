#pragma once

#include "wincur/helper/protocol.hpp"
#include "wincur/helper/inspection.hpp"
#include "wincur/helper/transaction.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wincur::helper {

inline constexpr std::uint32_t kCapsuleSchemaVersion = 1;
inline constexpr std::size_t kMaximumCapsules = 256;
inline constexpr std::size_t kMaximumCapsuleValueBytes = 4096;
inline constexpr std::wstring_view kCapsuleBuildIdentity = kHelperBuildId;

enum class ExactStateKind { Registry, Firewall };
enum class ObservedState { Enabled, Disabled, Unavailable, NotEstablished };

struct RegistryValueState final {
    bool key_exists{false};
    bool value_exists{false};
    std::uint32_t type{0};
    std::vector<std::uint8_t> data;
};

struct FirewallProfileSnapshot final {
    ObservedState effective{ObservedState::Unavailable};
    ObservedState local{ObservedState::NotEstablished};
};

struct PreChangeCapsule final {
    std::uint32_t schema_version{kCapsuleSchemaVersion};
    std::uint32_t protocol_version{kProtocolVersion};
    std::wstring capsule_id;
    std::wstring transaction_id;
    Operation operation{Operation::Apply};
    ActionId action{ActionId::DisableAutoRun};
    std::wstring helper_version;
    std::wstring build_identity;
    std::wstring created_utc;
    PolicyAuthority authority{PolicyAuthority::Ambiguous};
    ExactStateKind kind{ExactStateKind::Registry};
    std::array<RegistryValueState, 3> registry_values{};
    std::array<FirewallProfileSnapshot, 3> firewall_profiles{};
    std::size_t target_count{0};
};

enum class CapsuleValueType { Dword, String, Binary };
struct CapsuleValue final {
    std::wstring name;
    CapsuleValueType type{CapsuleValueType::String};
    std::uint32_t dword_value{0};
    std::wstring string_value;
    std::vector<std::uint8_t> binary_value;
};

enum class CapsuleCreateStatus {
    Created,
    Duplicate,
    Exhausted,
    Untrusted,
    AccessDenied,
    Error,
};

class CapsuleStorage {
public:
    CapsuleStorage() = default;
    CapsuleStorage(const CapsuleStorage&) = delete;
    CapsuleStorage& operator=(const CapsuleStorage&) = delete;
    virtual ~CapsuleStorage() = default;
    [[nodiscard]] virtual CapsuleCreateStatus Begin(
        std::wstring_view capsule_id
    ) noexcept = 0;
    [[nodiscard]] virtual bool Write(const CapsuleValue& value) noexcept = 0;
    [[nodiscard]] virtual bool Flush() noexcept = 0;
    [[nodiscard]] virtual bool Read(std::vector<CapsuleValue>& values) noexcept = 0;
};

enum class CapsulePersistStatus {
    Success,
    Duplicate,
    Exhausted,
    Untrusted,
    AccessDenied,
    InvalidRecord,
    PartialWrite,
    Error,
};
enum class CapsuleParseStatus { Success, Incomplete, Malformed, BindingMismatch };
struct CapsuleParseResult final {
    CapsuleParseStatus status{CapsuleParseStatus::Malformed};
    std::optional<PreChangeCapsule> capsule;
};

[[nodiscard]] std::optional<std::vector<CapsuleValue>> SerializeCapsule(
    const PreChangeCapsule& capsule
);
[[nodiscard]] CapsuleParseResult ParseCapsule(
    std::span<const CapsuleValue> values,
    std::wstring_view expected_capsule_id,
    std::wstring_view expected_transaction_id,
    Operation expected_operation,
    ActionId expected_action
);
[[nodiscard]] CapsulePersistStatus PersistCapsule(
    CapsuleStorage& storage,
    const PreChangeCapsule& capsule
);

enum class ReconciliationClassification {
    Unchanged,
    IntendedStateObserved,
    PartiallyChanged,
    ExternallyModified,
    Indeterminate,
    ManagedOrPolicyControlled,
};

[[nodiscard]] ReconciliationClassification ReconcileState(
    const PreChangeCapsule& protected_pre_change,
    const PreChangeCapsule& current_observation,
    const PreChangeCapsule& intended_post_change
) noexcept;

enum class MutationBoundary {
    MutationNotStarted,
    MutationMayHaveStarted,
    MutationCompletedNotVerified,
    VerifiedCompletion,
    InterruptedOrIndeterminate,
};

struct RecoveryAssessment final {
    MutationBoundary boundary{MutationBoundary::InterruptedOrIndeterminate};
    ReconciliationClassification reconciliation{
        ReconciliationClassification::Indeterminate
    };
    bool may_retry{false};
    bool may_automatically_rollback{false};
};

[[nodiscard]] RecoveryAssessment AssessRecovery(
    MutationBoundary boundary,
    const PreChangeCapsule& protected_pre_change,
    const PreChangeCapsule& current_observation,
    const PreChangeCapsule& intended_post_change
) noexcept;

[[nodiscard]] std::optional<PreChangeCapsule> MakeIntendedPostChange(
    const PreChangeCapsule& pre_change
);

}  // namespace wincur::helper
