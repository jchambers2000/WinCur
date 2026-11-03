#pragma once

#include "wincur/helper/protocol.hpp"
#include "wincur/helper/transaction.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace wincur::helper {

enum class EvidenceState {
    Missing,
    Present,
    Inaccessible,
    Unsupported,
    Error,
};

enum class EvidenceType {
    None,
    Dword,
    String,
    Other,
};

struct ValueEvidence final {
    EvidenceState state{EvidenceState::Error};
    EvidenceType type{EvidenceType::None};
    std::uint32_t dword_value{0};
    std::wstring string_value;
};

enum class PolicyAuthority {
    NoReliableManagedOverrideEvidence,
    Managed,
    Ambiguous,
    Inaccessible,
    Unsupported,
};

struct RegistryInspectionEvidence final {
    PolicyAuthority authority{PolicyAuthority::NoReliableManagedOverrideEvidence};
    std::array<ValueEvidence, 3> values{};
    std::size_t value_count{0};
};

enum class FirewallProfileState {
    Enabled,
    Disabled,
    Inaccessible,
    Unsupported,
    Error,
};

struct FirewallInspectionEvidence final {
    PolicyAuthority authority{PolicyAuthority::Ambiguous};
    std::array<FirewallProfileState, 3> profiles{};
};

enum class InspectionStatus {
    Compliant,
    RemediationRequired,
    Managed,
    Ambiguous,
    Inaccessible,
    Unsupported,
    Partial,
};

struct InspectionResult final {
    InspectionStatus status{InspectionStatus::Ambiguous};
    std::wstring message_code;
    std::wstring display_message;
    std::wstring verification_summary;
};

[[nodiscard]] InspectionResult EvaluateAutoRunInspection(
    const RegistryInspectionEvidence& evidence
);

[[nodiscard]] InspectionResult EvaluatePowerShellLoggingInspection(
    const RegistryInspectionEvidence& evidence
);

[[nodiscard]] InspectionResult EvaluateFirewallInspection(
    const FirewallInspectionEvidence& evidence
);

[[nodiscard]] TransactionResult MakeInspectionTransactionResult(
    const Request& request,
    const InspectionResult& inspection,
    std::wstring timestamp_utc
);

}  // namespace wincur::helper
