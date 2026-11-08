#pragma once

#include "wincur/helper/inspection.hpp"
#include "wincur/helper/management_posture.hpp"
#include "wincur/helper/protocol.hpp"

#include <cstdint>

namespace wincur::helper {

// Advisory classifications only. No value in this enum is an authorization
// receipt, transaction transition, confirmation, or permission to mutate.
enum class RemediationEligibilityClassification : std::uint8_t {
    EligibleForLocalRemediationCandidate,
    AlreadyCompliant,
    ManagedByPolicy,
    AmbiguousOwnership,
    UnsupportedConfiguration,
    InsufficientRollbackEvidence,
};

enum class LocalOwnershipEvidence : std::uint8_t {
    NotEstablished,
    VerifiedLocalBySupportedProvider,
};

enum class RollbackEvidenceQuality : std::uint8_t {
    ExactPreChangeState,
    Insufficient,
    Unsupported,
    Malformed,
};

enum class RemediationEligibilityReason : std::uint8_t {
    CandidateEvidenceComplete,
    ObservedAlreadyCompliant,
    InspectionManaged,
    TargetManaged,
    InspectionUnavailable,
    ManagementEvidenceAmbiguous,
    ManagementProviderFailure,
    OwnershipNotEstablished,
    InspectionUnsupported,
    ManagementUnsupported,
    ActionEvidenceUnresolved,
    RollbackEvidenceInsufficient,
    RollbackEvidenceUnsupported,
    RollbackEvidenceMalformed,
    MalformedInput,
};

struct RemediationEligibilityInput final {
    ActionId action{ActionId::DisableAutoRun};
    InspectionStatus inspection_status{InspectionStatus::Ambiguous};
    ManagementPostureResult management{};
    LocalOwnershipEvidence local_ownership{
        LocalOwnershipEvidence::NotEstablished
    };
    RollbackEvidenceQuality rollback_evidence{
        RollbackEvidenceQuality::Insufficient
    };
};

struct RemediationEligibilityResult final {
    RemediationEligibilityClassification classification{
        RemediationEligibilityClassification::AmbiguousOwnership
    };
    RemediationEligibilityReason reason{
        RemediationEligibilityReason::MalformedInput
    };
    // These constants make the trust boundary explicit at every call site.
    bool advisory_only{true};
    bool authorizes_mutation{false};
};

[[nodiscard]] RemediationEligibilityResult EvaluateRemediationEligibility(
    const RemediationEligibilityInput& input
) noexcept;

}  // namespace wincur::helper
