#include "wincur/helper/remediation_eligibility.hpp"

#include <array>
#include <cstddef>
#include <span>

namespace wincur::helper {
namespace {

static_assert(
    kFixedPolicyTargetCount == 5,
    "Eligibility target mapping must be reviewed when fixed targets change."
);

[[nodiscard]] RemediationEligibilityResult Result(
    const RemediationEligibilityClassification classification,
    const RemediationEligibilityReason reason
) noexcept {
    return {classification, reason, true, false};
}

[[nodiscard]] bool ValidAction(const ActionId action) noexcept {
    switch (action) {
        case ActionId::DisableAutoRun:
        case ActionId::EnablePowerShellLogging:
        case ActionId::EnableFirewallProfiles:
            return true;
    }
    return false;
}

[[nodiscard]] bool ValidInspectionStatus(
    const InspectionStatus status
) noexcept {
    switch (status) {
        case InspectionStatus::Compliant:
        case InspectionStatus::RemediationRequired:
        case InspectionStatus::Managed:
        case InspectionStatus::Ambiguous:
        case InspectionStatus::Inaccessible:
        case InspectionStatus::Unsupported:
        case InspectionStatus::Partial:
            return true;
    }
    return false;
}

[[nodiscard]] bool ValidOwnershipEvidence(
    const LocalOwnershipEvidence evidence
) noexcept {
    switch (evidence) {
        case LocalOwnershipEvidence::NotEstablished:
        case LocalOwnershipEvidence::VerifiedLocalBySupportedProvider:
            return true;
    }
    return false;
}

[[nodiscard]] bool ValidRollbackEvidence(
    const RollbackEvidenceQuality evidence
) noexcept {
    switch (evidence) {
        case RollbackEvidenceQuality::ExactPreChangeState:
        case RollbackEvidenceQuality::Insufficient:
        case RollbackEvidenceQuality::Unsupported:
        case RollbackEvidenceQuality::Malformed:
            return true;
    }
    return false;
}

[[nodiscard]] bool ValidManagementClassification(
    const ManagementClassification classification
) noexcept {
    switch (classification) {
        case ManagementClassification::Managed:
        case ManagementClassification::NoMatchingPolicyObserved:
        case ManagementClassification::Ambiguous:
        case ManagementClassification::Unsupported:
        case ManagementClassification::ProviderError:
            return true;
    }
    return false;
}

[[nodiscard]] bool ValidManagementShape(
    const ManagementPostureResult& management
) noexcept {
    const bool domain_value_mismatch =
        (management.domain_provider.health == ProviderHealth::Healthy) !=
        (management.domain_membership != DomainMembership::Unknown);
    const bool mdm_value_mismatch =
        (management.mdm_provider.health == ProviderHealth::Healthy) !=
        (management.mdm_registration != MdmRegistration::Unknown);
    if (!ValidManagementClassification(management.classification) ||
        domain_value_mismatch || mdm_value_mismatch ||
        !IsProviderEvidenceConsistent(management.domain_provider, false) ||
        !IsProviderEvidenceConsistent(management.mdm_provider, false) ||
        !IsProviderEvidenceConsistent(
            management.local_group_policy_provider, false) ||
        !IsProviderEvidenceConsistent(management.rsop_provider, true) ||
        !IsLocalGroupPolicyDiagnosticConsistent(
            management.local_group_policy_provider,
            management.local_group_policy_diagnostics) ||
        !management.local_group_policy_diagnostics.structurally_consistent ||
        !management.rsop_diagnostics.structurally_consistent) {
        return false;
    }

    constexpr std::array expected_targets{
        FixedPolicyTarget::AutoRunDriveTypes,
        FixedPolicyTarget::AutoRunCommands,
        FixedPolicyTarget::PowerShellScriptBlockLogging,
        FixedPolicyTarget::PowerShellModuleLogging,
        FixedPolicyTarget::PowerShellAllModules,
    };
    for (std::size_t index = 0; index < expected_targets.size(); ++index) {
        const TargetManagementEvidence& target = management.targets[index];
        if (target.target != expected_targets[index] ||
            !ValidManagementClassification(target.classification) ||
            ((target.local_group_policy_match || target.rsop_match) &&
             target.classification != ManagementClassification::Managed) ||
            (management.rsop_provider.health == ProviderHealth::Healthy &&
             management.rsop_provider.freshness !=
                 EvidenceFreshness::Current &&
             target.classification ==
                 ManagementClassification::NoMatchingPolicyObserved)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] RemediationEligibilityResult EvaluateInspection(
    const InspectionStatus status
) noexcept {
    switch (status) {
        case InspectionStatus::Compliant:
            return Result(
                RemediationEligibilityClassification::AlreadyCompliant,
                RemediationEligibilityReason::ObservedAlreadyCompliant);
        case InspectionStatus::Managed:
            return Result(
                RemediationEligibilityClassification::ManagedByPolicy,
                RemediationEligibilityReason::InspectionManaged);
        case InspectionStatus::Unsupported:
            return Result(
                RemediationEligibilityClassification::UnsupportedConfiguration,
                RemediationEligibilityReason::InspectionUnsupported);
        case InspectionStatus::Ambiguous:
        case InspectionStatus::Inaccessible:
        case InspectionStatus::Partial:
            return Result(
                RemediationEligibilityClassification::AmbiguousOwnership,
                RemediationEligibilityReason::InspectionUnavailable);
        case InspectionStatus::RemediationRequired:
            break;
    }
    return Result(
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput);
}

[[nodiscard]] RemediationEligibilityResult EvaluateTargetManagement(
    const ManagementPostureResult& management,
    const std::span<const std::size_t> target_indices
) noexcept {
    // A positive fixed-target match is authoritative blocking evidence even
    // when another provider failed during the same collection.
    for (const std::size_t index : target_indices) {
        if (management.targets[index].classification ==
            ManagementClassification::Managed) {
            return Result(
                RemediationEligibilityClassification::ManagedByPolicy,
                RemediationEligibilityReason::TargetManaged);
        }
    }

    const auto provider_failed = [](const ProviderEvidence& provider) {
        return provider.health == ProviderHealth::AccessDenied ||
               provider.health == ProviderHealth::Failed ||
               (provider.health == ProviderHealth::Healthy &&
                !provider.complete);
    };
    if (provider_failed(management.domain_provider) ||
        provider_failed(management.mdm_provider) ||
        provider_failed(management.local_group_policy_provider) ||
        provider_failed(management.rsop_provider) ||
        management.classification ==
            ManagementClassification::ProviderError) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::ManagementProviderFailure);
    }
    if (management.domain_provider.health == ProviderHealth::Unsupported ||
        management.mdm_provider.health == ProviderHealth::Unsupported ||
        management.local_group_policy_provider.health ==
            ProviderHealth::Unsupported ||
        management.rsop_provider.health == ProviderHealth::Unsupported ||
        management.classification ==
            ManagementClassification::Unsupported) {
        return Result(
            RemediationEligibilityClassification::UnsupportedConfiguration,
            RemediationEligibilityReason::ManagementUnsupported);
    }

    bool unsupported = false;
    bool provider_error = false;
    bool ambiguous = false;
    for (const std::size_t index : target_indices) {
        switch (management.targets[index].classification) {
            case ManagementClassification::Managed:
                break;
            case ManagementClassification::ProviderError:
                provider_error = true;
                break;
            case ManagementClassification::Ambiguous:
                ambiguous = true;
                break;
            case ManagementClassification::Unsupported:
                unsupported = true;
                break;
            case ManagementClassification::NoMatchingPolicyObserved:
                break;
        }
    }
    if (provider_error) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::ManagementProviderFailure);
    }
    if (ambiguous) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::ManagementEvidenceAmbiguous);
    }
    if (unsupported) {
        return Result(
            RemediationEligibilityClassification::UnsupportedConfiguration,
            RemediationEligibilityReason::ManagementUnsupported);
    }
    if (management.classification == ManagementClassification::Ambiguous ||
        management.classification == ManagementClassification::Managed) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::ManagementEvidenceAmbiguous);
    }
    return Result(
        RemediationEligibilityClassification::
            EligibleForLocalRemediationCandidate,
        RemediationEligibilityReason::CandidateEvidenceComplete);
}

[[nodiscard]] bool IsBlockingResult(
    const RemediationEligibilityResult& result
) noexcept {
    return result.classification !=
           RemediationEligibilityClassification::
               EligibleForLocalRemediationCandidate;
}

}  // namespace

RemediationEligibilityResult EvaluateRemediationEligibility(
    const RemediationEligibilityInput& input
) noexcept {
    if (!ValidAction(input.action) ||
        !ValidInspectionStatus(input.inspection_status) ||
        !ValidOwnershipEvidence(input.local_ownership) ||
        !ValidRollbackEvidence(input.rollback_evidence)) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::MalformedInput);
    }

    const RemediationEligibilityResult inspection =
        EvaluateInspection(input.inspection_status);
    if (input.inspection_status != InspectionStatus::RemediationRequired) {
        return inspection;
    }

    if (input.action == ActionId::EnableFirewallProfiles) {
        // The fixed management-posture provider has no firewall target, and
        // rollback-grade effective/local policy ownership remains unresolved.
        return Result(
            RemediationEligibilityClassification::
                InsufficientRollbackEvidence,
            RemediationEligibilityReason::ActionEvidenceUnresolved);
    }

    if (!ValidManagementShape(input.management)) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::MalformedInput);
    }

    constexpr std::array<std::size_t, 2> autorun_targets{0, 1};
    constexpr std::array<std::size_t, 3> powershell_targets{2, 3, 4};
    const RemediationEligibilityResult management =
        input.action == ActionId::DisableAutoRun
            ? EvaluateTargetManagement(input.management, autorun_targets)
            : EvaluateTargetManagement(input.management, powershell_targets);
    if (IsBlockingResult(management)) {
        return management;
    }

    if (input.action == ActionId::EnablePowerShellLogging) {
        // Effective-state attribution and exact all-module rollback authority
        // are not established by the current provider set.
        return Result(
            RemediationEligibilityClassification::
                InsufficientRollbackEvidence,
            RemediationEligibilityReason::ActionEvidenceUnresolved);
    }

    if (input.local_ownership !=
        LocalOwnershipEvidence::VerifiedLocalBySupportedProvider) {
        return Result(
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::OwnershipNotEstablished);
    }

    switch (input.rollback_evidence) {
        case RollbackEvidenceQuality::ExactPreChangeState:
            return Result(
                RemediationEligibilityClassification::
                    EligibleForLocalRemediationCandidate,
                RemediationEligibilityReason::CandidateEvidenceComplete);
        case RollbackEvidenceQuality::Unsupported:
            return Result(
                RemediationEligibilityClassification::UnsupportedConfiguration,
                RemediationEligibilityReason::RollbackEvidenceUnsupported);
        case RollbackEvidenceQuality::Insufficient:
            return Result(
                RemediationEligibilityClassification::
                    InsufficientRollbackEvidence,
                RemediationEligibilityReason::RollbackEvidenceInsufficient);
        case RollbackEvidenceQuality::Malformed:
            return Result(
                RemediationEligibilityClassification::
                    InsufficientRollbackEvidence,
                RemediationEligibilityReason::RollbackEvidenceMalformed);
    }
    return Result(
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput);
}

}  // namespace wincur::helper
