#include "wincur/helper/management_posture.hpp"

#include <algorithm>
#include <array>

namespace wincur::helper {
namespace {

[[nodiscard]] bool IsProviderFailure(const ProviderEvidence& provider) noexcept {
    return provider.health == ProviderHealth::AccessDenied ||
           provider.health == ProviderHealth::Failed ||
           (provider.health == ProviderHealth::Healthy && !provider.complete);
}

[[nodiscard]] bool IsMalformedProviderState(
    const ManagementPostureInput& input
) noexcept {
    const auto malformed_shape = [](
        const ProviderEvidence& provider,
        const bool freshness_is_applicable
    ) noexcept {
        // A healthy provider whose enumeration did not complete is an
        // existing ProviderError case, not a contradictory tuple.
        const bool incomplete_healthy =
            provider.health == ProviderHealth::Healthy &&
            !provider.complete && provider.error_code == 0 &&
            (freshness_is_applicable ||
             provider.freshness == EvidenceFreshness::NotApplicable);
        return !incomplete_healthy &&
               !IsProviderEvidenceConsistent(
                   provider, freshness_is_applicable);
    };
    const bool domain_value_mismatch =
        (input.domain_provider.health == ProviderHealth::Healthy) !=
        (input.domain_membership != DomainMembership::Unknown);
    const bool mdm_value_mismatch =
        (input.mdm_provider.health == ProviderHealth::Healthy) !=
        (input.mdm_registration != MdmRegistration::Unknown);
    const bool local_matches_without_provider =
        input.local_group_policy_provider.health != ProviderHealth::Healthy &&
        std::any_of(
            input.local_group_policy_matches.begin(),
            input.local_group_policy_matches.end(),
            [](const bool value) { return value; }
        );
    const bool rsop_matches_without_provider =
        input.rsop_provider.health != ProviderHealth::Healthy &&
        std::any_of(
            input.rsop_matches.begin(),
            input.rsop_matches.end(),
            [](const bool value) { return value; }
        );
    const bool invalid_rsop_freshness =
        (input.rsop_provider.health == ProviderHealth::Healthy &&
         input.rsop_provider.freshness == EvidenceFreshness::NotApplicable) ||
        (input.rsop_provider.health != ProviderHealth::Healthy &&
         input.rsop_provider.freshness != EvidenceFreshness::NotApplicable);
    const bool invalid_provider_shape =
        malformed_shape(input.domain_provider, false) ||
        malformed_shape(input.mdm_provider, false) ||
        malformed_shape(input.local_group_policy_provider, false) ||
        malformed_shape(input.rsop_provider, true) ||
        !IsLocalGroupPolicyDiagnosticConsistent(
            input.local_group_policy_provider,
            input.local_group_policy_diagnostics) ||
        !input.local_group_policy_diagnostics.structurally_consistent ||
        !input.rsop_diagnostics.structurally_consistent;
    return domain_value_mismatch || mdm_value_mismatch ||
           local_matches_without_provider || rsop_matches_without_provider ||
           invalid_rsop_freshness || invalid_provider_shape;
}

[[nodiscard]] bool HasProviderFailure(
    const ManagementPostureInput& input
) noexcept {
    return IsProviderFailure(input.domain_provider) ||
           IsProviderFailure(input.mdm_provider) ||
           IsProviderFailure(input.local_group_policy_provider) ||
           IsProviderFailure(input.rsop_provider);
}

[[nodiscard]] bool HasUnsupportedProvider(
    const ManagementPostureInput& input
) noexcept {
    return input.domain_provider.health == ProviderHealth::Unsupported ||
           input.mdm_provider.health == ProviderHealth::Unsupported ||
           input.local_group_policy_provider.health ==
               ProviderHealth::Unsupported ||
           input.rsop_provider.health == ProviderHealth::Unsupported;
}

[[nodiscard]] bool HasAnyTargetMatch(
    const ManagementPostureInput& input
) noexcept {
    for (std::size_t index = 0; index < kFixedPolicyTargetCount; ++index) {
        if (input.local_group_policy_matches[index] ||
            input.rsop_matches[index]) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] ManagementClassification ClassifyTarget(
    const ManagementPostureInput& input,
    const std::size_t index,
    const bool malformed
) noexcept {
    if (malformed) {
        return ManagementClassification::Ambiguous;
    }
    if (HasProviderFailure(input)) {
        return ManagementClassification::ProviderError;
    }
    if (input.local_group_policy_matches[index] || input.rsop_matches[index]) {
        return ManagementClassification::Managed;
    }
    if (HasUnsupportedProvider(input)) {
        return ManagementClassification::Unsupported;
    }
    if (input.domain_membership == DomainMembership::Domain ||
        input.mdm_registration == MdmRegistration::Registered ||
        input.rsop_provider.freshness != EvidenceFreshness::Current) {
        return ManagementClassification::Ambiguous;
    }
    return ManagementClassification::NoMatchingPolicyObserved;
}

}  // namespace

bool IsProviderEvidenceConsistent(
    const ProviderEvidence& provider,
    const bool freshness_is_applicable
) noexcept {
    if (provider.health == ProviderHealth::Healthy) {
        if (!provider.complete || provider.error_code != 0) {
            return false;
        }
        return freshness_is_applicable ||
               provider.freshness == EvidenceFreshness::NotApplicable;
    }
    if (provider.complete ||
        provider.freshness != EvidenceFreshness::NotApplicable) {
        return false;
    }
    if ((provider.health == ProviderHealth::AccessDenied ||
         provider.health == ProviderHealth::Failed) &&
        provider.error_code == 0) {
        return false;
    }
    return true;
}

bool IsLocalGroupPolicyDiagnosticConsistent(
    const ProviderEvidence& provider,
    const ProviderDiagnostics& diagnostics
) noexcept {
    if (!IsProviderEvidenceConsistent(provider, false)) {
        return false;
    }
    if (provider.health == ProviderHealth::Healthy) {
        return diagnostics.stage == ProviderFailureStage::Completed &&
               diagnostics.raw_result == 0 &&
               diagnostics.normal_termination;
    }
    return diagnostics.stage != ProviderFailureStage::None &&
           diagnostics.stage != ProviderFailureStage::Completed &&
           diagnostics.raw_result != 0 &&
           diagnostics.raw_result == provider.error_code &&
           !diagnostics.normal_termination;
}

ManagementPostureResult EvaluateManagementPosture(
    const ManagementPostureInput& input
) noexcept {
    ManagementPostureResult result{};
    result.domain_provider = input.domain_provider;
    result.domain_membership = input.domain_membership;
    result.mdm_provider = input.mdm_provider;
    result.mdm_registration = input.mdm_registration;
    result.local_group_policy_provider = input.local_group_policy_provider;
    result.rsop_provider = input.rsop_provider;
    result.local_group_policy_diagnostics =
        input.local_group_policy_diagnostics;
    result.rsop_diagnostics = input.rsop_diagnostics;
    result.limitations =
        DomainMembershipIsNotTargetAttribution |
        MdmRegistrationIsNotTargetAttribution |
        RsopAbsenceIsNotOwnershipProof |
        UserPolicyScopeNotInspected |
        MdmTargetAttributionUnavailable;
    if (input.rsop_provider.freshness != EvidenceFreshness::Current) {
        result.limitations |= RsopFreshnessIsNotAuthoritative;
    }

    const bool malformed = IsMalformedProviderState(input);
    constexpr std::array targets{
        FixedPolicyTarget::AutoRunDriveTypes,
        FixedPolicyTarget::AutoRunCommands,
        FixedPolicyTarget::PowerShellScriptBlockLogging,
        FixedPolicyTarget::PowerShellModuleLogging,
        FixedPolicyTarget::PowerShellAllModules,
    };
    for (std::size_t index = 0; index < targets.size(); ++index) {
        result.targets[index] = {
            targets[index],
            ClassifyTarget(input, index, malformed),
            input.local_group_policy_matches[index],
            input.rsop_matches[index],
        };
    }

    if (malformed) {
        result.classification = ManagementClassification::Ambiguous;
    } else if (HasProviderFailure(input)) {
        result.classification = ManagementClassification::ProviderError;
    } else if (HasAnyTargetMatch(input) ||
               input.domain_membership == DomainMembership::Domain ||
               input.mdm_registration == MdmRegistration::Registered) {
        result.classification = ManagementClassification::Managed;
    } else if (HasUnsupportedProvider(input)) {
        result.classification = ManagementClassification::Unsupported;
    } else if (input.rsop_provider.freshness != EvidenceFreshness::Current) {
        result.classification = ManagementClassification::Ambiguous;
    } else {
        result.classification =
            ManagementClassification::NoMatchingPolicyObserved;
    }
    return result;
}

}  // namespace wincur::helper
