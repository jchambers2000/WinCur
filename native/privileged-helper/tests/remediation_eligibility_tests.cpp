#include "wincur/helper/remediation_eligibility.hpp"

#include <cstdlib>
#include <iostream>

namespace {

using wincur::helper::ActionId;
using wincur::helper::EvidenceFreshness;
using wincur::helper::InspectionStatus;
using wincur::helper::LocalOwnershipEvidence;
using wincur::helper::ManagementClassification;
using wincur::helper::ManagementPostureResult;
using wincur::helper::MdmRegistration;
using wincur::helper::ProviderFailureStage;
using wincur::helper::ProviderHealth;
using wincur::helper::RemediationEligibilityClassification;
using wincur::helper::RemediationEligibilityInput;
using wincur::helper::RemediationEligibilityReason;
using wincur::helper::RollbackEvidenceQuality;

int checks = 0;
int failures = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] ManagementPostureResult ClearCurrentManagement() {
    ManagementPostureResult result{};
    result.classification =
        ManagementClassification::NoMatchingPolicyObserved;
    result.domain_provider = {
        ProviderHealth::Healthy,
        EvidenceFreshness::NotApplicable,
        0,
        true,
    };
    result.domain_membership = wincur::helper::DomainMembership::Workgroup;
    result.mdm_provider = result.domain_provider;
    result.mdm_registration = MdmRegistration::NotRegistered;
    result.local_group_policy_provider = result.domain_provider;
    result.local_group_policy_diagnostics = {
        ProviderFailureStage::Completed,
        0,
        0,
        true,
        true,
    };
    result.rsop_provider = {
        ProviderHealth::Healthy,
        EvidenceFreshness::Current,
        0,
        true,
    };
    result.rsop_diagnostics = {
        ProviderFailureStage::Completed,
        0,
        0,
        true,
        true,
    };
    constexpr std::array targets{
        wincur::helper::FixedPolicyTarget::AutoRunDriveTypes,
        wincur::helper::FixedPolicyTarget::AutoRunCommands,
        wincur::helper::FixedPolicyTarget::PowerShellScriptBlockLogging,
        wincur::helper::FixedPolicyTarget::PowerShellModuleLogging,
        wincur::helper::FixedPolicyTarget::PowerShellAllModules,
    };
    for (std::size_t index = 0; index < targets.size(); ++index) {
        result.targets[index] = {
            targets[index],
            ManagementClassification::NoMatchingPolicyObserved,
            false,
            false,
        };
    }
    return result;
}

[[nodiscard]] RemediationEligibilityInput AutoRunCandidateInput() {
    return {
        ActionId::DisableAutoRun,
        InspectionStatus::RemediationRequired,
        ClearCurrentManagement(),
        LocalOwnershipEvidence::VerifiedLocalBySupportedProvider,
        RollbackEvidenceQuality::ExactPreChangeState,
    };
}

void Expect(
    const RemediationEligibilityInput& input,
    const RemediationEligibilityClassification classification,
    const RemediationEligibilityReason reason,
    const char* const description
) {
    const auto result =
        wincur::helper::EvaluateRemediationEligibility(input);
    Check(
        result.classification == classification && result.reason == reason,
        description
    );
    Check(
        result.advisory_only && !result.authorizes_mutation,
        "every eligibility result remains advisory and non-authorizing"
    );
}

void TestAllClassifications() {
    auto input = AutoRunCandidateInput();
    Expect(
        input,
        RemediationEligibilityClassification::
            EligibleForLocalRemediationCandidate,
        RemediationEligibilityReason::CandidateEvidenceComplete,
        "complete synthetic AutoRun evidence can produce a candidate"
    );

    input.inspection_status = InspectionStatus::Compliant;
    input.management.classification = ManagementClassification::Managed;
    Expect(
        input,
        RemediationEligibilityClassification::AlreadyCompliant,
        RemediationEligibilityReason::ObservedAlreadyCompliant,
        "already compliant describes configuration without claiming ownership"
    );

    input = AutoRunCandidateInput();
    input.inspection_status = InspectionStatus::Managed;
    Expect(
        input,
        RemediationEligibilityClassification::ManagedByPolicy,
        RemediationEligibilityReason::InspectionManaged,
        "inspection-managed evidence blocks as managed"
    );

    input = AutoRunCandidateInput();
    input.management.targets[0].classification =
        ManagementClassification::Managed;
    input.management.targets[0].local_group_policy_match = true;
    Expect(
        input,
        RemediationEligibilityClassification::ManagedByPolicy,
        RemediationEligibilityReason::TargetManaged,
        "positive fixed-target policy match blocks as managed"
    );

    input = AutoRunCandidateInput();
    input.local_ownership = LocalOwnershipEvidence::NotEstablished;
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::OwnershipNotEstablished,
        "absence of policy matches does not establish local ownership"
    );

    input = AutoRunCandidateInput();
    input.inspection_status = InspectionStatus::Unsupported;
    Expect(
        input,
        RemediationEligibilityClassification::UnsupportedConfiguration,
        RemediationEligibilityReason::InspectionUnsupported,
        "unsupported inspection remains unsupported"
    );

    input = AutoRunCandidateInput();
    input.rollback_evidence = RollbackEvidenceQuality::Insufficient;
    Expect(
        input,
        RemediationEligibilityClassification::InsufficientRollbackEvidence,
        RemediationEligibilityReason::RollbackEvidenceInsufficient,
        "missing exact rollback evidence blocks a candidate"
    );
}

void TestFailClosedPrecedence() {
    auto input = AutoRunCandidateInput();
    input.management.targets[0].classification =
        ManagementClassification::ProviderError;
    input.management.targets[1].classification =
        ManagementClassification::Managed;
    input.management.targets[1].rsop_match = true;
    Expect(
        input,
        RemediationEligibilityClassification::ManagedByPolicy,
        RemediationEligibilityReason::TargetManaged,
        "positive managed evidence takes precedence over provider failure"
    );

    input = AutoRunCandidateInput();
    input.management.classification =
        ManagementClassification::ProviderError;
    input.management.rsop_provider = {
        ProviderHealth::AccessDenied,
        EvidenceFreshness::NotApplicable,
        0x80041003U,
        false,
    };
    input.management.rsop_diagnostics = {
        ProviderFailureStage::WmiConnection,
        0x80041003U,
        0,
        false,
        true,
    };
    for (auto& target : input.management.targets) {
        target.classification = ManagementClassification::ProviderError;
    }
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::ManagementProviderFailure,
        "provider failure blocks eligibility"
    );

    input = AutoRunCandidateInput();
    input.management.targets[0].classification =
        ManagementClassification::Ambiguous;
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::ManagementEvidenceAmbiguous,
        "ambiguous target ownership blocks eligibility"
    );

    input = AutoRunCandidateInput();
    input.management.targets[0].classification =
        ManagementClassification::Unsupported;
    Expect(
        input,
        RemediationEligibilityClassification::UnsupportedConfiguration,
        RemediationEligibilityReason::ManagementUnsupported,
        "unsupported management evidence remains unsupported"
    );

    input = AutoRunCandidateInput();
    input.management.classification = ManagementClassification::Managed;
    for (auto& target : input.management.targets) {
        target.classification = ManagementClassification::Ambiguous;
    }
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::ManagementEvidenceAmbiguous,
        "device-level management without target attribution stays ambiguous"
    );

    for (const InspectionStatus status : {
             InspectionStatus::Ambiguous,
             InspectionStatus::Inaccessible,
             InspectionStatus::Partial}) {
        input = AutoRunCandidateInput();
        input.inspection_status = status;
        Expect(
            input,
            RemediationEligibilityClassification::AmbiguousOwnership,
            RemediationEligibilityReason::InspectionUnavailable,
            "ambiguous, inaccessible, and partial inspections fail closed"
        );
    }
}

void TestCurrentlyIneligibleActions() {
    auto input = AutoRunCandidateInput();
    input.action = ActionId::EnablePowerShellLogging;
    Expect(
        input,
        RemediationEligibilityClassification::InsufficientRollbackEvidence,
        RemediationEligibilityReason::ActionEvidenceUnresolved,
        "PowerShell logging remains ineligible with synthetic clear evidence"
    );

    input = AutoRunCandidateInput();
    input.action = ActionId::EnableFirewallProfiles;
    Expect(
        input,
        RemediationEligibilityClassification::InsufficientRollbackEvidence,
        RemediationEligibilityReason::ActionEvidenceUnresolved,
        "Firewall remains ineligible without rollback-grade policy ownership"
    );

    input.inspection_status = InspectionStatus::Managed;
    Expect(
        input,
        RemediationEligibilityClassification::ManagedByPolicy,
        RemediationEligibilityReason::InspectionManaged,
        "Firewall managed inspection takes precedence over unresolved rollback"
    );
}

void TestMalformedAndCurrentProviderEvidence() {
    auto input = AutoRunCandidateInput();
    input.action = static_cast<ActionId>(255);
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput,
        "unknown action fails closed"
    );

    input = AutoRunCandidateInput();
    input.management.targets[0].target =
        wincur::helper::FixedPolicyTarget::PowerShellAllModules;
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput,
        "reordered fixed targets are malformed"
    );

    input = AutoRunCandidateInput();
    input.management.rsop_provider = {
        ProviderHealth::Failed,
        EvidenceFreshness::NotApplicable,
        0,
        false,
    };
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput,
        "failed provider without an error code is malformed"
    );

    input = AutoRunCandidateInput();
    input.management.rsop_provider.freshness = EvidenceFreshness::Unknown;
    for (auto& target : input.management.targets) {
        target.classification = ManagementClassification::Ambiguous;
    }
    input.management.classification = ManagementClassification::Ambiguous;
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::ManagementEvidenceAmbiguous,
        "current RSoP unknown freshness remains an ambiguity blocker"
    );

    input = AutoRunCandidateInput();
    input.management.rsop_provider.freshness = EvidenceFreshness::Unknown;
    Expect(
        input,
        RemediationEligibilityClassification::AmbiguousOwnership,
        RemediationEligibilityReason::MalformedInput,
        "unknown freshness cannot accompany no-match ownership claims"
    );

    input = AutoRunCandidateInput();
    input.rollback_evidence = RollbackEvidenceQuality::Malformed;
    Expect(
        input,
        RemediationEligibilityClassification::InsufficientRollbackEvidence,
        RemediationEligibilityReason::RollbackEvidenceMalformed,
        "malformed rollback evidence remains ineligible"
    );

    input = AutoRunCandidateInput();
    input.rollback_evidence = RollbackEvidenceQuality::Unsupported;
    Expect(
        input,
        RemediationEligibilityClassification::UnsupportedConfiguration,
        RemediationEligibilityReason::RollbackEvidenceUnsupported,
        "unsupported rollback representation remains unsupported"
    );
}

void TestNoCurrentRealWorldCandidate() {
    auto input = AutoRunCandidateInput();
    input.management.classification = ManagementClassification::Ambiguous;
    input.management.rsop_provider.freshness = EvidenceFreshness::Unknown;
    for (auto& target : input.management.targets) {
        target.classification = ManagementClassification::Ambiguous;
    }
    input.local_ownership = LocalOwnershipEvidence::NotEstablished;

    for (const ActionId action : {
             ActionId::DisableAutoRun,
             ActionId::EnablePowerShellLogging,
             ActionId::EnableFirewallProfiles}) {
        input.action = action;
        const auto result =
            wincur::helper::EvaluateRemediationEligibility(input);
        Check(
            result.classification !=
                RemediationEligibilityClassification::
                    EligibleForLocalRemediationCandidate,
            "current unknown-freshness evidence cannot produce a candidate"
        );
        Check(
            result.advisory_only && !result.authorizes_mutation,
            "current evidence remains advisory and non-authorizing"
        );
    }
}

}  // namespace

int main() {
    TestAllClassifications();
    TestFailClosedPrecedence();
    TestCurrentlyIneligibleActions();
    TestMalformedAndCurrentProviderEvidence();
    TestNoCurrentRealWorldCandidate();
    if (failures != 0) {
        std::cerr << failures << " of " << checks
                  << " remediation eligibility checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " remediation eligibility checks passed.\n";
    return EXIT_SUCCESS;
}
