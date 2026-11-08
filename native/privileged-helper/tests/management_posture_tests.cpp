#include "wincur/helper/management_posture.hpp"

#include <cstdlib>
#include <iostream>

namespace {

using wincur::helper::DomainMembership;
using wincur::helper::EvidenceFreshness;
using wincur::helper::ManagementClassification;
using wincur::helper::ManagementPostureInput;
using wincur::helper::MdmRegistration;
using wincur::helper::ProviderEvidence;
using wincur::helper::ProviderHealth;

int checks = 0;
int failures = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] ProviderEvidence Healthy(
    const EvidenceFreshness freshness = EvidenceFreshness::NotApplicable
) {
    return {ProviderHealth::Healthy, freshness, 0, true};
}

[[nodiscard]] ManagementPostureInput StandaloneCurrent() {
    ManagementPostureInput input{};
    input.domain_provider = Healthy();
    input.domain_membership = DomainMembership::Workgroup;
    input.mdm_provider = Healthy();
    input.mdm_registration = MdmRegistration::NotRegistered;
    input.local_group_policy_provider = Healthy();
    input.local_group_policy_diagnostics = {
        wincur::helper::ProviderFailureStage::Completed,
        0,
        0,
        true,
        true,
    };
    input.rsop_provider = Healthy(EvidenceFreshness::Current);
    return input;
}

void TestNoMatchingPolicyObserved() {
    const auto result = wincur::helper::EvaluateManagementPosture(
        StandaloneCurrent()
    );
    Check(
        result.classification ==
            ManagementClassification::NoMatchingPolicyObserved,
        "complete simulated standalone evidence can report no matching policy"
    );
    for (const auto& target : result.targets) {
        Check(
            target.classification ==
                ManagementClassification::NoMatchingPolicyObserved,
            "each fixed target reports no observed matching policy"
        );
    }
    Check(
        (result.limitations &
         wincur::helper::RsopAbsenceIsNotOwnershipProof) != 0,
        "absence result retains the RSoP ownership limitation"
    );
}

void TestManagedSignals() {
    auto input = StandaloneCurrent();
    input.domain_membership = DomainMembership::Domain;
    auto result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Managed,
        "domain membership marks device posture managed"
    );
    Check(
        result.targets[0].classification ==
            ManagementClassification::Ambiguous,
        "domain membership alone is not target attribution"
    );

    input = StandaloneCurrent();
    input.mdm_registration = MdmRegistration::Registered;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Managed,
        "MDM registration marks device posture managed"
    );
    Check(
        result.targets[0].classification ==
            ManagementClassification::Ambiguous,
        "MDM registration alone is not target attribution"
    );

    input = StandaloneCurrent();
    input.local_group_policy_matches[0] = true;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.targets[0].classification == ManagementClassification::Managed &&
            result.targets[0].local_group_policy_match,
        "Local GPO target match is positive managed evidence"
    );

    input = StandaloneCurrent();
    input.rsop_matches[4] = true;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.targets[4].classification == ManagementClassification::Managed &&
            result.targets[4].rsop_match,
        "RSoP target match is positive managed evidence"
    );
}

void TestFreshnessAndFailures() {
    auto input = StandaloneCurrent();
    input.rsop_provider.freshness = EvidenceFreshness::Unknown;
    auto result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "unknown RSoP freshness fails closed"
    );
    Check(
        (result.limitations &
         wincur::helper::RsopFreshnessIsNotAuthoritative) != 0,
        "unknown freshness is recorded as a limitation"
    );

    input.rsop_provider.freshness = EvidenceFreshness::Stale;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "stale RSoP evidence fails closed"
    );

    input = StandaloneCurrent();
    input.mdm_provider = {
        ProviderHealth::Failed,
        EvidenceFreshness::NotApplicable,
        5,
        false,
    };
    input.mdm_registration = MdmRegistration::Unknown;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::ProviderError,
        "MDM query failure remains distinct from not registered"
    );

    input = StandaloneCurrent();
    input.local_group_policy_provider = {
        ProviderHealth::AccessDenied,
        EvidenceFreshness::NotApplicable,
        5,
        false,
    };
    input.local_group_policy_diagnostics = {
        wincur::helper::ProviderFailureStage::OpenLocalMachineGpo,
        5,
        0,
        false,
        true,
    };
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::ProviderError,
        "access-denied policy evidence is a provider error"
    );

    input = StandaloneCurrent();
    input.rsop_provider = {
        ProviderHealth::Unsupported,
        EvidenceFreshness::NotApplicable,
        0,
        false,
    };
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Unsupported,
        "unsupported RSoP provider is preserved"
    );
}

void TestMalformedAndContradictoryEvidence() {
    auto input = StandaloneCurrent();
    input.domain_membership = DomainMembership::Unknown;
    auto result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "healthy domain provider with no value is malformed"
    );

    input = StandaloneCurrent();
    input.local_group_policy_provider = {
        ProviderHealth::Unsupported,
        EvidenceFreshness::NotApplicable,
        0,
        false,
    };
    input.local_group_policy_matches[1] = true;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "match from an unavailable Local GPO provider is contradictory"
    );

    input = StandaloneCurrent();
    input.rsop_provider.complete = false;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::ProviderError,
        "incomplete provider enumeration fails closed"
    );

    input = StandaloneCurrent();
    input.rsop_provider = {
        ProviderHealth::Failed,
        EvidenceFreshness::Current,
        1,
        false,
    };
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "failed provider claiming current evidence is contradictory"
    );

    input = StandaloneCurrent();
    input.rsop_provider = {
        ProviderHealth::Failed,
        EvidenceFreshness::NotApplicable,
        0,
        false,
    };
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "failed provider with a zero error code is impossible evidence"
    );

    input = StandaloneCurrent();
    input.rsop_diagnostics.structurally_consistent = false;
    result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "malformed enumeration diagnostics fail closed"
    );
}

void TestProviderEvidenceConsistency() {
    Check(
        wincur::helper::IsProviderEvidenceConsistent(Healthy(), false),
        "healthy non-freshness provider is consistent"
    );
    Check(
        wincur::helper::IsProviderEvidenceConsistent(
            Healthy(EvidenceFreshness::Unknown), true),
        "healthy RSoP provider may report unknown freshness"
    );
    Check(
        !wincur::helper::IsProviderEvidenceConsistent(
            {ProviderHealth::Healthy,
             EvidenceFreshness::NotApplicable,
             5,
             true},
            false),
        "healthy provider cannot carry an error"
    );
    Check(
        !wincur::helper::IsProviderEvidenceConsistent(
            {ProviderHealth::AccessDenied,
             EvidenceFreshness::NotApplicable,
             0,
             false},
            false),
        "access denial requires a nonzero error"
    );
}

void TestLocalGroupPolicyStaDiagnostics() {
    using wincur::helper::IsLocalGroupPolicyDiagnosticConsistent;
    using wincur::helper::ProviderDiagnostics;
    using wincur::helper::ProviderFailureStage;

    Check(
        IsLocalGroupPolicyDiagnosticConsistent(
            Healthy(),
            {ProviderFailureStage::Completed, 0, 0, true, true}),
        "dedicated STA success has a consistent terminal diagnostic"
    );
    Check(
        IsLocalGroupPolicyDiagnosticConsistent(
            {ProviderHealth::AccessDenied,
             EvidenceFreshness::NotApplicable,
             0x80070005U,
             false},
            {ProviderFailureStage::OpenLocalMachineGpo,
             0x80070005U,
             0,
             false,
             true}),
        "STA access denial at GPO open is consistent failure evidence"
    );
    Check(
        IsLocalGroupPolicyDiagnosticConsistent(
            {ProviderHealth::Unsupported,
             EvidenceFreshness::NotApplicable,
             0x80004002U,
             false},
            {ProviderFailureStage::ComActivation,
             0x80004002U,
             0,
             false,
             true}),
        "COM interface failure is consistent unsupported evidence"
    );
    Check(
        IsLocalGroupPolicyDiagnosticConsistent(
            {ProviderHealth::Failed,
             EvidenceFreshness::NotApplicable,
             0x80010106U,
             false},
            {ProviderFailureStage::ComInitialization,
             0x80010106U,
             0,
             false,
             true}),
        "RPC_E_CHANGED_MODE is a COM initialization failure"
    );
    Check(
        !IsLocalGroupPolicyDiagnosticConsistent(
            Healthy(),
            {ProviderFailureStage::Completed, 5, 0, true, true}),
        "healthy STA evidence with a raw error is malformed"
    );
    Check(
        !IsLocalGroupPolicyDiagnosticConsistent(
            {ProviderHealth::AccessDenied,
             EvidenceFreshness::NotApplicable,
             0x80070005U,
             false},
            {ProviderFailureStage::OpenLocalMachineGpo,
             0x80004002U,
             0,
             false,
             true}),
        "mismatched provider and diagnostic errors are malformed"
    );

    auto input = StandaloneCurrent();
    input.local_group_policy_diagnostics = ProviderDiagnostics{
        ProviderFailureStage::Completed, 5, 0, true, true};
    const auto result = wincur::helper::EvaluateManagementPosture(input);
    Check(
        result.classification == ManagementClassification::Ambiguous,
        "malformed Local GPO evidence fails closed"
    );
}

}  // namespace

int main() {
    static_assert(wincur::helper::kFixedPolicyTargetCount == 5);
    TestNoMatchingPolicyObserved();
    TestManagedSignals();
    TestFreshnessAndFailures();
    TestMalformedAndContradictoryEvidence();
    TestProviderEvidenceConsistency();
    TestLocalGroupPolicyStaDiagnostics();

    if (failures != 0) {
        std::cerr << failures << " of " << checks
                  << " management-posture checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " management-posture checks passed.\n";
    return EXIT_SUCCESS;
}
