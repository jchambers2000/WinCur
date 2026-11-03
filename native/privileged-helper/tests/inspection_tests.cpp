#include "wincur/helper/inspection.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;
int checks = 0;

void Check(const bool condition, const char* const description) {
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << description << '\n';
        ++failures;
    }
}

[[nodiscard]] wincur::helper::ValueEvidence Missing() {
    return {wincur::helper::EvidenceState::Missing};
}

[[nodiscard]] wincur::helper::ValueEvidence Dword(const std::uint32_t value) {
    return {
        wincur::helper::EvidenceState::Present,
        wincur::helper::EvidenceType::Dword,
        value,
        {},
    };
}

[[nodiscard]] wincur::helper::ValueEvidence String(const wchar_t* value) {
    return {
        wincur::helper::EvidenceState::Present,
        wincur::helper::EvidenceType::String,
        0,
        value,
    };
}

[[nodiscard]] wincur::helper::RegistryInspectionEvidence AutoRun(
    const wincur::helper::ValueEvidence& drive,
    const wincur::helper::ValueEvidence& command
) {
    wincur::helper::RegistryInspectionEvidence evidence{};
    evidence.value_count = 2;
    evidence.values[0] = drive;
    evidence.values[1] = command;
    return evidence;
}

[[nodiscard]] wincur::helper::RegistryInspectionEvidence PowerShell(
    const wincur::helper::ValueEvidence& script,
    const wincur::helper::ValueEvidence& module,
    const wincur::helper::ValueEvidence& wildcard
) {
    wincur::helper::RegistryInspectionEvidence evidence{};
    evidence.value_count = 3;
    evidence.values[0] = script;
    evidence.values[1] = module;
    evidence.values[2] = wildcard;
    return evidence;
}

void TestAutoRun() {
    auto result = wincur::helper::EvaluateAutoRunInspection(
        AutoRun(Dword(255), Dword(1))
    );
    Check(result.status == wincur::helper::InspectionStatus::Compliant,
          "exact AutoRun DWORD values are compliant");

    result = wincur::helper::EvaluateAutoRunInspection(
        AutoRun(Missing(), Missing())
    );
    Check(
        result.status == wincur::helper::InspectionStatus::RemediationRequired,
        "fully missing AutoRun values require remediation"
    );

    result = wincur::helper::EvaluateAutoRunInspection(
        AutoRun(Dword(145), Dword(1))
    );
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "explicit conflicting AutoRun value is ambiguous");

    result = wincur::helper::EvaluateAutoRunInspection(
        AutoRun(String(L"255"), Dword(1))
    );
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous &&
              result.message_code == L"MalformedPolicyValue",
          "wrong AutoRun type is malformed");

    auto evidence = AutoRun(Dword(255), Dword(1));
    evidence.authority = wincur::helper::PolicyAuthority::Managed;
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Managed,
          "managed AutoRun evidence remains managed even when compliant");

    evidence = AutoRun(
        {wincur::helper::EvidenceState::Inaccessible},
        {wincur::helper::EvidenceState::Inaccessible}
    );
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Inaccessible,
          "fully inaccessible AutoRun evidence is inaccessible");

    evidence = AutoRun(
        Dword(255),
        {wincur::helper::EvidenceState::Inaccessible}
    );
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Partial,
          "partially readable AutoRun evidence is partial");

    evidence = AutoRun(
        {wincur::helper::EvidenceState::Unsupported},
        {wincur::helper::EvidenceState::Unsupported}
    );
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Unsupported,
          "unsupported AutoRun provider is unsupported");

    evidence = AutoRun(Missing(), Missing());
    evidence.authority = wincur::helper::PolicyAuthority::Unsupported;
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Unsupported,
          "unsupported AutoRun authority provider fails closed");

    evidence.value_count = 3;
    result = wincur::helper::EvaluateAutoRunInspection(evidence);
    Check(result.message_code == L"InspectionSchemaMismatch",
          "unexpected AutoRun evidence shape is rejected");
}

void TestPowerShellLogging() {
    auto result = wincur::helper::EvaluatePowerShellLoggingInspection(
        PowerShell(Dword(1), Dword(1), String(L"*"))
    );
    Check(result.status == wincur::helper::InspectionStatus::Compliant,
          "exact PowerShell logging policy is compliant");

    result = wincur::helper::EvaluatePowerShellLoggingInspection(
        PowerShell(Missing(), Missing(), Missing())
    );
    Check(
        result.status == wincur::helper::InspectionStatus::RemediationRequired,
        "fully missing PowerShell logging policy requires remediation"
    );

    result = wincur::helper::EvaluatePowerShellLoggingInspection(
        PowerShell(Dword(1), Dword(0), String(L"*"))
    );
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "conflicting PowerShell logging policy is ambiguous");

    result = wincur::helper::EvaluatePowerShellLoggingInspection(
        PowerShell(Dword(1), Dword(1), String(L"SelectedModule"))
    );
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "non-wildcard module policy is not compliant");

    auto evidence = PowerShell(Dword(1), Missing(), Missing());
    evidence.authority = wincur::helper::PolicyAuthority::Managed;
    result = wincur::helper::EvaluatePowerShellLoggingInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Managed,
          "reliably managed PowerShell policy is blocked managed");

    evidence = PowerShell(Missing(), Missing(), Missing());
    evidence.authority = wincur::helper::PolicyAuthority::Ambiguous;
    result = wincur::helper::EvaluatePowerShellLoggingInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "ambiguous PowerShell management evidence fails closed");

    evidence.authority = wincur::helper::PolicyAuthority::Inaccessible;
    result = wincur::helper::EvaluatePowerShellLoggingInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Inaccessible,
          "inaccessible PowerShell management evidence fails closed");
}

void TestFirewall() {
    wincur::helper::FirewallInspectionEvidence evidence{};
    evidence.authority =
        wincur::helper::PolicyAuthority::NoReliableManagedOverrideEvidence;
    evidence.profiles.fill(wincur::helper::FirewallProfileState::Enabled);
    auto result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Compliant,
          "three enabled firewall profiles are compliant");

    evidence.profiles[2] = wincur::helper::FirewallProfileState::Disabled;
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(
        result.status == wincur::helper::InspectionStatus::RemediationRequired,
        "disabled firewall profile requires remediation"
    );

    evidence.authority = wincur::helper::PolicyAuthority::Managed;
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Managed,
          "firewall Group Policy override is managed");

    evidence.authority = wincur::helper::PolicyAuthority::Ambiguous;
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "ambiguous firewall authority fails closed");

    evidence.authority =
        wincur::helper::PolicyAuthority::NoReliableManagedOverrideEvidence;
    evidence.profiles = {
        wincur::helper::FirewallProfileState::Enabled,
        wincur::helper::FirewallProfileState::Inaccessible,
        wincur::helper::FirewallProfileState::Disabled,
    };
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Partial,
          "partially readable firewall profiles are partial");

    evidence.profiles.fill(wincur::helper::FirewallProfileState::Unsupported);
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Unsupported,
          "unavailable firewall provider is unsupported");

    evidence.profiles.fill(wincur::helper::FirewallProfileState::Inaccessible);
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Inaccessible,
          "inaccessible firewall provider fails closed");

    evidence.profiles.fill(wincur::helper::FirewallProfileState::Error);
    result = wincur::helper::EvaluateFirewallInspection(evidence);
    Check(result.status == wincur::helper::InspectionStatus::Ambiguous,
          "contradictory firewall provider failure is ambiguous");
}

void TestTransactionMappingAndBounds() {
    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Preview;
    request.transaction_id = L"123e4567-e89b-12d3-a456-426614174000";
    request.action = wincur::helper::ActionId::DisableAutoRun;

    const auto inspection = wincur::helper::EvaluateAutoRunInspection(
        AutoRun(Missing(), Missing())
    );
    const auto transaction = wincur::helper::MakeInspectionTransactionResult(
        request,
        inspection,
        L"2026-11-02T12:00:00Z"
    );
    Check(transaction.outcome == wincur::helper::TransactionOutcome::Succeeded,
          "successful preview can report remediation required");
    Check(transaction.message_code == L"RemediationRequired",
          "preview disposition remains explicit in message code");
    Check(
        transaction.display_message.size() <=
                wincur::helper::kMaximumDisplayMessageCharacters &&
            transaction.verification_summary.size() <=
                wincur::helper::kMaximumVerificationSummaryCharacters,
        "inspection result fields remain bounded"
    );
    Check(
        wincur::helper::SerializeTransactionResult(transaction).has_value(),
        "inspection transaction satisfies protected schema"
    );

    auto managed = AutoRun(Dword(255), Dword(1));
    managed.authority = wincur::helper::PolicyAuthority::Managed;
    const auto managed_transaction =
        wincur::helper::MakeInspectionTransactionResult(
            request,
            wincur::helper::EvaluateAutoRunInspection(managed),
            L"2026-11-02T12:00:00Z"
        );
    Check(
        managed_transaction.outcome ==
            wincur::helper::TransactionOutcome::BlockedManaged,
        "managed inspection maps to blocked-managed transaction outcome"
    );
}

}  // namespace

int main() {
    TestAutoRun();
    TestPowerShellLogging();
    TestFirewall();
    TestTransactionMappingAndBounds();

    if (failures != 0) {
        std::cerr << failures << " of " << checks << " inspection checks failed.\n";
        return EXIT_FAILURE;
    }
    std::cout << checks << " inspection checks passed.\n";
    return EXIT_SUCCESS;
}
