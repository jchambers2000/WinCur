#include "wincur/helper/inspection.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <string_view>
#include <utility>

namespace wincur::helper {
namespace {

[[nodiscard]] InspectionResult Result(
    const InspectionStatus status,
    const wchar_t* const code,
    const wchar_t* const message,
    const wchar_t* const summary
) {
    return {status, code, message, summary};
}

[[nodiscard]] InspectionResult EvidenceFailure(
    const RegistryInspectionEvidence& evidence,
    const wchar_t* const subject
) {
    std::size_t readable = 0;
    std::size_t inaccessible = 0;
    std::size_t unsupported = 0;
    std::size_t errors = 0;
    for (std::size_t index = 0; index < evidence.value_count; ++index) {
        switch (evidence.values[index].state) {
            case EvidenceState::Missing:
            case EvidenceState::Present:
                ++readable;
                break;
            case EvidenceState::Inaccessible:
                ++inaccessible;
                break;
            case EvidenceState::Unsupported:
                ++unsupported;
                break;
            case EvidenceState::Error:
                ++errors;
                break;
        }
    }
    if (readable != 0 && readable != evidence.value_count) {
        return Result(
            InspectionStatus::Partial,
            L"InspectionPartial",
            L"Only part of the selected policy configuration could be read.",
            subject
        );
    }
    if (inaccessible != 0) {
        return Result(
            InspectionStatus::Inaccessible,
            L"InspectionAccessDenied",
            L"Access was denied while reading the selected policy configuration.",
            subject
        );
    }
    if (unsupported != 0) {
        return Result(
            InspectionStatus::Unsupported,
            L"InspectionUnsupported",
            L"The selected policy configuration is unavailable on this system.",
            subject
        );
    }
    if (errors != 0) {
        return Result(
            InspectionStatus::Ambiguous,
            L"InspectionProviderError",
            L"The selected policy configuration could not be assessed reliably.",
            subject
        );
    }
    return {};
}

[[nodiscard]] bool HasCollectionFailure(
    const RegistryInspectionEvidence& evidence
) {
    return std::any_of(
        evidence.values.begin(),
        evidence.values.begin() + evidence.value_count,
        [](const ValueEvidence& value) {
            return value.state == EvidenceState::Inaccessible ||
                   value.state == EvidenceState::Unsupported ||
                   value.state == EvidenceState::Error;
        }
    );
}

[[nodiscard]] InspectionResult EvaluateRegistryPolicy(
    const RegistryInspectionEvidence& evidence,
    const std::span<const EvidenceType> types,
    const std::span<const std::uint32_t> dwords,
    const std::span<const std::wstring_view> strings,
    const wchar_t* const compliant_message,
    const wchar_t* const missing_message,
    const wchar_t* const subject
) {
    if (evidence.value_count != types.size() || types.size() != dwords.size() ||
        types.size() != strings.size() || evidence.value_count == 0 ||
        evidence.value_count > evidence.values.size()) {
        return Result(
            InspectionStatus::Ambiguous,
            L"InspectionSchemaMismatch",
            L"The inspection provider returned an unexpected evidence shape.",
            subject
        );
    }
    if (HasCollectionFailure(evidence)) {
        return EvidenceFailure(evidence, subject);
    }

    std::size_t missing = 0;
    bool compliant = true;
    bool malformed = false;
    for (std::size_t index = 0; index < evidence.value_count; ++index) {
        const ValueEvidence& value = evidence.values[index];
        if (value.state == EvidenceState::Missing) {
            ++missing;
            compliant = false;
            continue;
        }
        if (value.state != EvidenceState::Present || value.type != types[index]) {
            compliant = false;
            malformed = true;
            continue;
        }
        if (types[index] == EvidenceType::Dword &&
            value.dword_value != dwords[index]) {
            compliant = false;
        } else if (types[index] == EvidenceType::String &&
                   value.string_value != strings[index]) {
            compliant = false;
        }
    }

    if (evidence.authority == PolicyAuthority::Managed) {
        return Result(
            InspectionStatus::Managed,
            L"PolicyManaged",
            L"Windows reports that the selected configuration is policy managed.",
            compliant ? compliant_message : subject
        );
    }
    if (compliant) {
        return Result(
            InspectionStatus::Compliant,
            L"AlreadyCompliant",
            compliant_message,
            L"Every selected value exists with the required type and value."
        );
    }
    if (evidence.authority == PolicyAuthority::Inaccessible) {
        return Result(
            InspectionStatus::Inaccessible,
            L"ManagementEvidenceAccessDenied",
            L"Management authority could not be inspected because access was denied.",
            subject
        );
    }
    if (evidence.authority == PolicyAuthority::Unsupported) {
        return Result(
            InspectionStatus::Unsupported,
            L"ManagementEvidenceUnsupported",
            L"Management authority is not exposed reliably on this system.",
            subject
        );
    }
    if (evidence.authority == PolicyAuthority::Ambiguous) {
        return Result(
            InspectionStatus::Ambiguous,
            L"ManagementEvidenceAmbiguous",
            L"The selected configuration may be policy controlled; ownership could not be attributed reliably.",
            subject
        );
    }
    if (missing == evidence.value_count) {
        return Result(
            InspectionStatus::RemediationRequired,
            L"RemediationRequired",
            missing_message,
            L"All selected values are absent. Absence does not prove that no management authority exists."
        );
    }

    return Result(
        InspectionStatus::Ambiguous,
        malformed ? L"MalformedPolicyValue" : L"ConflictingPolicyEvidence",
        malformed
            ? L"At least one selected policy value has an unsupported registry type."
            : L"Selected policy values are present but do not form one complete required configuration.",
        subject
    );
}

[[nodiscard]] TransactionOutcome OutcomeForStatus(
    const InspectionStatus status
) noexcept {
    switch (status) {
        case InspectionStatus::Compliant:
            return TransactionOutcome::AlreadyCompliant;
        case InspectionStatus::RemediationRequired:
            return TransactionOutcome::Succeeded;
        case InspectionStatus::Managed:
            return TransactionOutcome::BlockedManaged;
        case InspectionStatus::Ambiguous:
        case InspectionStatus::Partial:
        case InspectionStatus::Unsupported:
            return TransactionOutcome::BlockedAmbiguous;
        case InspectionStatus::Inaccessible:
            return TransactionOutcome::Failed;
    }
    return TransactionOutcome::Failed;
}

}  // namespace

InspectionResult EvaluateAutoRunInspection(
    const RegistryInspectionEvidence& evidence
) {
    constexpr std::array types{EvidenceType::Dword, EvidenceType::Dword};
    constexpr std::array<std::uint32_t, 2> dwords{255, 1};
    constexpr std::array<std::wstring_view, 2> strings{L"", L""};
    return EvaluateRegistryPolicy(
        evidence,
        types,
        dwords,
        strings,
        L"The machine AutoRun policy disables commands for all drive types.",
        L"The selected machine AutoRun policy values are absent.",
        L"AutoRun requires NoDriveTypeAutoRun=255 and NoAutorun=1 as DWORD values at the fixed machine policy target."
    );
}

InspectionResult EvaluatePowerShellLoggingInspection(
    const RegistryInspectionEvidence& evidence
) {
    constexpr std::array types{
        EvidenceType::Dword,
        EvidenceType::Dword,
        EvidenceType::String,
    };
    constexpr std::array<std::uint32_t, 3> dwords{1, 1, 0};
    constexpr std::array<std::wstring_view, 3> strings{L"", L"", L"*"};
    return EvaluateRegistryPolicy(
        evidence,
        types,
        dwords,
        strings,
        L"Script Block Logging and all-module Module Logging are enabled by machine policy.",
        L"The selected machine PowerShell logging policy values are absent.",
        L"PowerShell logging requires both enable DWORD values and the ModuleNames wildcard string at the fixed machine policy targets."
    );
}

InspectionResult EvaluateFirewallInspection(
    const FirewallInspectionEvidence& evidence
) {
    std::size_t enabled = 0;
    std::size_t readable = 0;
    std::size_t inaccessible = 0;
    std::size_t unsupported = 0;
    for (const FirewallProfileState profile : evidence.profiles) {
        switch (profile) {
            case FirewallProfileState::Enabled:
                ++enabled;
                ++readable;
                break;
            case FirewallProfileState::Disabled:
                ++readable;
                break;
            case FirewallProfileState::Inaccessible:
                ++inaccessible;
                break;
            case FirewallProfileState::Unsupported:
                ++unsupported;
                break;
            case FirewallProfileState::Error:
                break;
        }
    }
    if (readable != 0 && readable != evidence.profiles.size()) {
        return Result(
            InspectionStatus::Partial,
            L"InspectionPartial",
            L"Only some Windows Firewall profiles could be inspected.",
            L"Domain, Private, and Public profile evidence is required."
        );
    }
    if (inaccessible != 0) {
        return Result(
            InspectionStatus::Inaccessible,
            L"InspectionAccessDenied",
            L"Access was denied while inspecting Windows Firewall profiles.",
            L"No profile state is assumed when the firewall provider denies access."
        );
    }
    if (unsupported != 0) {
        return Result(
            InspectionStatus::Unsupported,
            L"InspectionUnsupported",
            L"The Windows Firewall policy provider is unavailable.",
            L"No profile state is assumed when INetFwPolicy2 is unavailable."
        );
    }
    if (readable != evidence.profiles.size()) {
        return Result(
            InspectionStatus::Ambiguous,
            L"InspectionProviderError",
            L"Windows Firewall profile state could not be assessed reliably.",
            L"Domain, Private, and Public profile evidence is required."
        );
    }
    if (evidence.authority == PolicyAuthority::Managed) {
        return Result(
            InspectionStatus::Managed,
            L"FirewallPolicyManaged",
            L"Windows reports that Group Policy overrides local firewall policy.",
            enabled == evidence.profiles.size()
                ? L"All profiles are enabled, but local policy is overridden."
                : L"At least one profile is disabled and local policy is overridden."
        );
    }
    if (enabled == evidence.profiles.size()) {
        return Result(
            InspectionStatus::Compliant,
            L"AlreadyCompliant",
            L"Domain, Private, and Public Windows Firewall profiles are enabled.",
            L"All three effective profile states were read as enabled."
        );
    }
    if (evidence.authority == PolicyAuthority::Inaccessible) {
        return Result(
            InspectionStatus::Inaccessible,
            L"ManagementEvidenceAccessDenied",
            L"Firewall management authority could not be inspected because access was denied.",
            L"A disabled profile is present; modification authority is unknown."
        );
    }
    if (evidence.authority == PolicyAuthority::Unsupported) {
        return Result(
            InspectionStatus::Unsupported,
            L"ManagementEvidenceUnsupported",
            L"Firewall management authority is not exposed reliably on this system.",
            L"A disabled profile is present; modification authority is unknown."
        );
    }
    if (evidence.authority == PolicyAuthority::Ambiguous) {
        return Result(
            InspectionStatus::Ambiguous,
            L"FirewallManagementAmbiguous",
            L"At least one firewall profile is disabled, but local policy authority is ambiguous.",
            L"The provider did not establish that a local profile change would be authoritative."
        );
    }
    return Result(
        InspectionStatus::RemediationRequired,
        L"RemediationRequired",
        L"At least one Windows Firewall profile is disabled.",
        L"The effective profile states require remediation. Preview does not authorize a future write."
    );
}

TransactionResult MakeInspectionTransactionResult(
    const Request& request,
    const InspectionResult& inspection,
    std::wstring timestamp_utc
) {
    TransactionResult result{};
    result.transaction_id = request.transaction_id;
    result.operation = request.operation;
    result.action = request.action;
    result.outcome = OutcomeForStatus(inspection.status);
    result.message_code = inspection.message_code;
    result.display_message = inspection.display_message;
    result.verification_summary = inspection.verification_summary;
    result.helper_version = std::wstring(kHelperVersion);
    result.build_id = std::wstring(kHelperBuildId);
    result.timestamp_utc = std::move(timestamp_utc);
    return result;
}

}  // namespace wincur::helper
