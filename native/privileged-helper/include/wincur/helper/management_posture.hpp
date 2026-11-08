#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wincur::helper {

inline constexpr std::uint32_t kManagementPostureProviderSchemaVersion = 1;
inline constexpr std::wstring_view kManagementPostureBuildIdentity =
    L"phase-2f2-diagnostics-1";

enum class ManagementClassification {
    Managed,
    NoMatchingPolicyObserved,
    Ambiguous,
    Unsupported,
    ProviderError,
};

enum class ProviderHealth {
    Healthy,
    Unsupported,
    AccessDenied,
    Failed,
};

enum class EvidenceFreshness {
    NotApplicable,
    Current,
    Unknown,
    Stale,
};

enum class ProviderFailureStage : std::uint8_t {
    None,
    Completed,
    ComInitialization,
    ComActivation,
    OpenLocalMachineGpo,
    GetRegistryKey,
    RegistryQuery,
    WmiConnection,
    ProxySecurity,
    ExecQuery,
    Enumeration,
};

enum class DomainMembership {
    Unknown,
    Unjoined,
    Workgroup,
    Domain,
};

enum class MdmRegistration {
    Unknown,
    NotRegistered,
    Registered,
};

enum class FixedPolicyTarget : std::uint8_t {
    AutoRunDriveTypes,
    AutoRunCommands,
    PowerShellScriptBlockLogging,
    PowerShellModuleLogging,
    PowerShellAllModules,
};

inline constexpr std::size_t kFixedPolicyTargetCount = 5;

enum ManagementLimitation : std::uint32_t {
    ManagementLimitationNone = 0,
    DomainMembershipIsNotTargetAttribution = 1U << 0U,
    MdmRegistrationIsNotTargetAttribution = 1U << 1U,
    RsopAbsenceIsNotOwnershipProof = 1U << 2U,
    RsopFreshnessIsNotAuthoritative = 1U << 3U,
    UserPolicyScopeNotInspected = 1U << 4U,
    MdmTargetAttributionUnavailable = 1U << 5U,
};

struct ProviderEvidence final {
    ProviderHealth health{ProviderHealth::Failed};
    EvidenceFreshness freshness{EvidenceFreshness::NotApplicable};
    std::uint32_t error_code{0};
    bool complete{false};
};

struct ProviderDiagnostics final {
    ProviderFailureStage stage{ProviderFailureStage::None};
    std::uint32_t raw_result{0};
    std::uint32_t returned_object_count{0};
    bool normal_termination{false};
    bool structurally_consistent{true};
};

struct ManagementPostureInput final {
    ProviderEvidence domain_provider{};
    DomainMembership domain_membership{DomainMembership::Unknown};
    ProviderEvidence mdm_provider{};
    MdmRegistration mdm_registration{MdmRegistration::Unknown};
    ProviderEvidence local_group_policy_provider{};
    ProviderEvidence rsop_provider{};
    ProviderDiagnostics local_group_policy_diagnostics{};
    ProviderDiagnostics rsop_diagnostics{};
    std::array<bool, kFixedPolicyTargetCount> local_group_policy_matches{};
    std::array<bool, kFixedPolicyTargetCount> rsop_matches{};
};

struct TargetManagementEvidence final {
    FixedPolicyTarget target{FixedPolicyTarget::AutoRunDriveTypes};
    ManagementClassification classification{
        ManagementClassification::Ambiguous
    };
    bool local_group_policy_match{false};
    bool rsop_match{false};
};

struct ManagementPostureResult final {
    ManagementClassification classification{
        ManagementClassification::Ambiguous
    };
    ProviderEvidence domain_provider{};
    DomainMembership domain_membership{DomainMembership::Unknown};
    ProviderEvidence mdm_provider{};
    MdmRegistration mdm_registration{MdmRegistration::Unknown};
    ProviderEvidence local_group_policy_provider{};
    ProviderEvidence rsop_provider{};
    ProviderDiagnostics local_group_policy_diagnostics{};
    ProviderDiagnostics rsop_diagnostics{};
    std::array<TargetManagementEvidence, kFixedPolicyTargetCount> targets{};
    std::uint32_t limitations{ManagementLimitationNone};
};

struct LocalGroupPolicyApartmentDiagnostic final {
    ProviderEvidence mta_provider{};
    ProviderDiagnostics mta_diagnostics{};
    ProviderEvidence sta_provider{};
    ProviderDiagnostics sta_diagnostics{};
};

[[nodiscard]] bool IsProviderEvidenceConsistent(
    const ProviderEvidence& provider,
    bool freshness_is_applicable
) noexcept;

[[nodiscard]] bool IsLocalGroupPolicyDiagnosticConsistent(
    const ProviderEvidence& provider,
    const ProviderDiagnostics& diagnostics
) noexcept;

// Combines already-collected evidence. This is deliberately not a remediation
// eligibility decision. Managed and ambiguous results are both write blocks.
[[nodiscard]] ManagementPostureResult EvaluateManagementPosture(
    const ManagementPostureInput& input
) noexcept;

}  // namespace wincur::helper
