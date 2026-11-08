#include "wincur/helper/windows_management_posture.hpp"
#include "wincur/helper/protocol.hpp"

#include <Windows.h>

#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <string_view>

namespace {

constexpr wchar_t kOptInVariable[] =
    L"WINCUR_RUN_READ_ONLY_POSTURE_INTEGRATION";
constexpr wchar_t kOptInValue[] =
    L"DISPOSABLE_WINDOWS_11_VM_READ_ONLY_POSTURE";

[[nodiscard]] bool HasExplicitOptIn() {
    wchar_t value[128]{};
    const DWORD length = GetEnvironmentVariableW(
        kOptInVariable,
        value,
        static_cast<DWORD>(std::size(value))
    );
    return length == std::wcslen(kOptInValue) &&
           std::wstring_view(value, length) == kOptInValue;
}

}  // namespace

void PrintProvider(
    const wchar_t* const name,
    const wincur::helper::ProviderEvidence& provider
) {
    std::wcout << name << L"-health=" << static_cast<int>(provider.health)
               << L" " << name << L"-complete=" << provider.complete
               << L" " << name << L"-freshness="
               << static_cast<int>(provider.freshness) << L" " << name
               << L"-error-dec=" << provider.error_code << L" " << name
               << L"-error-hex=0x" << std::hex << std::setw(8)
               << std::setfill(L'0') << provider.error_code << std::dec
               << std::setfill(L' ') << L" " << name << L"-consistent="
               << wincur::helper::IsProviderEvidenceConsistent(
                      provider,
                      std::wstring_view(name) == L"rsop"
                  )
               << L"\n";
}

void PrintDiagnostics(
    const wchar_t* const name,
    const wincur::helper::ProviderDiagnostics& diagnostics
) {
    std::wcout << name << L"-stage="
               << static_cast<int>(diagnostics.stage) << L" " << name
               << L"-raw-dec=" << diagnostics.raw_result << L" " << name
               << L"-raw-hex=0x" << std::hex << std::setw(8)
               << std::setfill(L'0') << diagnostics.raw_result << std::dec
               << std::setfill(L' ') << L" " << name << L"-returned="
               << diagnostics.returned_object_count << L" " << name
               << L"-normal-termination=" << diagnostics.normal_termination
               << L" " << name << L"-diagnostic-consistent="
               << diagnostics.structurally_consistent << L"\n";
}

int wmain() {
    if (!HasExplicitOptIn()) {
        std::wcerr << L"Refusing posture inspection without the exact "
                      L"disposable-VM opt-in value.\n";
        return 77;
    }
    std::wcout << L"build-identity="
               << wincur::helper::kManagementPostureBuildIdentity
               << L" helper-version=" << wincur::helper::kHelperVersion
               << L" protocol-version=" << wincur::helper::kProtocolVersion
               << L" provider-schema-version="
               << wincur::helper::kManagementPostureProviderSchemaVersion
               << L"\n";
    const auto result = wincur::helper::InspectWindowsManagementPosture();
    std::wcout << L"classification=" << static_cast<int>(result.classification)
               << L" domain=" << static_cast<int>(result.domain_membership)
               << L" mdm=" << static_cast<int>(result.mdm_registration)
               << L" limitations=" << result.limitations << L"\n";
    PrintProvider(L"domain", result.domain_provider);
    PrintProvider(L"mdm", result.mdm_provider);
    PrintProvider(L"local-gpo", result.local_group_policy_provider);
    PrintProvider(L"rsop", result.rsop_provider);
    PrintDiagnostics(
        L"local-gpo", result.local_group_policy_diagnostics);
    PrintDiagnostics(L"rsop", result.rsop_diagnostics);
    for (const auto& target : result.targets) {
        std::wcout << L"target=" << static_cast<int>(target.target)
                   << L" classification="
                   << static_cast<int>(target.classification)
                   << L" local-gpo=" << target.local_group_policy_match
                   << L" rsop=" << target.rsop_match << L"\n";
    }
    const auto apartments =
        wincur::helper::InspectLocalGroupPolicyApartmentsForDiagnostics();
    PrintProvider(L"local-gpo-mta", apartments.mta_provider);
    PrintDiagnostics(L"local-gpo-mta", apartments.mta_diagnostics);
    PrintProvider(L"local-gpo-sta", apartments.sta_provider);
    PrintDiagnostics(L"local-gpo-sta", apartments.sta_diagnostics);
    std::wcout << L"Read-only posture collection completed. No security "
                  L"configuration or protected transaction state was written.\n";
    return EXIT_SUCCESS;
}
