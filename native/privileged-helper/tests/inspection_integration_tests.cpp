#include "wincur/helper/windows_inspection.hpp"

#include <Windows.h>

#include <array>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <string_view>

namespace {

constexpr wchar_t kOptInVariable[] =
    L"WINCUR_RUN_READ_ONLY_INSPECTION_INTEGRATION";
constexpr wchar_t kOptInValue[] =
    L"DISPOSABLE_WINDOWS_11_VM_READ_ONLY_INSPECTION";

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

[[nodiscard]] bool ValidBoundedResult(
    const wincur::helper::InspectionResult& result
) {
    return !result.message_code.empty() && !result.display_message.empty() &&
           !result.verification_summary.empty() &&
           result.display_message.size() <=
               wincur::helper::kMaximumDisplayMessageCharacters &&
           result.verification_summary.size() <=
               wincur::helper::kMaximumVerificationSummaryCharacters;
}

}  // namespace

int wmain() {
    static_assert(
        wincur::helper::kInspectionRegistryView == KEY_WOW64_64KEY,
        "Inspection must remain pinned to the 64-bit registry view."
    );
    if (!HasExplicitOptIn()) {
        std::wcerr << L"Refusing read-only Windows inspection without the exact "
                      L"disposable-VM opt-in value.\n";
        return 77;
    }
    constexpr std::array actions{
        wincur::helper::ActionId::DisableAutoRun,
        wincur::helper::ActionId::EnablePowerShellLogging,
        wincur::helper::ActionId::EnableFirewallProfiles,
    };
    for (const auto action : actions) {
        const auto result = wincur::helper::InspectWindowsAction(action);
        if (!ValidBoundedResult(result)) {
            std::wcerr << L"A provider returned an invalid or unbounded result.\n";
            return EXIT_FAILURE;
        }
        std::wcout << static_cast<int>(action) << L": " << result.message_code
                   << L"\n";
    }
    std::wcout << L"Read-only native inspection completed; no result record or "
                   L"security configuration was written.\n";
    return EXIT_SUCCESS;
}
