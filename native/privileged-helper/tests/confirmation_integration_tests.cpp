#include "wincur/helper/confirmation.hpp"
#include "wincur/helper/windows_confirmation.hpp"

#include <Windows.h>

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

constexpr wchar_t kOptInName[] =
    L"WINCUR_RUN_CONFIRMATION_INTEGRATION";
constexpr wchar_t kOptInValue[] =
    L"DISPOSABLE_WINDOWS_11_VM_NATIVE_DIALOG";

[[nodiscard]] bool HasExactOptIn() {
    wchar_t value[128]{};
    std::size_t required = 0;
    if (_wgetenv_s(&required, value, kOptInName) != 0 || required == 0 ||
        required > std::size(value)) {
        return false;
    }
    return std::wstring_view(value) == kOptInValue;
}

}  // namespace

int wmain() {
    if (!HasExactOptIn()) {
        std::wcerr << L"Refusing to display an elevated integration dialog. Set "
                   << kOptInName << L" to the documented disposable-VM value.\n";
        return 77;
    }

    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Apply;
    request.transaction_id = L"123e4567-e89b-12d3-a456-426614174000";
    request.action = wincur::helper::ActionId::DisableAutoRun;
    const auto prompt = wincur::helper::MakeConfirmationPrompt(
        request,
        wincur::helper::ActionId::DisableAutoRun,
        L"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    );
    if (!prompt.has_value()) {
        return 78;
    }

    wincur::helper::WindowsConfirmationPresenter presenter;
    const std::uint64_t challenge =
        wincur::helper::CreateConfirmationChallenge();
    if (challenge == 0) {
        return 79;
    }
    const auto receipt = presenter.Present(*prompt, challenge);
    wincur::helper::ConfirmationSession session(*prompt, challenge);
    const auto status = session.Consume(receipt);
    if (status == wincur::helper::AuthorizationStatus::Confirmed) {
        std::wcout << L"CONFIRMED: dialog binding validated; no setting was changed.\n";
        return 0;
    }
    if (status == wincur::helper::AuthorizationStatus::Cancelled) {
        std::wcout << L"CANCELLED: denial validated; no setting was changed.\n";
        return 10;
    }
    if (status == wincur::helper::AuthorizationStatus::TimedOut) {
        std::wcout << L"TIMED_OUT: denial validated; no setting was changed.\n";
        return 10;
    }
    std::wcout << L"DENIED: dialog or binding failure; no setting was changed.\n";
    return 14;
}
