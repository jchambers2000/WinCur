#include "wincur/helper/windows_confirmation.hpp"

#include <Windows.h>
#include <CommCtrl.h>
#include <bcrypt.h>

#include <array>
#include <string>

namespace wincur::helper {
namespace {

constexpr int kConfirmButtonId = 1001;

struct DialogState final {
    bool timed_out{false};
};

HRESULT CALLBACK DialogCallback(
    const HWND window,
    const UINT notification,
    const WPARAM parameter,
    const LPARAM,
    const LONG_PTR callback_data
) noexcept {
    if (notification == TDN_TIMER &&
        parameter >= kConfirmationTimeoutMilliseconds) {
        auto* const state = reinterpret_cast<DialogState*>(callback_data);
        if (state != nullptr) {
            state->timed_out = true;
        }
        SendMessageW(window, TDM_CLICK_BUTTON, IDCANCEL, 0);
    }
    return S_OK;
}

[[nodiscard]] std::wstring OperationLabel(const Operation operation) {
    return operation == Operation::Rollback ? L"Rollback" : L"Apply";
}

}  // namespace

ConfirmationReceipt WindowsConfirmationPresenter::Present(
    const ConfirmationPrompt& prompt,
    const std::uint64_t challenge
) noexcept {
    ConfirmationReceipt receipt{
        ConfirmationChoice::UiFailure,
        prompt.binding,
        challenge,
    };
    try {
        const std::wstring instruction =
            OperationLabel(prompt.binding.operation) + L": " +
            prompt.action_name;
        const std::wstring content =
            L"Proposed change\n" + prompt.proposed_change +
            L"\n\nAffected Windows setting\n" + prompt.affected_setting +
            L"\n\nSecurity implications\n" + prompt.security_implications +
            L"\n\nConfirm only if this exact action is expected. WinCur will revalidate the setting after confirmation.";

        const std::array<TASKDIALOG_BUTTON, 1> buttons{{
            {kConfirmButtonId, L"Confirm privileged action"},
        }};
        DialogState state{};
        TASKDIALOGCONFIG configuration{};
        configuration.cbSize = sizeof(configuration);
        configuration.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION |
                                TDF_CALLBACK_TIMER |
                                TDF_SIZE_TO_CONTENT |
                                TDF_POSITION_RELATIVE_TO_WINDOW;
        configuration.dwCommonButtons = TDCBF_CANCEL_BUTTON;
        configuration.pszWindowTitle = L"WinCur Privileged Confirmation";
        configuration.pszMainIcon = TD_WARNING_ICON;
        configuration.pszMainInstruction = instruction.c_str();
        configuration.pszContent = content.c_str();
        configuration.cButtons = static_cast<UINT>(buttons.size());
        configuration.pButtons = buttons.data();
        configuration.nDefaultButton = IDCANCEL;
        configuration.pfCallback = DialogCallback;
        configuration.lpCallbackData = reinterpret_cast<LONG_PTR>(&state);

        int selected = 0;
        const HRESULT result = TaskDialogIndirect(
            &configuration,
            &selected,
            nullptr,
            nullptr
        );
        if (FAILED(result)) {
            receipt.choice = ConfirmationChoice::UiFailure;
        } else if (state.timed_out) {
            receipt.choice = ConfirmationChoice::TimedOut;
        } else if (selected == kConfirmButtonId) {
            receipt.choice = ConfirmationChoice::Confirmed;
        } else {
            receipt.choice = ConfirmationChoice::Cancelled;
        }
    } catch (...) {
        receipt.choice = ConfirmationChoice::UiFailure;
    }
    return receipt;
}

std::uint64_t CreateConfirmationChallenge() noexcept {
    std::uint64_t challenge = 0;
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(&challenge),
        sizeof(challenge),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status < 0 || challenge == 0) {
        return 0;
    }
    return challenge;
}

}  // namespace wincur::helper
