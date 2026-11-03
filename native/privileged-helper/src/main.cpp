#include "wincur/helper/operation_mutex.hpp"
#include "wincur/helper/protocol.hpp"
#include "wincur/helper/stub_backend.hpp"
#include "wincur/helper/transaction.hpp"
#include "wincur/helper/windows_transaction_store.hpp"

#include <Windows.h>
#include <CommCtrl.h>
#include <Shellapi.h>

#include <cstddef>
#include <cwchar>
#include <span>
#include <string_view>
#include <vector>

namespace {

using wincur::helper::ExitCode;

[[nodiscard]] int ToExitCode(const ExitCode code) noexcept {
    return static_cast<int>(code);
}

void ShowNotImplemented() noexcept {
    TASKDIALOGCONFIG configuration{};
    configuration.cbSize = sizeof(configuration);
    configuration.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    configuration.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    configuration.pszWindowTitle = L"WinCur Privileged Helper";
    configuration.pszMainIcon = TD_INFORMATION_ICON;
    configuration.pszMainInstruction = L"NotImplemented";
    configuration.pszContent =
        L"This development helper contains no privileged operation backend. "
        L"No Windows security configuration was read or changed.";

    int selected_button = 0;
    TaskDialogIndirect(
        &configuration,
        &selected_button,
        nullptr,
        nullptr
    );
}

}  // namespace

int WINAPI wWinMain(
    HINSTANCE instance,
    HINSTANCE previous_instance,
    PWSTR command_line,
    int show_command
) {
    static_cast<void>(instance);
    static_cast<void>(previous_instance);
    static_cast<void>(command_line);
    static_cast<void>(show_command);

    try {
        const wchar_t* const raw_command_line = GetCommandLineW();
        if (raw_command_line == nullptr) {
            return ToExitCode(ExitCode::InternalError);
        }

        const std::size_t measured_length =
            wcsnlen_s(raw_command_line, wincur::helper::kMaximumCommandLineCodeUnits + 1);
        if (measured_length == 0 ||
            measured_length > wincur::helper::kMaximumCommandLineCodeUnits) {
            return ToExitCode(ExitCode::InvalidArguments);
        }

        int argument_count = 0;
        wchar_t** const argument_values =
            CommandLineToArgvW(raw_command_line, &argument_count);
        if (argument_values == nullptr || argument_count < 1) {
            if (argument_values != nullptr) {
                LocalFree(argument_values);
            }
            return ToExitCode(ExitCode::InvalidArguments);
        }

        std::vector<std::wstring_view> arguments;
        arguments.reserve(static_cast<std::size_t>(argument_count - 1));
        for (int index = 1; index < argument_count; ++index) {
            arguments.emplace_back(argument_values[index]);
        }

        const wincur::helper::ParseResult parse_result =
            wincur::helper::ParseArguments(arguments, measured_length);
        LocalFree(argument_values);

        if (parse_result.status == wincur::helper::ParseStatus::UnsupportedProtocol) {
            return ToExitCode(ExitCode::UnsupportedProtocol);
        }
        if (parse_result.status != wincur::helper::ParseStatus::Success ||
            !parse_result.request.has_value()) {
            return ToExitCode(ExitCode::InvalidArguments);
        }

        wincur::helper::OperationMutex operation_mutex;
        switch (operation_mutex.Acquire()) {
            case wincur::helper::MutexAcquireResult::Busy:
                return ToExitCode(ExitCode::Busy);
            case wincur::helper::MutexAcquireResult::Error:
                return ToExitCode(ExitCode::InternalError);
            case wincur::helper::MutexAcquireResult::Acquired:
                break;
        }

        const wincur::helper::BackendOutcome outcome =
            wincur::helper::ExecuteStub(*parse_result.request);
        if (outcome == wincur::helper::BackendOutcome::NotImplemented) {
            const std::wstring timestamp = wincur::helper::CurrentUtcTimestamp();
            if (timestamp.empty()) {
                return ToExitCode(ExitCode::InternalError);
            }
            const wincur::helper::TransactionResult result =
                wincur::helper::MakeNotImplementedResult(
                    *parse_result.request,
                    timestamp
                );
            wincur::helper::WindowsTransactionStorage storage;
            const wincur::helper::PersistStatus persist_status =
                wincur::helper::PersistTransactionResult(storage, result);
            if (persist_status != wincur::helper::PersistStatus::Success) {
                return ToExitCode(ExitCode::ProtectedStateError);
            }
            static_cast<void>(wincur::helper::PruneCompletedTransactionResults());
            ShowNotImplemented();
            return ToExitCode(ExitCode::Success);
        }

        return ToExitCode(ExitCode::InternalError);
    } catch (...) {
        return ToExitCode(ExitCode::InternalError);
    }
}
