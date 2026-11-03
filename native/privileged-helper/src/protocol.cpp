#include "wincur/helper/protocol.hpp"

#include <array>
#include <utility>

namespace wincur::helper {
namespace {

constexpr std::wstring_view kProtocolSwitch = L"--protocol";
constexpr std::wstring_view kOperationSwitch = L"--operation";
constexpr std::wstring_view kTransactionSwitch = L"--transaction";
constexpr std::wstring_view kActionSwitch = L"--action";
constexpr std::wstring_view kRollbackIdSwitch = L"--rollback-id";

[[nodiscard]] bool IsPrintableAscii(std::wstring_view value) noexcept {
    if (value.empty()) {
        return false;
    }
    for (const wchar_t character : value) {
        if (character < 0x21 || character > 0x7e) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool IsLowerHex(const wchar_t character) noexcept {
    return (character >= L'0' && character <= L'9') ||
           (character >= L'a' && character <= L'f');
}

[[nodiscard]] std::optional<Operation> ParseOperation(
    const std::wstring_view value
) noexcept {
    if (value == L"preview") {
        return Operation::Preview;
    }
    if (value == L"apply") {
        return Operation::Apply;
    }
    if (value == L"rollback") {
        return Operation::Rollback;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<ActionId> ParseAction(
    const std::wstring_view value
) noexcept {
    if (value == L"disable-autorun") {
        return ActionId::DisableAutoRun;
    }
    if (value == L"enable-powershell-logging") {
        return ActionId::EnablePowerShellLogging;
    }
    if (value == L"enable-firewall-profiles") {
        return ActionId::EnableFirewallProfiles;
    }
    return std::nullopt;
}

}  // namespace

bool IsCanonicalTransactionUuid(const std::wstring_view value) noexcept {
    if (value.size() != 36) {
        return false;
    }

    constexpr std::array<std::size_t, 4> kHyphenPositions{8, 13, 18, 23};
    bool has_nonzero_digit = false;

    for (std::size_t index = 0; index < value.size(); ++index) {
        bool is_hyphen_position = false;
        for (const std::size_t hyphen_position : kHyphenPositions) {
            if (index == hyphen_position) {
                is_hyphen_position = true;
                break;
            }
        }

        if (is_hyphen_position) {
            if (value[index] != L'-') {
                return false;
            }
            continue;
        }

        if (!IsLowerHex(value[index])) {
            return false;
        }
        has_nonzero_digit = has_nonzero_digit || value[index] != L'0';
    }

    return has_nonzero_digit;
}

ParseResult ParseArguments(
    const std::span<const std::wstring_view> arguments,
    const std::size_t complete_command_line_code_units
) {
    if (complete_command_line_code_units == 0 ||
        complete_command_line_code_units > kMaximumCommandLineCodeUnits) {
        return {};
    }

    for (const std::wstring_view argument : arguments) {
        if (!IsPrintableAscii(argument)) {
            return {};
        }
    }

    if (arguments.size() != 8 || arguments[0] != kProtocolSwitch) {
        return {};
    }

    if (arguments[1] != L"1") {
        return {ParseStatus::UnsupportedProtocol, std::nullopt};
    }

    if (arguments[2] != kOperationSwitch ||
        arguments[4] != kTransactionSwitch ||
        !IsCanonicalTransactionUuid(arguments[5])) {
        return {};
    }

    const std::optional<Operation> operation = ParseOperation(arguments[3]);
    if (!operation.has_value()) {
        return {};
    }

    Request request{};
    request.operation = *operation;
    request.transaction_id = std::wstring(arguments[5]);

    if (*operation == Operation::Rollback) {
        if (arguments[6] != kRollbackIdSwitch ||
            !IsCanonicalTransactionUuid(arguments[7])) {
            return {};
        }
        request.rollback_id = std::wstring(arguments[7]);
    } else {
        if (arguments[6] != kActionSwitch) {
            return {};
        }
        const std::optional<ActionId> action = ParseAction(arguments[7]);
        if (!action.has_value()) {
            return {};
        }
        request.action = *action;
    }

    return {ParseStatus::Success, std::move(request)};
}

}  // namespace wincur::helper
