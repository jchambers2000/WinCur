#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace wincur::helper {

inline constexpr unsigned int kProtocolVersion = 1;
inline constexpr std::wstring_view kHelperVersion = L"1.0.0";
inline constexpr std::size_t kMaximumCommandLineCodeUnits = 1024;

enum class Operation {
    Preview,
    Apply,
    Rollback,
};

enum class ActionId {
    DisableAutoRun,
    EnablePowerShellLogging,
    EnableFirewallProfiles,
};

enum class ParseStatus {
    Success,
    InvalidArguments,
    UnsupportedProtocol,
};

struct Request final {
    Operation operation{};
    std::wstring transaction_id;
    std::optional<ActionId> action;
    std::optional<std::wstring> rollback_id;
};

struct ParseResult final {
    ParseStatus status{ParseStatus::InvalidArguments};
    std::optional<Request> request;
};

[[nodiscard]] ParseResult ParseArguments(
    std::span<const std::wstring_view> arguments,
    std::size_t complete_command_line_code_units
);

[[nodiscard]] bool IsCanonicalTransactionUuid(std::wstring_view value) noexcept;

enum class ExitCode : int {
    Success = 0,
    UserCancelled = 10,
    InvalidArguments = 11,
    UnsupportedProtocol = 12,
    Blocked = 13,
    Failed = 14,
    Partial = 15,
    ProtectedStateError = 16,
    Busy = 17,
    InternalError = 18,
};

}  // namespace wincur::helper
