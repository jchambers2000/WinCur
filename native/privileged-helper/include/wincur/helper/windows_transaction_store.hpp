#pragma once

#include "wincur/helper/transaction.hpp"

#include <Windows.h>

#include <optional>
#include <string>
#include <string_view>

namespace wincur::helper {

// Production code has one fixed namespace and accepts no caller- or
// build-supplied path. A separately compiled integration-test library can select
// exactly one fixed test namespace; it is never linked into the helper.
#ifdef WINCUR_TEST_REGISTRY_NAMESPACE
inline constexpr wchar_t kWinCurRegistryRootName[] = L"WinCurNativeHelperTests";
inline constexpr wchar_t kWinCurRegistryPath[] =
    L"SOFTWARE\\WinCurNativeHelperTests";
#else
inline constexpr wchar_t kWinCurRegistryRootName[] = L"WinCur";
inline constexpr wchar_t kWinCurRegistryPath[] = L"SOFTWARE\\WinCur";
#endif
inline constexpr wchar_t kTransactionsSubkey[] = L"Transactions";

class WindowsTransactionStorage final : public TransactionStorage {
public:
    WindowsTransactionStorage() noexcept = default;
    WindowsTransactionStorage(const WindowsTransactionStorage&) = delete;
    WindowsTransactionStorage& operator=(const WindowsTransactionStorage&) = delete;
    ~WindowsTransactionStorage() noexcept override;

    [[nodiscard]] StorageCreateStatus Begin(
        std::wstring_view transaction_id
    ) noexcept override;
    [[nodiscard]] bool Write(const TransactionValue& value) noexcept override;

private:
    HKEY transaction_key_{nullptr};
    bool complete_written_{false};
};

enum class RegistryReadStatus {
    Success,
    NotFound,
    Incomplete,
    Malformed,
    Untrusted,
    AccessDenied,
    Error,
};

struct RegistryReadResult final {
    RegistryReadStatus status{RegistryReadStatus::Error};
    std::optional<TransactionResult> result;
};

[[nodiscard]] RegistryReadResult ReadTransactionResultFromRegistry(
    std::wstring_view transaction_id
) noexcept;

[[nodiscard]] std::wstring CurrentUtcTimestamp();

// Deletes only validated, completed records beyond the count limit. Incomplete,
// malformed, untrusted, and active records are never deletion candidates.
[[nodiscard]] bool PruneCompletedTransactionResults(
    std::size_t maximum_completed = kMaximumCompletedTransactions
) noexcept;

}  // namespace wincur::helper
