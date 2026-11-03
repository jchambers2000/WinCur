#pragma once

#include "wincur/helper/protocol.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wincur::helper {

inline constexpr std::uint32_t kTransactionSchemaVersion = 1;
inline constexpr std::wstring_view kHelperBuildId = L"phase-2c2-dev";
inline constexpr std::size_t kMaximumDisplayMessageCharacters = 2048;
inline constexpr std::size_t kMaximumVerificationSummaryCharacters = 4096;
inline constexpr std::size_t kMaximumCompletedTransactions = 256;

enum class TransactionOutcome {
    Succeeded,
    Cancelled,
    AlreadyCompliant,
    BlockedManaged,
    BlockedAmbiguous,
    BlockedPrecondition,
    Failed,
    Partial,
    Interrupted,
};

struct TransactionResult final {
    std::uint32_t schema_version{kTransactionSchemaVersion};
    std::uint32_t protocol_version{kProtocolVersion};
    std::wstring transaction_id;
    Operation operation{};
    std::optional<ActionId> action;
    TransactionOutcome outcome{TransactionOutcome::Failed};
    std::wstring message_code;
    std::wstring display_message;
    std::wstring verification_summary;
    std::wstring helper_version;
    std::wstring build_id;
    std::wstring timestamp_utc;
    std::optional<std::wstring> rollback_id;
};

enum class TransactionValueType {
    Dword,
    String,
};

struct TransactionValue final {
    std::wstring name;
    TransactionValueType type{TransactionValueType::String};
    std::uint32_t dword_value{0};
    std::wstring string_value;
};

enum class TransactionParseStatus {
    Success,
    Incomplete,
    Malformed,
};

struct TransactionParseResult final {
    TransactionParseStatus status{TransactionParseStatus::Malformed};
    std::optional<TransactionResult> result;
};

enum class StorageCreateStatus {
    Created,
    Duplicate,
    Untrusted,
    AccessDenied,
    Error,
};

class TransactionStorage {
public:
    TransactionStorage() = default;
    TransactionStorage(const TransactionStorage&) = delete;
    TransactionStorage& operator=(const TransactionStorage&) = delete;
    virtual ~TransactionStorage() = default;

    [[nodiscard]] virtual StorageCreateStatus Begin(
        std::wstring_view transaction_id
    ) noexcept = 0;
    [[nodiscard]] virtual bool Write(const TransactionValue& value) noexcept = 0;
};

enum class PersistStatus {
    Success,
    Duplicate,
    Untrusted,
    AccessDenied,
    InvalidRecord,
    PartialWrite,
    Error,
};

[[nodiscard]] std::wstring_view OperationName(Operation operation) noexcept;
[[nodiscard]] std::wstring_view ActionName(ActionId action) noexcept;
[[nodiscard]] std::wstring_view OutcomeName(TransactionOutcome outcome) noexcept;

[[nodiscard]] TransactionResult MakeNotImplementedResult(
    const Request& request,
    std::wstring timestamp_utc
);

[[nodiscard]] std::optional<std::vector<TransactionValue>>
SerializeTransactionResult(const TransactionResult& result);

[[nodiscard]] TransactionParseResult ParseTransactionResult(
    std::span<const TransactionValue> values,
    std::wstring_view expected_transaction_id
);

[[nodiscard]] PersistStatus PersistTransactionResult(
    TransactionStorage& storage,
    const TransactionResult& result
);

}  // namespace wincur::helper
