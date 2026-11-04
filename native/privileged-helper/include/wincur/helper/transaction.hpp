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
inline constexpr std::wstring_view kHelperBuildId = L"phase-2d-dev";
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

enum class TransactionLifecycle {
    Reserved,
    AwaitingConfirmation,
    Confirmed,
    Executing,
    Verifying,
    Completed,
    Interrupted,
    Failed,
};

struct TransactionReservation final {
    std::uint32_t schema_version{kTransactionSchemaVersion};
    std::uint32_t protocol_version{kProtocolVersion};
    std::wstring transaction_id;
    Operation operation{};
    std::optional<ActionId> action;
    std::optional<std::wstring> rollback_id;
    std::wstring helper_version;
    std::wstring build_id;
    std::wstring created_utc;
    std::wstring updated_utc;
    TransactionLifecycle lifecycle{TransactionLifecycle::Reserved};
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

enum class ReservationParseStatus {
    Success,
    Absent,
    Incomplete,
    Malformed,
};

struct ReservationParseResult final {
    ReservationParseStatus status{ReservationParseStatus::Malformed};
    std::optional<TransactionReservation> reservation;
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

enum class StorageOpenStatus {
    Opened,
    NotFound,
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
    [[nodiscard]] virtual StorageOpenStatus Open(
        std::wstring_view transaction_id
    ) noexcept {
        static_cast<void>(transaction_id);
        return StorageOpenStatus::Error;
    }
    [[nodiscard]] virtual bool Write(const TransactionValue& value) noexcept = 0;
    [[nodiscard]] virtual bool Flush() noexcept { return false; }
    [[nodiscard]] virtual bool Read(
        std::vector<TransactionValue>& values
    ) noexcept {
        static_cast<void>(values);
        return false;
    }
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

enum class ReservationStatus {
    Success,
    Duplicate,
    Untrusted,
    AccessDenied,
    InvalidRecord,
    PartialWrite,
    Error,
};

enum class TransitionStatus {
    Success,
    BindingMismatch,
    InvalidTransition,
    MalformedState,
    PartialWrite,
    Error,
};

[[nodiscard]] std::wstring_view OperationName(Operation operation) noexcept;
[[nodiscard]] std::wstring_view ActionName(ActionId action) noexcept;
[[nodiscard]] std::wstring_view OutcomeName(TransactionOutcome outcome) noexcept;
[[nodiscard]] std::wstring_view LifecycleName(
    TransactionLifecycle lifecycle
) noexcept;

[[nodiscard]] bool IsAllowedLifecycleTransition(
    TransactionLifecycle current,
    TransactionLifecycle next
) noexcept;

[[nodiscard]] TransactionReservation MakeTransactionReservation(
    const Request& request,
    std::wstring timestamp_utc
);

[[nodiscard]] std::optional<std::vector<TransactionValue>>
SerializeTransactionReservation(const TransactionReservation& reservation);

[[nodiscard]] ReservationParseResult ParseTransactionReservation(
    std::span<const TransactionValue> values,
    std::wstring_view expected_transaction_id
);

[[nodiscard]] bool ReservationMatchesRequest(
    const TransactionReservation& reservation,
    const Request& request
) noexcept;

[[nodiscard]] ReservationStatus ReserveTransaction(
    TransactionStorage& storage,
    const TransactionReservation& reservation
);

[[nodiscard]] TransitionStatus TransitionTransaction(
    TransactionStorage& storage,
    const Request& request,
    TransactionLifecycle expected,
    TransactionLifecycle next,
    std::wstring updated_utc
);

[[nodiscard]] PersistStatus FinalizeReservedTransaction(
    TransactionStorage& storage,
    const Request& request,
    const TransactionResult& result,
    TransactionLifecycle expected,
    TransactionLifecycle terminal,
    std::wstring updated_utc
);

[[nodiscard]] TransactionResult MakeInterruptedResult(
    const TransactionReservation& reservation,
    std::wstring timestamp_utc
);

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
