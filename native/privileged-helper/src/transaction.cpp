#include "wincur/helper/transaction.hpp"

#include <algorithm>
#include <array>
#include <cwctype>
#include <map>
#include <utility>

namespace wincur::helper {
namespace {

constexpr std::size_t kMaximumIdentifierCharacters = 64;
constexpr std::size_t kMaximumVersionCharacters = 32;
constexpr std::size_t kTimestampCharacters = 20;

[[nodiscard]] bool IsAsciiIdentifier(
    const std::wstring_view value,
    const std::size_t maximum_length
) noexcept {
    if (value.empty() || value.size() > maximum_length) {
        return false;
    }
    for (const wchar_t character : value) {
        const bool valid =
            (character >= L'a' && character <= L'z') ||
            (character >= L'A' && character <= L'Z') ||
            (character >= L'0' && character <= L'9') ||
            character == L'.' || character == L'-' || character == L'_';
        if (!valid) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool IsSafeDisplayText(
    const std::wstring_view value,
    const std::size_t maximum_length
) noexcept {
    if (value.size() > maximum_length) {
        return false;
    }
    for (const wchar_t character : value) {
        if (character == L'\0' ||
            (character < 0x20 && character != L'\r' &&
             character != L'\n' && character != L'\t') ||
            character == 0x7f) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool IsDottedVersion(const std::wstring_view value) noexcept {
    if (value.empty() || value.size() > kMaximumVersionCharacters) {
        return false;
    }
    bool previous_was_dot = true;
    unsigned int dot_count = 0;
    for (const wchar_t character : value) {
        if (character == L'.') {
            if (previous_was_dot) {
                return false;
            }
            previous_was_dot = true;
            ++dot_count;
        } else if (character >= L'0' && character <= L'9') {
            previous_was_dot = false;
        } else {
            return false;
        }
    }
    return !previous_was_dot && dot_count >= 1 && dot_count <= 3;
}

[[nodiscard]] bool IsUtcTimestamp(const std::wstring_view value) noexcept {
    if (value.size() != kTimestampCharacters || value[4] != L'-' ||
        value[7] != L'-' || value[10] != L'T' || value[13] != L':' ||
        value[16] != L':' || value[19] != L'Z') {
        return false;
    }
    constexpr std::array<std::size_t, 6> separators{4, 7, 10, 13, 16, 19};
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (std::find(separators.begin(), separators.end(), index) != separators.end()) {
            continue;
        }
        if (value[index] < L'0' || value[index] > L'9') {
            return false;
        }
    }
    const auto number = [&value](const std::size_t offset, const std::size_t count) {
        unsigned int result = 0;
        for (std::size_t index = 0; index < count; ++index) {
            result = result * 10U + static_cast<unsigned int>(value[offset + index] - L'0');
        }
        return result;
    };
    return number(0, 4) >= 2000U && number(5, 2) >= 1U && number(5, 2) <= 12U &&
           number(8, 2) >= 1U && number(8, 2) <= 31U && number(11, 2) <= 23U &&
           number(14, 2) <= 59U && number(17, 2) <= 60U;
}

[[nodiscard]] std::optional<Operation> ParseOperationName(
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

[[nodiscard]] std::optional<ActionId> ParseActionName(
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

[[nodiscard]] std::optional<TransactionOutcome> ParseOutcomeName(
    const std::wstring_view value
) noexcept {
    constexpr std::array<std::pair<std::wstring_view, TransactionOutcome>, 9> values{{
        {L"Succeeded", TransactionOutcome::Succeeded},
        {L"Cancelled", TransactionOutcome::Cancelled},
        {L"AlreadyCompliant", TransactionOutcome::AlreadyCompliant},
        {L"BlockedManaged", TransactionOutcome::BlockedManaged},
        {L"BlockedAmbiguous", TransactionOutcome::BlockedAmbiguous},
        {L"BlockedPrecondition", TransactionOutcome::BlockedPrecondition},
        {L"Failed", TransactionOutcome::Failed},
        {L"Partial", TransactionOutcome::Partial},
        {L"Interrupted", TransactionOutcome::Interrupted},
    }};
    for (const auto& [name, outcome] : values) {
        if (name == value) {
            return outcome;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<TransactionLifecycle> ParseLifecycleName(
    const std::wstring_view value
) noexcept {
    constexpr std::array<std::pair<std::wstring_view, TransactionLifecycle>, 8>
        values{{
            {L"Reserved", TransactionLifecycle::Reserved},
            {L"AwaitingConfirmation", TransactionLifecycle::AwaitingConfirmation},
            {L"Confirmed", TransactionLifecycle::Confirmed},
            {L"Executing", TransactionLifecycle::Executing},
            {L"Verifying", TransactionLifecycle::Verifying},
            {L"Completed", TransactionLifecycle::Completed},
            {L"Interrupted", TransactionLifecycle::Interrupted},
            {L"Failed", TransactionLifecycle::Failed},
        }};
    for (const auto& [name, lifecycle] : values) {
        if (name == value) {
            return lifecycle;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<MutationBoundary> ParseMutationBoundaryName(
    const std::wstring_view value
) noexcept {
    constexpr std::array<std::pair<std::wstring_view, MutationBoundary>, 5>
        values{{
            {L"MutationNotStarted", MutationBoundary::MutationNotStarted},
            {L"MutationMayHaveStarted", MutationBoundary::MutationMayHaveStarted},
            {L"MutationCompletedNotVerified",
             MutationBoundary::MutationCompletedNotVerified},
            {L"VerifiedCompletion", MutationBoundary::VerifiedCompletion},
            {L"InterruptedOrIndeterminate",
             MutationBoundary::InterruptedOrIndeterminate},
        }};
    for (const auto& [name, boundary] : values) {
        if (name == value) return boundary;
    }
    return std::nullopt;
}

[[nodiscard]] const TransactionValue* FindValue(
    const std::map<std::wstring, const TransactionValue*>& values,
    const wchar_t* const name
) noexcept {
    const auto iterator = values.find(name);
    return iterator == values.end() ? nullptr : iterator->second;
}

[[nodiscard]] bool ReadDword(
    const std::map<std::wstring, const TransactionValue*>& values,
    const wchar_t* const name,
    std::uint32_t& output
) noexcept {
    const TransactionValue* const value = FindValue(values, name);
    if (value == nullptr || value->type != TransactionValueType::Dword) {
        return false;
    }
    output = value->dword_value;
    return true;
}

[[nodiscard]] bool ReadString(
    const std::map<std::wstring, const TransactionValue*>& values,
    const wchar_t* const name,
    std::wstring& output
) {
    const TransactionValue* const value = FindValue(values, name);
    if (value == nullptr || value->type != TransactionValueType::String) {
        return false;
    }
    output = value->string_value;
    return true;
}

[[nodiscard]] TransactionValue DwordValue(
    std::wstring name,
    const std::uint32_t value
) {
    return {std::move(name), TransactionValueType::Dword, value, {}};
}

[[nodiscard]] TransactionValue StringValue(
    std::wstring name,
    std::wstring value
) {
    return {std::move(name), TransactionValueType::String, 0, std::move(value)};
}

}  // namespace

std::wstring_view OperationName(const Operation operation) noexcept {
    switch (operation) {
        case Operation::Preview:
            return L"preview";
        case Operation::Apply:
            return L"apply";
        case Operation::Rollback:
            return L"rollback";
    }
    return {};
}

std::wstring_view ActionName(const ActionId action) noexcept {
    switch (action) {
        case ActionId::DisableAutoRun:
            return L"disable-autorun";
        case ActionId::EnablePowerShellLogging:
            return L"enable-powershell-logging";
        case ActionId::EnableFirewallProfiles:
            return L"enable-firewall-profiles";
    }
    return {};
}

std::wstring_view OutcomeName(const TransactionOutcome outcome) noexcept {
    switch (outcome) {
        case TransactionOutcome::Succeeded:
            return L"Succeeded";
        case TransactionOutcome::Cancelled:
            return L"Cancelled";
        case TransactionOutcome::AlreadyCompliant:
            return L"AlreadyCompliant";
        case TransactionOutcome::BlockedManaged:
            return L"BlockedManaged";
        case TransactionOutcome::BlockedAmbiguous:
            return L"BlockedAmbiguous";
        case TransactionOutcome::BlockedPrecondition:
            return L"BlockedPrecondition";
        case TransactionOutcome::Failed:
            return L"Failed";
        case TransactionOutcome::Partial:
            return L"Partial";
        case TransactionOutcome::Interrupted:
            return L"Interrupted";
    }
    return {};
}

std::wstring_view LifecycleName(
    const TransactionLifecycle lifecycle
) noexcept {
    switch (lifecycle) {
        case TransactionLifecycle::Reserved:
            return L"Reserved";
        case TransactionLifecycle::AwaitingConfirmation:
            return L"AwaitingConfirmation";
        case TransactionLifecycle::Confirmed:
            return L"Confirmed";
        case TransactionLifecycle::Executing:
            return L"Executing";
        case TransactionLifecycle::Verifying:
            return L"Verifying";
        case TransactionLifecycle::Completed:
            return L"Completed";
        case TransactionLifecycle::Interrupted:
            return L"Interrupted";
        case TransactionLifecycle::Failed:
            return L"Failed";
    }
    return {};
}

std::wstring_view MutationBoundaryName(const MutationBoundary boundary) noexcept {
    switch (boundary) {
        case MutationBoundary::MutationNotStarted:
            return L"MutationNotStarted";
        case MutationBoundary::MutationMayHaveStarted:
            return L"MutationMayHaveStarted";
        case MutationBoundary::MutationCompletedNotVerified:
            return L"MutationCompletedNotVerified";
        case MutationBoundary::VerifiedCompletion:
            return L"VerifiedCompletion";
        case MutationBoundary::InterruptedOrIndeterminate:
            return L"InterruptedOrIndeterminate";
    }
    return {};
}

bool IsAllowedLifecycleTransition(
    const TransactionLifecycle current,
    const TransactionLifecycle next
) noexcept {
    if (next == TransactionLifecycle::Interrupted &&
        current != TransactionLifecycle::Interrupted) {
        return true;
    }
    switch (current) {
        case TransactionLifecycle::Reserved:
            return next == TransactionLifecycle::AwaitingConfirmation ||
                   next == TransactionLifecycle::Executing ||
                   next == TransactionLifecycle::Completed ||
                   next == TransactionLifecycle::Failed;
        case TransactionLifecycle::AwaitingConfirmation:
            return next == TransactionLifecycle::Confirmed ||
                   next == TransactionLifecycle::Completed ||
                   next == TransactionLifecycle::Failed;
        case TransactionLifecycle::Confirmed:
            return next == TransactionLifecycle::Executing ||
                   next == TransactionLifecycle::Completed ||
                   next == TransactionLifecycle::Failed;
        case TransactionLifecycle::Executing:
            return next == TransactionLifecycle::Verifying ||
                   next == TransactionLifecycle::Completed ||
                   next == TransactionLifecycle::Failed;
        case TransactionLifecycle::Verifying:
            return next == TransactionLifecycle::Completed ||
                   next == TransactionLifecycle::Failed;
        case TransactionLifecycle::Completed:
        case TransactionLifecycle::Interrupted:
        case TransactionLifecycle::Failed:
            return false;
    }
    return false;
}

TransactionReservation MakeTransactionReservation(
    const Request& request,
    std::wstring timestamp_utc
) {
    TransactionReservation reservation{};
    reservation.transaction_id = request.transaction_id;
    reservation.operation = request.operation;
    reservation.action = request.action;
    reservation.rollback_id = request.rollback_id;
    reservation.helper_version = std::wstring(kHelperVersion);
    reservation.build_id = std::wstring(kHelperBuildId);
    reservation.created_utc = timestamp_utc;
    reservation.updated_utc = std::move(timestamp_utc);
    return reservation;
}

std::optional<std::vector<TransactionValue>>
SerializeTransactionReservation(const TransactionReservation& reservation) {
    if (reservation.schema_version != kTransactionSchemaVersion ||
        reservation.protocol_version != kProtocolVersion ||
        !IsCanonicalTransactionUuid(reservation.transaction_id) ||
        OperationName(reservation.operation).empty() ||
        (reservation.operation != Operation::Rollback &&
         !reservation.action.has_value()) ||
        (reservation.action.has_value() &&
         ActionName(*reservation.action).empty()) ||
        (reservation.operation == Operation::Rollback &&
         (!reservation.rollback_id.has_value() ||
          reservation.action.has_value())) ||
        (reservation.operation != Operation::Rollback &&
         reservation.rollback_id.has_value()) ||
        (reservation.rollback_id.has_value() &&
         !IsCanonicalTransactionUuid(*reservation.rollback_id)) ||
        (reservation.capsule_id.has_value() &&
         (reservation.operation != Operation::Apply ||
          !IsCanonicalTransactionUuid(*reservation.capsule_id))) ||
        (!reservation.capsule_id.has_value() &&
         reservation.mutation_boundary != MutationBoundary::MutationNotStarted) ||
        MutationBoundaryName(reservation.mutation_boundary).empty() ||
        !IsDottedVersion(reservation.helper_version) ||
        !IsAsciiIdentifier(reservation.build_id, kMaximumIdentifierCharacters) ||
        !IsUtcTimestamp(reservation.created_utc) ||
        !IsUtcTimestamp(reservation.updated_utc) ||
        LifecycleName(reservation.lifecycle).empty()) {
        return std::nullopt;
    }

    std::vector<TransactionValue> values;
    values.reserve(15);
    values.push_back(DwordValue(
        L"ReservationSchemaVersion",
        reservation.schema_version
    ));
    values.push_back(DwordValue(
        L"ReservationProtocolVersion",
        reservation.protocol_version
    ));
    values.push_back(StringValue(
        L"ReservationTransactionId",
        reservation.transaction_id
    ));
    values.push_back(StringValue(
        L"ReservationOperation",
        std::wstring(OperationName(reservation.operation))
    ));
    if (reservation.action.has_value()) {
        values.push_back(StringValue(
            L"ReservationActionId",
            std::wstring(ActionName(*reservation.action))
        ));
    }
    if (reservation.rollback_id.has_value()) {
        values.push_back(StringValue(
            L"ReservationRollbackId",
            *reservation.rollback_id
        ));
    }
    values.push_back(StringValue(
        L"ReservationHelperVersion",
        reservation.helper_version
    ));
    values.push_back(StringValue(L"ReservationBuildId", reservation.build_id));
    values.push_back(StringValue(
        L"ReservationCreatedUtc",
        reservation.created_utc
    ));
    values.push_back(StringValue(
        L"ReservationUpdatedUtc",
        reservation.updated_utc
    ));
    values.push_back(StringValue(
        L"Lifecycle",
        std::wstring(LifecycleName(reservation.lifecycle))
    ));
    if (reservation.capsule_id.has_value()) {
        values.push_back(StringValue(
            L"ReservationCapsuleId",
            *reservation.capsule_id
        ));
        values.push_back(StringValue(
            L"MutationBoundary",
            std::wstring(MutationBoundaryName(reservation.mutation_boundary))
        ));
        values.push_back(DwordValue(L"CapsuleBindingComplete", 1));
    }
    values.push_back(DwordValue(L"ReservationComplete", 1));
    return values;
}

ReservationParseResult ParseTransactionReservation(
    const std::span<const TransactionValue> values,
    const std::wstring_view expected_transaction_id
) {
    std::map<std::wstring, const TransactionValue*> by_name;
    bool has_reservation_value = false;
    std::size_t reservation_value_count = 0;
    constexpr std::array<std::wstring_view, 15> allowed_names{
        L"ReservationSchemaVersion", L"ReservationProtocolVersion",
        L"ReservationTransactionId", L"ReservationOperation",
        L"ReservationActionId", L"ReservationRollbackId",
        L"ReservationHelperVersion", L"ReservationBuildId",
        L"ReservationCreatedUtc", L"ReservationUpdatedUtc", L"Lifecycle",
        L"ReservationComplete", L"ReservationCapsuleId",
        L"MutationBoundary", L"CapsuleBindingComplete",
    };
    for (const TransactionValue& value : values) {
        const bool reservation_name =
            std::find(allowed_names.begin(), allowed_names.end(), value.name) !=
            allowed_names.end();
        const bool reservation_prefix =
            value.name.starts_with(L"Reservation") || value.name == L"Lifecycle" ||
            value.name == L"MutationBoundary" ||
            value.name == L"CapsuleBindingComplete";
        if (!reservation_name) {
            if (reservation_prefix) {
                return {};
            }
            continue;
        }
        has_reservation_value = true;
        ++reservation_value_count;
        if (!by_name.emplace(value.name, &value).second) {
            return {};
        }
    }
    if (!has_reservation_value) {
        return {ReservationParseStatus::Absent, std::nullopt};
    }
    const TransactionValue* const complete =
        FindValue(by_name, L"ReservationComplete");
    if (complete == nullptr) {
        return {ReservationParseStatus::Incomplete, std::nullopt};
    }
    if (complete->type != TransactionValueType::Dword ||
        complete->dword_value != 1) {
        return {};
    }
    const bool has_any_capsule_binding =
        FindValue(by_name, L"ReservationCapsuleId") != nullptr ||
        FindValue(by_name, L"MutationBoundary") != nullptr ||
        FindValue(by_name, L"CapsuleBindingComplete") != nullptr;
    if (has_any_capsule_binding) {
        const TransactionValue* const binding_complete =
            FindValue(by_name, L"CapsuleBindingComplete");
        if (binding_complete == nullptr) {
            return {ReservationParseStatus::Incomplete, std::nullopt};
        }
        if (binding_complete->type != TransactionValueType::Dword ||
            binding_complete->dword_value != 1) {
            return {};
        }
    }

    TransactionReservation reservation{};
    std::wstring operation_name;
    std::wstring lifecycle_name;
    if (!ReadDword(
            by_name,
            L"ReservationSchemaVersion",
            reservation.schema_version
        ) ||
        !ReadDword(
            by_name,
            L"ReservationProtocolVersion",
            reservation.protocol_version
        ) ||
        !ReadString(
            by_name,
            L"ReservationTransactionId",
            reservation.transaction_id
        ) ||
        !ReadString(by_name, L"ReservationOperation", operation_name) ||
        !ReadString(
            by_name,
            L"ReservationHelperVersion",
            reservation.helper_version
        ) ||
        !ReadString(by_name, L"ReservationBuildId", reservation.build_id) ||
        !ReadString(
            by_name,
            L"ReservationCreatedUtc",
            reservation.created_utc
        ) ||
        !ReadString(
            by_name,
            L"ReservationUpdatedUtc",
            reservation.updated_utc
        ) ||
        !ReadString(by_name, L"Lifecycle", lifecycle_name)) {
        return {};
    }
    const auto operation = ParseOperationName(operation_name);
    const auto lifecycle = ParseLifecycleName(lifecycle_name);
    if (!operation.has_value() || !lifecycle.has_value()) {
        return {};
    }
    reservation.operation = *operation;
    reservation.lifecycle = *lifecycle;
    if (const TransactionValue* const action =
            FindValue(by_name, L"ReservationActionId")) {
        if (action->type != TransactionValueType::String) {
            return {};
        }
        reservation.action = ParseActionName(action->string_value);
        if (!reservation.action.has_value()) {
            return {};
        }
    }
    if (const TransactionValue* const rollback =
            FindValue(by_name, L"ReservationRollbackId")) {
        if (rollback->type != TransactionValueType::String) {
            return {};
        }
        reservation.rollback_id = rollback->string_value;
    }
    if (has_any_capsule_binding) {
        std::wstring boundary_name;
        reservation.capsule_id.emplace();
        if (!ReadString(by_name, L"ReservationCapsuleId",
                        *reservation.capsule_id) ||
            !ReadString(by_name, L"MutationBoundary", boundary_name)) {
            return {};
        }
        const auto boundary = ParseMutationBoundaryName(boundary_name);
        if (!boundary.has_value()) return {};
        reservation.mutation_boundary = *boundary;
    }
    const auto canonical = SerializeTransactionReservation(reservation);
    if (!canonical.has_value() ||
        reservation.transaction_id != expected_transaction_id ||
        canonical->size() != reservation_value_count) {
        return {};
    }
    return {ReservationParseStatus::Success, std::move(reservation)};
}

bool ReservationMatchesRequest(
    const TransactionReservation& reservation,
    const Request& request
) noexcept {
    return reservation.transaction_id == request.transaction_id &&
           reservation.operation == request.operation &&
           reservation.action == request.action &&
           reservation.rollback_id == request.rollback_id;
}

ReservationStatus ReserveTransaction(
    TransactionStorage& storage,
    const TransactionReservation& reservation
) {
    const auto values = SerializeTransactionReservation(reservation);
    if (!values.has_value()) {
        return ReservationStatus::InvalidRecord;
    }
    switch (storage.Begin(reservation.transaction_id)) {
        case StorageCreateStatus::Created:
            break;
        case StorageCreateStatus::Duplicate:
            return ReservationStatus::Duplicate;
        case StorageCreateStatus::Untrusted:
            return ReservationStatus::Untrusted;
        case StorageCreateStatus::AccessDenied:
            return ReservationStatus::AccessDenied;
        case StorageCreateStatus::Error:
            return ReservationStatus::Error;
    }
    for (std::size_t index = 0; index + 1 < values->size(); ++index) {
        if (!storage.Write((*values)[index])) {
            return ReservationStatus::PartialWrite;
        }
    }
    if (!storage.Flush() || !storage.Write(values->back()) || !storage.Flush()) {
        return ReservationStatus::PartialWrite;
    }
    return ReservationStatus::Success;
}

TransitionStatus TransitionTransaction(
    TransactionStorage& storage,
    const Request& request,
    const TransactionLifecycle expected,
    const TransactionLifecycle next,
    std::wstring updated_utc
) {
    if (!IsUtcTimestamp(updated_utc) ||
        !IsAllowedLifecycleTransition(expected, next)) {
        return TransitionStatus::InvalidTransition;
    }
    std::vector<TransactionValue> values;
    if (!storage.Read(values)) {
        return TransitionStatus::Error;
    }
    const auto parsed = ParseTransactionReservation(values, request.transaction_id);
    if (parsed.status != ReservationParseStatus::Success ||
        !parsed.reservation.has_value()) {
        return TransitionStatus::MalformedState;
    }
    if (!ReservationMatchesRequest(*parsed.reservation, request)) {
        return TransitionStatus::BindingMismatch;
    }
    if (parsed.reservation->lifecycle != expected) {
        return TransitionStatus::InvalidTransition;
    }
    const bool apply_requires_capsule =
        request.operation == Operation::Apply &&
        (next == TransactionLifecycle::AwaitingConfirmation ||
         next == TransactionLifecycle::Confirmed ||
         next == TransactionLifecycle::Executing ||
         next == TransactionLifecycle::Verifying);
    if (apply_requires_capsule &&
        !parsed.reservation->capsule_id.has_value()) {
        return TransitionStatus::InvalidTransition;
    }
    if (request.operation == Operation::Apply &&
        next == TransactionLifecycle::Executing &&
        expected != TransactionLifecycle::Confirmed) {
        return TransitionStatus::InvalidTransition;
    }
    if (!storage.Write(StringValue(
            L"ReservationUpdatedUtc",
            std::move(updated_utc)
        )) ||
        !storage.Write(StringValue(L"Lifecycle", std::wstring(LifecycleName(next)))) ||
        !storage.Flush()) {
        return TransitionStatus::PartialWrite;
    }
    return TransitionStatus::Success;
}

CapsuleBindingStatus BindCapsuleToTransaction(
    TransactionStorage& storage,
    const Request& request,
    const std::wstring_view capsule_id,
    std::wstring updated_utc
) {
    if (request.operation != Operation::Apply || !request.action.has_value() ||
        !IsCanonicalTransactionUuid(capsule_id) || !IsUtcTimestamp(updated_utc)) {
        return CapsuleBindingStatus::InvalidState;
    }
    std::vector<TransactionValue> values;
    if (!storage.Read(values)) return CapsuleBindingStatus::Error;
    const auto parsed = ParseTransactionReservation(values, request.transaction_id);
    if (parsed.status != ReservationParseStatus::Success ||
        !parsed.reservation.has_value()) {
        return CapsuleBindingStatus::MalformedState;
    }
    if (!ReservationMatchesRequest(*parsed.reservation, request))
        return CapsuleBindingStatus::BindingMismatch;
    if (parsed.reservation->capsule_id.has_value())
        return *parsed.reservation->capsule_id == capsule_id
                   ? CapsuleBindingStatus::Duplicate
                   : CapsuleBindingStatus::BindingMismatch;
    if (parsed.reservation->lifecycle != TransactionLifecycle::Reserved)
        return CapsuleBindingStatus::InvalidState;

    if (!storage.Write(StringValue(L"ReservationCapsuleId",
                                   std::wstring(capsule_id))) ||
        !storage.Write(StringValue(
            L"MutationBoundary",
            std::wstring(MutationBoundaryName(MutationBoundary::MutationNotStarted)))) ||
        !storage.Write(StringValue(L"ReservationUpdatedUtc", updated_utc)) ||
        !storage.Flush() ||
        !storage.Write(DwordValue(L"CapsuleBindingComplete", 1)) ||
        !storage.Flush()) {
        return CapsuleBindingStatus::PartialWrite;
    }
    return ValidateTransactionCapsuleBinding(storage, request, capsule_id);
}

CapsuleBindingStatus ValidateTransactionCapsuleBinding(
    TransactionStorage& storage,
    const Request& request,
    const std::wstring_view capsule_id
) {
    std::vector<TransactionValue> values;
    if (!storage.Read(values)) return CapsuleBindingStatus::Error;
    const auto parsed = ParseTransactionReservation(values, request.transaction_id);
    if (parsed.status != ReservationParseStatus::Success ||
        !parsed.reservation.has_value()) {
        return CapsuleBindingStatus::MalformedState;
    }
    if (!ReservationMatchesRequest(*parsed.reservation, request) ||
        !parsed.reservation->capsule_id.has_value() ||
        *parsed.reservation->capsule_id != capsule_id) {
        return CapsuleBindingStatus::BindingMismatch;
    }
    return CapsuleBindingStatus::Success;
}

TransitionStatus UpdateMutationBoundary(
    TransactionStorage& storage,
    const Request& request,
    const std::wstring_view capsule_id,
    const MutationBoundary expected,
    const MutationBoundary next,
    std::wstring updated_utc
) {
    const bool allowed =
        (expected == MutationBoundary::MutationNotStarted &&
         next == MutationBoundary::MutationMayHaveStarted) ||
        (expected == MutationBoundary::MutationMayHaveStarted &&
         next == MutationBoundary::MutationCompletedNotVerified) ||
        (expected == MutationBoundary::MutationCompletedNotVerified &&
         next == MutationBoundary::VerifiedCompletion) ||
        (next == MutationBoundary::InterruptedOrIndeterminate &&
         expected != MutationBoundary::VerifiedCompletion);
    if (!allowed || !IsUtcTimestamp(updated_utc))
        return TransitionStatus::InvalidTransition;
    std::vector<TransactionValue> values;
    if (!storage.Read(values)) return TransitionStatus::Error;
    const auto parsed = ParseTransactionReservation(values, request.transaction_id);
    if (parsed.status != ReservationParseStatus::Success ||
        !parsed.reservation.has_value()) return TransitionStatus::MalformedState;
    if (!ReservationMatchesRequest(*parsed.reservation, request) ||
        !parsed.reservation->capsule_id.has_value() ||
        *parsed.reservation->capsule_id != capsule_id)
        return TransitionStatus::BindingMismatch;
    if (parsed.reservation->mutation_boundary != expected)
        return TransitionStatus::InvalidTransition;
    if (!storage.Write(StringValue(L"MutationBoundary",
                                   std::wstring(MutationBoundaryName(next)))) ||
        !storage.Write(StringValue(L"ReservationUpdatedUtc",
                                   std::move(updated_utc))) ||
        !storage.Flush()) return TransitionStatus::PartialWrite;
    return TransitionStatus::Success;
}

RecoveryDisposition ClassifyRecoveryDisposition(
    const TransactionReservation& reservation,
    const bool capsule_is_valid
) noexcept {
    static_cast<void>(capsule_is_valid);
    return reservation.mutation_boundary == MutationBoundary::MutationNotStarted
               ? RecoveryDisposition::TerminalizePreMutation
               : RecoveryDisposition::PreserveIndeterminate;
}

PersistStatus FinalizeReservedTransaction(
    TransactionStorage& storage,
    const Request& request,
    const TransactionResult& result,
    const TransactionLifecycle expected,
    const TransactionLifecycle terminal,
    std::wstring updated_utc
) {
    if (terminal != TransactionLifecycle::Completed &&
        terminal != TransactionLifecycle::Interrupted &&
        terminal != TransactionLifecycle::Failed) {
        return PersistStatus::InvalidRecord;
    }
    std::vector<TransactionValue> current_values;
    if (!storage.Read(current_values)) {
        return PersistStatus::Error;
    }
    const auto reservation =
        ParseTransactionReservation(current_values, request.transaction_id);
    if (reservation.status != ReservationParseStatus::Success ||
        !reservation.reservation.has_value() ||
        !ReservationMatchesRequest(*reservation.reservation, request) ||
        reservation.reservation->lifecycle != expected ||
        (!IsAllowedLifecycleTransition(expected, terminal) &&
         !(expected == TransactionLifecycle::Interrupted &&
           terminal == TransactionLifecycle::Interrupted)) ||
        !IsUtcTimestamp(updated_utc) ||
        result.transaction_id != request.transaction_id ||
        result.operation != request.operation || result.action != request.action ||
        result.rollback_id != request.rollback_id) {
        return PersistStatus::InvalidRecord;
    }
    if (request.operation == Operation::Apply &&
        (expected == TransactionLifecycle::AwaitingConfirmation ||
         expected == TransactionLifecycle::Confirmed ||
         expected == TransactionLifecycle::Executing ||
         expected == TransactionLifecycle::Verifying) &&
        !reservation.reservation->capsule_id.has_value()) {
        return PersistStatus::InvalidRecord;
    }
    const auto result_values = SerializeTransactionResult(result);
    if (!result_values.has_value()) {
        return PersistStatus::InvalidRecord;
    }
    for (std::size_t index = 0; index + 1 < result_values->size(); ++index) {
        if (!storage.Write((*result_values)[index])) {
            return PersistStatus::PartialWrite;
        }
    }
    if (!storage.Write(StringValue(
            L"ReservationUpdatedUtc",
            std::move(updated_utc)
        )) ||
        !storage.Write(StringValue(
            L"Lifecycle",
            std::wstring(LifecycleName(terminal))
        )) ||
        !storage.Flush() || !storage.Write(result_values->back()) ||
        !storage.Flush()) {
        return PersistStatus::PartialWrite;
    }
    return PersistStatus::Success;
}

TransactionResult MakeInterruptedResult(
    const TransactionReservation& reservation,
    std::wstring timestamp_utc
) {
    TransactionResult result{};
    result.transaction_id = reservation.transaction_id;
    result.operation = reservation.operation;
    result.action = reservation.action;
    result.rollback_id = reservation.rollback_id;
    result.outcome = TransactionOutcome::Interrupted;
    result.message_code = L"RecoveredInterrupted";
    result.display_message =
        L"A prior helper operation ended before a complete result was recorded.";
    result.verification_summary = reservation.mutation_boundary ==
                                          MutationBoundary::MutationNotStarted
        ? (reservation.capsule_id.has_value()
               ? L"The protected capsule was bound, but the mutation boundary was not crossed. The operation was not retried."
               : L"No protected capsule was bound and the mutation boundary was not crossed. The operation was not retried.")
        : L"The mutation boundary is indeterminate. The operation was not retried or rolled back, and no success is inferred.";
    result.helper_version = std::wstring(kHelperVersion);
    result.build_id = std::wstring(kHelperBuildId);
    result.timestamp_utc = std::move(timestamp_utc);
    return result;
}

TransactionResult MakeNotImplementedResult(
    const Request& request,
    std::wstring timestamp_utc
) {
    TransactionResult result{};
    result.transaction_id = request.transaction_id;
    result.operation = request.operation;
    result.action = request.action;
    result.outcome = TransactionOutcome::Failed;
    result.message_code = L"NotImplemented";
    result.display_message =
        L"This development helper contains no privileged operation backend.";
    result.verification_summary =
        L"Read-only prerequisites were evaluated, but no Windows security configuration was changed.";
    result.helper_version = std::wstring(kHelperVersion);
    result.build_id = std::wstring(kHelperBuildId);
    result.timestamp_utc = std::move(timestamp_utc);
    result.rollback_id = request.rollback_id;
    return result;
}

std::optional<std::vector<TransactionValue>> SerializeTransactionResult(
    const TransactionResult& result
) {
    if (result.schema_version != kTransactionSchemaVersion ||
        result.protocol_version != kProtocolVersion ||
        !IsCanonicalTransactionUuid(result.transaction_id) ||
        OperationName(result.operation).empty() ||
        (result.operation != Operation::Rollback && !result.action.has_value()) ||
        (result.action.has_value() && ActionName(*result.action).empty()) ||
        OutcomeName(result.outcome).empty() ||
        !IsAsciiIdentifier(result.message_code, kMaximumIdentifierCharacters) ||
        !IsSafeDisplayText(result.display_message, kMaximumDisplayMessageCharacters) ||
        !IsSafeDisplayText(
            result.verification_summary,
            kMaximumVerificationSummaryCharacters
        ) ||
        !IsDottedVersion(result.helper_version) ||
        !IsAsciiIdentifier(result.build_id, kMaximumIdentifierCharacters) ||
        !IsUtcTimestamp(result.timestamp_utc) ||
        (result.operation == Operation::Rollback &&
         !result.rollback_id.has_value()) ||
        (result.operation != Operation::Rollback &&
         result.rollback_id.has_value()) ||
        (result.rollback_id.has_value() &&
         !IsCanonicalTransactionUuid(*result.rollback_id))) {
        return std::nullopt;
    }

    std::vector<TransactionValue> values;
    values.reserve(14);
    values.push_back(DwordValue(L"SchemaVersion", result.schema_version));
    values.push_back(DwordValue(L"ProtocolVersion", result.protocol_version));
    values.push_back(StringValue(L"TransactionId", result.transaction_id));
    values.push_back(StringValue(L"Operation", std::wstring(OperationName(result.operation))));
    if (result.action.has_value()) {
        values.push_back(StringValue(L"ActionId", std::wstring(ActionName(*result.action))));
    }
    values.push_back(StringValue(L"Outcome", std::wstring(OutcomeName(result.outcome))));
    values.push_back(StringValue(L"MessageCode", result.message_code));
    values.push_back(StringValue(L"DisplayMessage", result.display_message));
    values.push_back(StringValue(L"VerificationSummary", result.verification_summary));
    values.push_back(StringValue(L"HelperVersion", result.helper_version));
    values.push_back(StringValue(L"BuildId", result.build_id));
    values.push_back(StringValue(L"TimestampUtc", result.timestamp_utc));
    if (result.rollback_id.has_value()) {
        values.push_back(StringValue(L"RollbackId", *result.rollback_id));
    }
    values.push_back(DwordValue(L"Complete", 1));
    return values;
}

TransactionParseResult ParseTransactionResult(
    const std::span<const TransactionValue> values,
    const std::wstring_view expected_transaction_id
) {
    std::map<std::wstring, const TransactionValue*> by_name;
    for (const TransactionValue& value : values) {
        if (value.name.empty() || value.name.size() > kMaximumIdentifierCharacters ||
            !by_name.emplace(value.name, &value).second) {
            return {};
        }
    }

    const TransactionValue* const completion = FindValue(by_name, L"Complete");
    if (completion == nullptr) {
        return {TransactionParseStatus::Incomplete, std::nullopt};
    }
    if (completion->type != TransactionValueType::Dword ||
        completion->dword_value != 1) {
        return {};
    }

    constexpr std::array<std::wstring_view, 14> allowed_names{
        L"SchemaVersion", L"ProtocolVersion", L"TransactionId", L"Operation",
        L"ActionId", L"Outcome", L"MessageCode", L"DisplayMessage",
        L"VerificationSummary", L"HelperVersion", L"BuildId", L"TimestampUtc",
        L"RollbackId", L"Complete",
    };
    for (const auto& [name, value] : by_name) {
        static_cast<void>(value);
        if (std::find(allowed_names.begin(), allowed_names.end(), name) ==
            allowed_names.end()) {
            return {};
        }
    }

    TransactionResult result{};
    std::wstring operation_name;
    std::wstring outcome_name;
    if (!ReadDword(by_name, L"SchemaVersion", result.schema_version) ||
        !ReadDword(by_name, L"ProtocolVersion", result.protocol_version) ||
        !ReadString(by_name, L"TransactionId", result.transaction_id) ||
        !ReadString(by_name, L"Operation", operation_name) ||
        !ReadString(by_name, L"Outcome", outcome_name) ||
        !ReadString(by_name, L"MessageCode", result.message_code) ||
        !ReadString(by_name, L"DisplayMessage", result.display_message) ||
        !ReadString(by_name, L"VerificationSummary", result.verification_summary) ||
        !ReadString(by_name, L"HelperVersion", result.helper_version) ||
        !ReadString(by_name, L"BuildId", result.build_id) ||
        !ReadString(by_name, L"TimestampUtc", result.timestamp_utc)) {
        return {};
    }

    const auto operation = ParseOperationName(operation_name);
    const auto outcome = ParseOutcomeName(outcome_name);
    if (!operation.has_value() || !outcome.has_value()) {
        return {};
    }
    result.operation = *operation;
    result.outcome = *outcome;

    if (const TransactionValue* const action = FindValue(by_name, L"ActionId")) {
        if (action->type != TransactionValueType::String) {
            return {};
        }
        result.action = ParseActionName(action->string_value);
        if (!result.action.has_value()) {
            return {};
        }
    }
    if (const TransactionValue* const rollback = FindValue(by_name, L"RollbackId")) {
        if (rollback->type != TransactionValueType::String) {
            return {};
        }
        result.rollback_id = rollback->string_value;
    }

    const auto canonical = SerializeTransactionResult(result);
    if (!canonical.has_value() || result.transaction_id != expected_transaction_id ||
        canonical->size() != values.size()) {
        return {};
    }
    return {TransactionParseStatus::Success, std::move(result)};
}

PersistStatus PersistTransactionResult(
    TransactionStorage& storage,
    const TransactionResult& result
) {
    const auto values = SerializeTransactionResult(result);
    if (!values.has_value()) {
        return PersistStatus::InvalidRecord;
    }

    switch (storage.Begin(result.transaction_id)) {
        case StorageCreateStatus::Created:
            break;
        case StorageCreateStatus::Duplicate:
            return PersistStatus::Duplicate;
        case StorageCreateStatus::Untrusted:
            return PersistStatus::Untrusted;
        case StorageCreateStatus::AccessDenied:
            return PersistStatus::AccessDenied;
        case StorageCreateStatus::Error:
            return PersistStatus::Error;
    }

    for (const TransactionValue& value : *values) {
        if (!storage.Write(value)) {
            return PersistStatus::PartialWrite;
        }
    }
    return PersistStatus::Success;
}

}  // namespace wincur::helper
