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
        L"No Windows security configuration was read or changed.";
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
