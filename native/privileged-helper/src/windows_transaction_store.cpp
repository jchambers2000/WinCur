#include "wincur/helper/windows_transaction_store.hpp"

#include "wincur/helper/registry_security.hpp"

#include <Sddl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace wincur::helper {
namespace {

constexpr wchar_t kSoftwareSubkey[] = L"SOFTWARE";
constexpr DWORD kMaximumSecurityDescriptorBytes = 64U * 1024U;
constexpr DWORD kMaximumRegistryValues = 32;
constexpr DWORD kMaximumValueNameCharacters = 64;
constexpr DWORD kMaximumValueDataBytes =
    static_cast<DWORD>((kMaximumVerificationSummaryCharacters + 1) * sizeof(wchar_t));
constexpr DWORD kMaximumEnumeratedTransactions = 4096;

class UniqueRegistryKey final {
public:
    UniqueRegistryKey() noexcept = default;
    explicit UniqueRegistryKey(HKEY key) noexcept : key_(key) {}
    UniqueRegistryKey(const UniqueRegistryKey&) = delete;
    UniqueRegistryKey& operator=(const UniqueRegistryKey&) = delete;
    ~UniqueRegistryKey() noexcept {
        if (key_ != nullptr) {
            RegCloseKey(key_);
        }
    }
    [[nodiscard]] HKEY get() const noexcept { return key_; }
    [[nodiscard]] HKEY* put() noexcept { return &key_; }
    [[nodiscard]] HKEY release() noexcept {
        HKEY released = key_;
        key_ = nullptr;
        return released;
    }

private:
    HKEY key_{nullptr};
};

class LocalSecurityDescriptor final {
public:
    LocalSecurityDescriptor() noexcept = default;
    LocalSecurityDescriptor(const LocalSecurityDescriptor&) = delete;
    LocalSecurityDescriptor& operator=(const LocalSecurityDescriptor&) = delete;
    ~LocalSecurityDescriptor() noexcept {
        if (descriptor_ != nullptr) {
            LocalFree(descriptor_);
        }
    }
    [[nodiscard]] bool Initialize() noexcept {
        return ConvertStringSecurityDescriptorToSecurityDescriptorW(
                   kPublicRegistrySecurityDescriptor,
                   SDDL_REVISION_1,
                   &descriptor_,
                   nullptr
               ) != FALSE;
    }
    [[nodiscard]] PSECURITY_DESCRIPTOR get() const noexcept { return descriptor_; }

private:
    PSECURITY_DESCRIPTOR descriptor_{nullptr};
};

enum class ParentStatus {
    Success,
    Untrusted,
    AccessDenied,
    Error,
};

[[nodiscard]] ParentStatus MapRegistryError(const LSTATUS status) noexcept {
    if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) {
        return ParentStatus::AccessDenied;
    }
    return ParentStatus::Error;
}

[[nodiscard]] bool ValidateKeySecurity(const HKEY key) noexcept {
    DWORD size = 0;
    const SECURITY_INFORMATION information =
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    LSTATUS status = RegGetKeySecurity(key, information, nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0 ||
        size > kMaximumSecurityDescriptorBytes) {
        return false;
    }
    try {
        std::vector<unsigned char> buffer(size);
        status = RegGetKeySecurity(
            key,
            information,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data()),
            &size
        );
        return status == ERROR_SUCCESS &&
               ValidatePublicRegistrySecurityDescriptor(
                   reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data())
               );
    } catch (...) {
        return false;
    }
}

[[nodiscard]] bool IsRegistryLinkOrAmbiguous(const HKEY key) noexcept {
    DWORD type = 0;
    DWORD size = 0;
    const LSTATUS status = RegQueryValueExW(
        key,
        L"SymbolicLinkValue",
        nullptr,
        &type,
        nullptr,
        &size
    );
    return status != ERROR_FILE_NOT_FOUND;
}

[[nodiscard]] ParentStatus CreateOrValidateChild(
    const HKEY parent,
    const wchar_t* const name,
    const REGSAM access,
    HKEY* const output,
    DWORD* const disposition = nullptr
) noexcept {
    LocalSecurityDescriptor descriptor;
    if (!descriptor.Initialize()) {
        return ParentStatus::Error;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor.get();
    attributes.bInheritHandle = FALSE;

    DWORD local_disposition = 0;
    HKEY key = nullptr;
    const LSTATUS status = RegCreateKeyExW(
        parent,
        name,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE | REG_OPTION_OPEN_LINK,
        access | KEY_WOW64_64KEY,
        &attributes,
        &key,
        &local_disposition
    );
    if (status != ERROR_SUCCESS) {
        return MapRegistryError(status);
    }
    UniqueRegistryKey owned(key);
    if (IsRegistryLinkOrAmbiguous(key) || !ValidateKeySecurity(key)) {
        return ParentStatus::Untrusted;
    }
    if (disposition != nullptr) {
        *disposition = local_disposition;
    }
    *output = owned.release();
    return ParentStatus::Success;
}

[[nodiscard]] ParentStatus EnsureProtectedParents(
    const REGSAM transactions_access,
    HKEY* const transactions_output
) noexcept {
    UniqueRegistryKey software;
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kSoftwareSubkey,
        REG_OPTION_OPEN_LINK,
        KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        software.put()
    );
    if (status != ERROR_SUCCESS) {
        return MapRegistryError(status);
    }

    UniqueRegistryKey root;
    ParentStatus parent_status = CreateOrValidateChild(
        software.get(),
        kWinCurRegistryRootName,
        KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE |
            READ_CONTROL,
        root.put()
    );
    if (parent_status != ParentStatus::Success) {
        return parent_status;
    }

    UniqueRegistryKey transactions;
    parent_status = CreateOrValidateChild(
        root.get(),
        kTransactionsSubkey,
        transactions_access | READ_CONTROL,
        transactions.put()
    );
    if (parent_status != ParentStatus::Success) {
        return parent_status;
    }
    *transactions_output = transactions.release();
    return ParentStatus::Success;
}

[[nodiscard]] RegistryReadStatus MapReadError(const LSTATUS status) noexcept {
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return RegistryReadStatus::NotFound;
    }
    if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) {
        return RegistryReadStatus::AccessDenied;
    }
    return RegistryReadStatus::Error;
}

[[nodiscard]] RegistryReadStatus OpenAndValidateReadKey(
    const HKEY parent,
    const wchar_t* const name,
    HKEY* const output
) noexcept {
    HKEY key = nullptr;
    const LSTATUS status = RegOpenKeyExW(
        parent,
        name,
        REG_OPTION_OPEN_LINK,
        KEY_READ | READ_CONTROL | KEY_WOW64_64KEY,
        &key
    );
    if (status != ERROR_SUCCESS) {
        return MapReadError(status);
    }
    UniqueRegistryKey owned(key);
    if (IsRegistryLinkOrAmbiguous(key) || !ValidateKeySecurity(key)) {
        return RegistryReadStatus::Untrusted;
    }
    *output = owned.release();
    return RegistryReadStatus::Success;
}

[[nodiscard]] RegistryReadStatus ReadRawValues(
    const HKEY key,
    std::vector<TransactionValue>& values
) {
    DWORD subkey_count = 0;
    DWORD value_count = 0;
    DWORD maximum_value_name = 0;
    DWORD maximum_value_data = 0;
    const LSTATUS query_status = RegQueryInfoKeyW(
        key,
        nullptr,
        nullptr,
        nullptr,
        &subkey_count,
        nullptr,
        nullptr,
        &value_count,
        &maximum_value_name,
        &maximum_value_data,
        nullptr,
        nullptr
    );
    if (query_status != ERROR_SUCCESS) {
        return MapReadError(query_status);
    }
    if (subkey_count != 0 || value_count > kMaximumRegistryValues ||
        maximum_value_name > kMaximumValueNameCharacters ||
        maximum_value_data > kMaximumValueDataBytes) {
        return RegistryReadStatus::Malformed;
    }

    values.clear();
    values.reserve(value_count);
    std::array<wchar_t, kMaximumValueNameCharacters + 1> name{};
    alignas(wchar_t)
        std::array<unsigned char, kMaximumValueDataBytes + sizeof(wchar_t)> data{};
    for (DWORD index = 0; index < value_count; ++index) {
        DWORD name_size = static_cast<DWORD>(name.size());
        DWORD data_size = static_cast<DWORD>(data.size());
        DWORD type = 0;
        const LSTATUS status = RegEnumValueW(
            key,
            index,
            name.data(),
            &name_size,
            nullptr,
            &type,
            data.data(),
            &data_size
        );
        if (status != ERROR_SUCCESS || name_size == 0 ||
            name_size > kMaximumValueNameCharacters) {
            return status == ERROR_SUCCESS ? RegistryReadStatus::Malformed
                                           : MapReadError(status);
        }

        TransactionValue value{};
        value.name.assign(name.data(), name_size);
        if (type == REG_DWORD && data_size == sizeof(std::uint32_t)) {
            value.type = TransactionValueType::Dword;
            std::memcpy(&value.dword_value, data.data(), sizeof(value.dword_value));
        } else if (type == REG_SZ && data_size >= sizeof(wchar_t) &&
                   data_size % sizeof(wchar_t) == 0) {
            const auto* const characters =
                reinterpret_cast<const wchar_t*>(data.data());
            const std::size_t character_count = data_size / sizeof(wchar_t);
            if (characters[character_count - 1] != L'\0' ||
                std::find(characters, characters + character_count - 1, L'\0') !=
                    characters + character_count - 1) {
                return RegistryReadStatus::Malformed;
            }
            value.type = TransactionValueType::String;
            value.string_value.assign(characters, character_count - 1);
        } else {
            return RegistryReadStatus::Malformed;
        }
        values.push_back(std::move(value));
    }
    return RegistryReadStatus::Success;
}

}  // namespace

WindowsTransactionStorage::~WindowsTransactionStorage() noexcept {
    if (transaction_key_ != nullptr) {
        RegCloseKey(transaction_key_);
    }
}

StorageCreateStatus WindowsTransactionStorage::Begin(
    const std::wstring_view transaction_id
) noexcept {
    if (transaction_key_ != nullptr ||
        !IsCanonicalTransactionUuid(transaction_id)) {
        return StorageCreateStatus::Error;
    }

    UniqueRegistryKey transactions;
    switch (EnsureProtectedParents(
        KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
        transactions.put()
    )) {
        case ParentStatus::Success:
            break;
        case ParentStatus::Untrusted:
            return StorageCreateStatus::Untrusted;
        case ParentStatus::AccessDenied:
            return StorageCreateStatus::AccessDenied;
        case ParentStatus::Error:
            return StorageCreateStatus::Error;
    }

    std::array<wchar_t, 37> identifier{};
    std::wmemcpy(identifier.data(), transaction_id.data(), transaction_id.size());
    DWORD disposition = 0;
    HKEY result_key = nullptr;
    const ParentStatus result = CreateOrValidateChild(
        transactions.get(),
        identifier.data(),
        KEY_SET_VALUE | KEY_QUERY_VALUE | READ_CONTROL,
        &result_key,
        &disposition
    );
    if (result == ParentStatus::Untrusted) {
        return StorageCreateStatus::Untrusted;
    }
    if (result == ParentStatus::AccessDenied) {
        return StorageCreateStatus::AccessDenied;
    }
    if (result != ParentStatus::Success) {
        return StorageCreateStatus::Error;
    }

    UniqueRegistryKey owned_result(result_key);
    if (disposition != REG_CREATED_NEW_KEY) {
        return StorageCreateStatus::Duplicate;
    }
    transaction_key_ = owned_result.release();
    return StorageCreateStatus::Created;
}

StorageOpenStatus WindowsTransactionStorage::Open(
    const std::wstring_view transaction_id
) noexcept {
    if (transaction_key_ != nullptr ||
        !IsCanonicalTransactionUuid(transaction_id)) {
        return StorageOpenStatus::Error;
    }
    UniqueRegistryKey transactions;
    switch (EnsureProtectedParents(
        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
        transactions.put()
    )) {
        case ParentStatus::Success:
            break;
        case ParentStatus::Untrusted:
            return StorageOpenStatus::Untrusted;
        case ParentStatus::AccessDenied:
            return StorageOpenStatus::AccessDenied;
        case ParentStatus::Error:
            return StorageOpenStatus::Error;
    }
    std::array<wchar_t, 37> identifier{};
    std::wmemcpy(identifier.data(), transaction_id.data(), transaction_id.size());
    HKEY key = nullptr;
    const LSTATUS status = RegOpenKeyExW(
        transactions.get(),
        identifier.data(),
        REG_OPTION_OPEN_LINK,
        KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL | KEY_WOW64_64KEY,
        &key
    );
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return StorageOpenStatus::NotFound;
    }
    if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) {
        return StorageOpenStatus::AccessDenied;
    }
    if (status != ERROR_SUCCESS) {
        return StorageOpenStatus::Error;
    }
    UniqueRegistryKey owned(key);
    if (IsRegistryLinkOrAmbiguous(key) || !ValidateKeySecurity(key)) {
        return StorageOpenStatus::Untrusted;
    }
    std::vector<TransactionValue> values;
    if (ReadRawValues(key, values) != RegistryReadStatus::Success) {
        return StorageOpenStatus::Error;
    }
    complete_written_ = std::any_of(
        values.begin(),
        values.end(),
        [](const TransactionValue& value) { return value.name == L"Complete"; }
    );
    transaction_key_ = owned.release();
    return StorageOpenStatus::Opened;
}

bool WindowsTransactionStorage::Write(const TransactionValue& value) noexcept {
    if (transaction_key_ == nullptr || complete_written_ || value.name.empty()) {
        return false;
    }
    const bool is_complete = value.name == L"Complete";
    if (is_complete &&
        (value.type != TransactionValueType::Dword || value.dword_value != 1)) {
        return false;
    }

    // Completion is a durability boundary, not merely an ordering marker.
    // Flush every preceding value before publishing Complete=1. A second flush
    // makes PersistStatus::Success mean the completion marker was also handed
    // to the registry's durable-write path. Any flush failure leaves the
    // caller with an incomplete/indeterminate transaction, never an assumed
    // success.
    if (is_complete && RegFlushKey(transaction_key_) != ERROR_SUCCESS) {
        return false;
    }

    LSTATUS status = ERROR_INVALID_DATA;
    if (value.type == TransactionValueType::Dword) {
        const DWORD data = value.dword_value;
        status = RegSetValueExW(
            transaction_key_,
            value.name.c_str(),
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&data),
            sizeof(data)
        );
    } else {
        if (value.string_value.size() > kMaximumVerificationSummaryCharacters) {
            return false;
        }
        const DWORD bytes = static_cast<DWORD>(
            (value.string_value.size() + 1) * sizeof(wchar_t)
        );
        status = RegSetValueExW(
            transaction_key_,
            value.name.c_str(),
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.string_value.c_str()),
            bytes
        );
    }
    if (status != ERROR_SUCCESS) {
        return false;
    }
    if (is_complete) {
        if (RegFlushKey(transaction_key_) != ERROR_SUCCESS) {
            return false;
        }
        complete_written_ = true;
    }
    return true;
}

bool WindowsTransactionStorage::Flush() noexcept {
    return transaction_key_ != nullptr &&
           RegFlushKey(transaction_key_) == ERROR_SUCCESS;
}

bool WindowsTransactionStorage::Read(
    std::vector<TransactionValue>& values
) noexcept {
    if (transaction_key_ == nullptr) {
        return false;
    }
    try {
        return ReadRawValues(transaction_key_, values) ==
               RegistryReadStatus::Success;
    } catch (...) {
        return false;
    }
}

RegistryReadResult ReadTransactionResultFromRegistry(
    const std::wstring_view transaction_id
) noexcept {
    if (!IsCanonicalTransactionUuid(transaction_id)) {
        return {RegistryReadStatus::Malformed, std::nullopt};
    }
    try {
        UniqueRegistryKey root;
        RegistryReadStatus status = OpenAndValidateReadKey(
            HKEY_LOCAL_MACHINE,
            kWinCurRegistryPath,
            root.put()
        );
        if (status != RegistryReadStatus::Success) {
            return {status, std::nullopt};
        }

        UniqueRegistryKey transactions;
        status = OpenAndValidateReadKey(
            root.get(),
            kTransactionsSubkey,
            transactions.put()
        );
        if (status != RegistryReadStatus::Success) {
            return {status, std::nullopt};
        }

        std::array<wchar_t, 37> identifier{};
        std::wmemcpy(identifier.data(), transaction_id.data(), transaction_id.size());
        UniqueRegistryKey result_key;
        status = OpenAndValidateReadKey(
            transactions.get(),
            identifier.data(),
            result_key.put()
        );
        if (status != RegistryReadStatus::Success) {
            return {status, std::nullopt};
        }

        std::vector<TransactionValue> values;
        status = ReadRawValues(result_key.get(), values);
        if (status != RegistryReadStatus::Success) {
            return {status, std::nullopt};
        }
        const ReservationParseResult reservation =
            ParseTransactionReservation(values, transaction_id);
        if (reservation.status == ReservationParseStatus::Incomplete) {
            return {RegistryReadStatus::Incomplete, std::nullopt};
        }
        if (reservation.status == ReservationParseStatus::Malformed) {
            return {RegistryReadStatus::Malformed, std::nullopt};
        }
        std::vector<TransactionValue> result_values;
        result_values.reserve(values.size());
        for (const TransactionValue& value : values) {
            if (value.name.starts_with(L"Reservation") ||
                value.name == L"Lifecycle") {
                continue;
            }
            result_values.push_back(value);
        }
        TransactionParseResult parsed =
            ParseTransactionResult(result_values, transaction_id);
        if (parsed.status == TransactionParseStatus::Incomplete) {
            return {RegistryReadStatus::Incomplete, std::nullopt};
        }
        if (parsed.status != TransactionParseStatus::Success ||
            !parsed.result.has_value()) {
            return {RegistryReadStatus::Malformed, std::nullopt};
        }
        if (reservation.status == ReservationParseStatus::Success) {
            if (!reservation.reservation.has_value() ||
                (reservation.reservation->lifecycle !=
                     TransactionLifecycle::Completed &&
                 reservation.reservation->lifecycle !=
                     TransactionLifecycle::Interrupted &&
                 reservation.reservation->lifecycle !=
                     TransactionLifecycle::Failed)) {
                return {RegistryReadStatus::Malformed, std::nullopt};
            }
            Request request{};
            request.operation = parsed.result->operation;
            request.transaction_id = parsed.result->transaction_id;
            request.action = parsed.result->action;
            request.rollback_id = parsed.result->rollback_id;
            if (!ReservationMatchesRequest(*reservation.reservation, request)) {
                return {RegistryReadStatus::Malformed, std::nullopt};
            }
        }
        return {RegistryReadStatus::Success, std::move(parsed.result)};
    } catch (...) {
        return {RegistryReadStatus::Error, std::nullopt};
    }
}

std::wstring CurrentUtcTimestamp() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    std::array<wchar_t, 21> buffer{};
    const int written = swprintf_s(
        buffer.data(),
        buffer.size(),
        L"%04u-%02u-%02uT%02u:%02u:%02uZ",
        static_cast<unsigned int>(time.wYear),
        static_cast<unsigned int>(time.wMonth),
        static_cast<unsigned int>(time.wDay),
        static_cast<unsigned int>(time.wHour),
        static_cast<unsigned int>(time.wMinute),
        static_cast<unsigned int>(time.wSecond)
    );
    if (written != 20) {
        return {};
    }
    return std::wstring(buffer.data(), static_cast<std::size_t>(written));
}

bool PruneCompletedTransactionResults(
    const std::size_t maximum_completed
) noexcept {
    if (maximum_completed == 0 || maximum_completed > kMaximumCompletedTransactions) {
        return false;
    }
    try {
        UniqueRegistryKey root;
        RegistryReadStatus read_status = OpenAndValidateReadKey(
            HKEY_LOCAL_MACHINE,
            kWinCurRegistryPath,
            root.put()
        );
        if (read_status == RegistryReadStatus::NotFound) {
            return true;
        }
        if (read_status != RegistryReadStatus::Success) {
            return false;
        }

        HKEY transactions_key = nullptr;
        const LSTATUS open_status = RegOpenKeyExW(
            root.get(),
            kTransactionsSubkey,
            REG_OPTION_OPEN_LINK,
            KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WRITE | READ_CONTROL |
                KEY_WOW64_64KEY,
            &transactions_key
        );
        if (open_status != ERROR_SUCCESS) {
            return false;
        }
        UniqueRegistryKey transactions(transactions_key);
        if (IsRegistryLinkOrAmbiguous(transactions.get()) ||
            !ValidateKeySecurity(transactions.get())) {
            return false;
        }

        DWORD subkey_count = 0;
        DWORD maximum_name = 0;
        if (RegQueryInfoKeyW(
                transactions.get(),
                nullptr,
                nullptr,
                nullptr,
                &subkey_count,
                &maximum_name,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            ) != ERROR_SUCCESS ||
            subkey_count > kMaximumEnumeratedTransactions || maximum_name > 36) {
            return false;
        }

        struct Candidate final {
            std::wstring id;
            std::wstring timestamp;
        };
        std::vector<Candidate> candidates;
        candidates.reserve(subkey_count);
        for (DWORD index = 0; index < subkey_count; ++index) {
            std::array<wchar_t, 37> name{};
            DWORD name_size = static_cast<DWORD>(name.size());
            const LSTATUS status = RegEnumKeyExW(
                transactions.get(),
                index,
                name.data(),
                &name_size,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            );
            if (status != ERROR_SUCCESS) {
                return false;
            }
            const std::wstring id(name.data(), name_size);
            if (!IsCanonicalTransactionUuid(id)) {
                continue;
            }
            RegistryReadResult result = ReadTransactionResultFromRegistry(id);
            if (result.status == RegistryReadStatus::Success &&
                result.result.has_value()) {
                candidates.push_back({id, result.result->timestamp_utc});
            }
        }

        if (candidates.size() <= maximum_completed) {
            return true;
        }
        std::sort(
            candidates.begin(),
            candidates.end(),
            [](const Candidate& left, const Candidate& right) {
                return std::tie(left.timestamp, left.id) <
                       std::tie(right.timestamp, right.id);
            }
        );
        const std::size_t delete_count = candidates.size() - maximum_completed;
        for (std::size_t index = 0; index < delete_count; ++index) {
            RegistryReadResult current =
                ReadTransactionResultFromRegistry(candidates[index].id);
            if (current.status != RegistryReadStatus::Success ||
                !current.result.has_value() ||
                current.result->timestamp_utc != candidates[index].timestamp) {
                continue;
            }
            const LSTATUS delete_status = RegDeleteKeyExW(
                transactions.get(),
                candidates[index].id.c_str(),
                KEY_WOW64_64KEY,
                0
            );
            if (delete_status != ERROR_SUCCESS) {
                return false;
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

RecoverySummary RecoverIncompleteTransactions() noexcept {
    RecoverySummary summary{};
    try {
        UniqueRegistryKey root;
        RegistryReadStatus read_status = OpenAndValidateReadKey(
            HKEY_LOCAL_MACHINE,
            kWinCurRegistryPath,
            root.put()
        );
        if (read_status == RegistryReadStatus::NotFound) {
            return summary;
        }
        if (read_status != RegistryReadStatus::Success) {
            summary.storage_trusted = false;
            return summary;
        }
        UniqueRegistryKey transactions;
        read_status = OpenAndValidateReadKey(
            root.get(),
            kTransactionsSubkey,
            transactions.put()
        );
        if (read_status == RegistryReadStatus::NotFound) {
            return summary;
        }
        if (read_status != RegistryReadStatus::Success) {
            summary.storage_trusted = false;
            return summary;
        }
        DWORD subkey_count = 0;
        DWORD maximum_name = 0;
        if (RegQueryInfoKeyW(
                transactions.get(),
                nullptr,
                nullptr,
                nullptr,
                &subkey_count,
                &maximum_name,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr
            ) != ERROR_SUCCESS ||
            subkey_count > kMaximumEnumeratedTransactions || maximum_name > 36) {
            summary.bounded = false;
            return summary;
        }
        std::vector<std::wstring> identifiers;
        identifiers.reserve(subkey_count);
        for (DWORD index = 0; index < subkey_count; ++index) {
            std::array<wchar_t, 37> name{};
            DWORD name_size = static_cast<DWORD>(name.size());
            if (RegEnumKeyExW(
                    transactions.get(),
                    index,
                    name.data(),
                    &name_size,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                ) != ERROR_SUCCESS) {
                summary.storage_trusted = false;
                return summary;
            }
            const std::wstring id(name.data(), name_size);
            if (IsCanonicalTransactionUuid(id)) {
                identifiers.push_back(id);
            } else {
                ++summary.retained_partial_or_malformed;
            }
        }
        for (const std::wstring& id : identifiers) {
            ++summary.examined;
            const RegistryReadResult completed =
                ReadTransactionResultFromRegistry(id);
            if (completed.status == RegistryReadStatus::Success) {
                ++summary.completed_unchanged;
                continue;
            }
            if (completed.status != RegistryReadStatus::Incomplete) {
                ++summary.retained_partial_or_malformed;
                continue;
            }
            WindowsTransactionStorage storage;
            if (storage.Open(id) != StorageOpenStatus::Opened) {
                summary.storage_trusted = false;
                return summary;
            }
            std::vector<TransactionValue> values;
            if (!storage.Read(values)) {
                summary.storage_trusted = false;
                return summary;
            }
            const ReservationParseResult parsed =
                ParseTransactionReservation(values, id);
            if (parsed.status != ReservationParseStatus::Success ||
                !parsed.reservation.has_value()) {
                ++summary.retained_partial_or_malformed;
                continue;
            }
            Request request{};
            request.operation = parsed.reservation->operation;
            request.transaction_id = parsed.reservation->transaction_id;
            request.action = parsed.reservation->action;
            request.rollback_id = parsed.reservation->rollback_id;
            const std::wstring timestamp = CurrentUtcTimestamp();
            if (timestamp.empty()) {
                summary.storage_trusted = false;
                return summary;
            }
            const TransactionResult interrupted =
                MakeInterruptedResult(*parsed.reservation, timestamp);
            if (FinalizeReservedTransaction(
                    storage,
                    request,
                    interrupted,
                    parsed.reservation->lifecycle,
                    TransactionLifecycle::Interrupted,
                    timestamp
                ) != PersistStatus::Success) {
                summary.storage_trusted = false;
                return summary;
            }
            ++summary.recovered_interrupted;
        }
        return summary;
    } catch (...) {
        summary.storage_trusted = false;
        return summary;
    }
}

}  // namespace wincur::helper
