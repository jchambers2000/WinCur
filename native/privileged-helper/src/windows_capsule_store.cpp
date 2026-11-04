#include "wincur/helper/windows_capsule_store.hpp"

#include "wincur/helper/registry_security.hpp"
#include "wincur/helper/windows_transaction_store.hpp"

#include <Sddl.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <vector>

namespace wincur::helper {
namespace {

constexpr DWORD kMaximumDescriptorBytes = 64U * 1024U;
constexpr DWORD kMaximumCapsuleValues = 32;
constexpr DWORD kMaximumNameCharacters = 64;

class Key final {
public:
    Key() noexcept = default;
    explicit Key(HKEY value) noexcept : value_(value) {}
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() noexcept { if (value_) RegCloseKey(value_); }
    [[nodiscard]] HKEY get() const noexcept { return value_; }
    [[nodiscard]] HKEY* put() noexcept { return &value_; }
    [[nodiscard]] HKEY release() noexcept { HKEY value = value_; value_ = nullptr; return value; }
private:
    HKEY value_{nullptr};
};

class Descriptor final {
public:
    ~Descriptor() noexcept { if (value_) LocalFree(value_); }
    [[nodiscard]] bool Initialize(const wchar_t* sddl) noexcept {
        return ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &value_, nullptr) != FALSE;
    }
    [[nodiscard]] PSECURITY_DESCRIPTOR get() const noexcept { return value_; }
private:
    PSECURITY_DESCRIPTOR value_{nullptr};
};

[[nodiscard]] bool IsLink(const HKEY key) noexcept {
    DWORD type = 0;
    DWORD size = 0;
    return RegQueryValueExW(key, L"SymbolicLinkValue", nullptr, &type, nullptr, &size)
           != ERROR_FILE_NOT_FOUND;
}

[[nodiscard]] bool ValidateSecurity(const HKEY key, const bool private_key) noexcept {
    DWORD size = 0;
    const SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION |
                                      DACL_SECURITY_INFORMATION;
    if (RegGetKeySecurity(key, info, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER ||
        size == 0 || size > kMaximumDescriptorBytes) return false;
    try {
        std::vector<unsigned char> bytes(size);
        if (RegGetKeySecurity(key, info,
                reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data()), &size)
            != ERROR_SUCCESS) return false;
        return private_key
            ? ValidatePrivateRegistrySecurityDescriptor(
                  reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data()))
            : ValidatePublicRegistrySecurityDescriptor(
                  reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data()));
    } catch (...) { return false; }
}

[[nodiscard]] CapsuleCreateStatus ErrorStatus(LSTATUS status) noexcept {
    SetLastError(static_cast<DWORD>(status));
    if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD)
        return CapsuleCreateStatus::AccessDenied;
    return CapsuleCreateStatus::Error;
}

[[nodiscard]] bool CreateChild(
    HKEY parent, const wchar_t* name, bool private_key, REGSAM access,
    HKEY* output, DWORD* disposition
) noexcept {
    Descriptor descriptor;
    if (!descriptor.Initialize(private_key ? kPrivateRegistrySecurityDescriptor
                                           : kPublicRegistrySecurityDescriptor)) {
        SetLastError(ERROR_INVALID_SECURITY_DESCR);
        return false;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.get(), FALSE};
    HKEY raw = nullptr;
    const LSTATUS status = RegCreateKeyExW(
        parent, name, 0, nullptr, REG_OPTION_NON_VOLATILE | REG_OPTION_OPEN_LINK,
        access | KEY_WOW64_64KEY, &attributes, &raw, disposition);
    if (status != ERROR_SUCCESS) {
        SetLastError(static_cast<DWORD>(status));
        return false;
    }
    Key owned(raw);
    if (IsLink(raw) || !ValidateSecurity(raw, private_key)) {
        SetLastError(ERROR_INVALID_SECURITY_DESCR);
        return false;
    }
    *output = owned.release();
    return true;
}

[[nodiscard]] CapsuleCreateStatus OpenParentsForCreate(HKEY* output) noexcept {
    Key software;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE",
        REG_OPTION_OPEN_LINK, KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY, software.put());
    if (status != ERROR_SUCCESS) return ErrorStatus(status);
    Key root;
    DWORD disposition = 0;
    if (!CreateChild(software.get(), kWinCurRegistryRootName, false,
            KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE |
                READ_CONTROL, root.put(), &disposition)) return CapsuleCreateStatus::Untrusted;
    Key rollback;
    if (!CreateChild(root.get(), kRollbackCapsulesSubkey, true,
            KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE |
                READ_CONTROL, rollback.put(), &disposition)) return CapsuleCreateStatus::Untrusted;
    *output = rollback.release();
    return CapsuleCreateStatus::Created;
}

[[nodiscard]] bool ReadValues(HKEY key, std::vector<CapsuleValue>& values) noexcept {
    DWORD subkeys = 0, count = 0, max_name = 0, max_data = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
            &count, &max_name, &max_data, nullptr, nullptr) != ERROR_SUCCESS ||
        subkeys != 0 || count > kMaximumCapsuleValues ||
        max_name > kMaximumNameCharacters || max_data > kMaximumCapsuleValueBytes)
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    try {
        values.clear();
        for (DWORD i = 0; i < count; ++i) {
            std::array<wchar_t, kMaximumNameCharacters + 1> name{};
            DWORD name_size = static_cast<DWORD>(name.size());
            DWORD data_size = max_data;
            std::vector<unsigned char> data(data_size + sizeof(wchar_t));
            DWORD type = 0;
            const LSTATUS status = RegEnumValueW(key, i, name.data(), &name_size,
                nullptr, &type, data.data(), &data_size);
            if (status != ERROR_SUCCESS || name_size == 0) {
                SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA
                                                     : static_cast<DWORD>(status));
                return false;
            }
            CapsuleValue value{};
            value.name.assign(name.data(), name_size);
            if (type == REG_DWORD && data_size == sizeof(std::uint32_t)) {
                value.type = CapsuleValueType::Dword;
                std::memcpy(&value.dword_value, data.data(), sizeof(value.dword_value));
            } else if (type == REG_SZ && data_size >= sizeof(wchar_t) &&
                       data_size % sizeof(wchar_t) == 0) {
                const auto* chars = reinterpret_cast<const wchar_t*>(data.data());
                const std::size_t length = data_size / sizeof(wchar_t);
                if (chars[length - 1] != L'\0') {
                    SetLastError(ERROR_INVALID_DATA);
                    return false;
                }
                value.type = CapsuleValueType::String;
                value.string_value.assign(chars, length - 1);
            } else if (type == REG_BINARY && data_size <= kMaximumCapsuleValueBytes) {
                value.type = CapsuleValueType::Binary;
                value.binary_value.assign(data.begin(), data.begin() + data_size);
            } else {
                SetLastError(ERROR_INVALID_DATA);
                return false;
            }
            values.push_back(std::move(value));
        }
        return true;
    } catch (...) {
        SetLastError(ERROR_OUTOFMEMORY);
        return false;
    }
}

}  // namespace

WindowsCapsuleStorage::~WindowsCapsuleStorage() noexcept { if (key_) RegCloseKey(key_); }

CapsuleCreateStatus WindowsCapsuleStorage::Begin(std::wstring_view id) noexcept {
    if (key_ || !IsCanonicalTransactionUuid(id)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return CapsuleCreateStatus::Error;
    }
    Key parent;
    const CapsuleCreateStatus parent_status = OpenParentsForCreate(parent.put());
    if (parent_status != CapsuleCreateStatus::Created) return parent_status;
    DWORD count = 0;
    if (RegQueryInfoKeyW(parent.get(), nullptr, nullptr, nullptr, &count, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
    {
        SetLastError(ERROR_INVALID_DATA);
        return CapsuleCreateStatus::Error;
    }
    if (count >= kMaximumCapsules) {
        SetLastError(ERROR_TOO_MANY_NAMES);
        return CapsuleCreateStatus::Exhausted;
    }
    std::array<wchar_t, 37> name{};
    std::wmemcpy(name.data(), id.data(), id.size());
    DWORD disposition = 0;
    HKEY raw = nullptr;
    if (!CreateChild(parent.get(), name.data(), true,
            KEY_SET_VALUE | KEY_QUERY_VALUE | READ_CONTROL,
            &raw, &disposition)) return CapsuleCreateStatus::Untrusted;
    Key owned(raw);
    if (disposition != REG_CREATED_NEW_KEY) {
        SetLastError(ERROR_ALREADY_EXISTS);
        return CapsuleCreateStatus::Duplicate;
    }
    key_ = owned.release();
    return CapsuleCreateStatus::Created;
}

bool WindowsCapsuleStorage::Write(const CapsuleValue& value) noexcept {
    if (!key_ || complete_written_ || value.name.empty() ||
        value.name.size() > kMaximumNameCharacters) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    const bool complete = value.name == L"CapsuleComplete";
    if (complete && (value.type != CapsuleValueType::Dword || value.dword_value != 1))
        return false;
    if (complete) {
        const LSTATUS flush = RegFlushKey(key_);
        if (flush != ERROR_SUCCESS) {
            SetLastError(static_cast<DWORD>(flush));
            return false;
        }
    }
    LSTATUS status = ERROR_INVALID_DATA;
    if (value.type == CapsuleValueType::Dword) {
        const DWORD data = value.dword_value;
        status = RegSetValueExW(key_, value.name.c_str(), 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&data), sizeof(data));
    } else if (value.type == CapsuleValueType::String &&
               value.string_value.size() <= 128) {
        const DWORD size = static_cast<DWORD>((value.string_value.size() + 1) * sizeof(wchar_t));
        status = RegSetValueExW(key_, value.name.c_str(), 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value.string_value.c_str()), size);
    } else if (value.type == CapsuleValueType::Binary &&
               value.binary_value.size() <= kMaximumCapsuleValueBytes) {
        status = RegSetValueExW(key_, value.name.c_str(), 0, REG_BINARY,
            value.binary_value.data(), static_cast<DWORD>(value.binary_value.size()));
    }
    if (status != ERROR_SUCCESS) {
        SetLastError(static_cast<DWORD>(status));
        return false;
    }
    if (complete) {
        const LSTATUS flush = RegFlushKey(key_);
        if (flush != ERROR_SUCCESS) {
            SetLastError(static_cast<DWORD>(flush));
            return false;
        }
        complete_written_ = true;
    }
    return true;
}

bool WindowsCapsuleStorage::Flush() noexcept {
    if (!key_) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    const LSTATUS status = RegFlushKey(key_);
    if (status != ERROR_SUCCESS) SetLastError(static_cast<DWORD>(status));
    return status == ERROR_SUCCESS;
}
bool WindowsCapsuleStorage::Read(std::vector<CapsuleValue>& values) noexcept {
    return key_ && ReadValues(key_, values);
}

CapsuleRegistryReadResult ReadCapsuleFromRegistry(
    std::wstring_view capsule_id, std::wstring_view transaction_id,
    Operation operation, ActionId action
) noexcept {
    if (!IsCanonicalTransactionUuid(capsule_id) ||
        !IsCanonicalTransactionUuid(transaction_id)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return {CapsuleRegistryReadStatus::Malformed, std::nullopt};
    }
    Key root;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWinCurRegistryPath,
        REG_OPTION_OPEN_LINK, KEY_READ | READ_CONTROL | KEY_WOW64_64KEY, root.put());
    if (status == ERROR_FILE_NOT_FOUND) {
        SetLastError(static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::NotFound, {}};
    }
    if (status == ERROR_ACCESS_DENIED) {
        SetLastError(static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::AccessDenied, {}};
    }
    if (status != ERROR_SUCCESS || IsLink(root.get()) || !ValidateSecurity(root.get(), false)) {
        SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR
                                             : static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::Untrusted, {}};
    }
    Key parent;
    status = RegOpenKeyExW(root.get(), kRollbackCapsulesSubkey, REG_OPTION_OPEN_LINK,
        KEY_READ | READ_CONTROL | KEY_WOW64_64KEY, parent.put());
    if (status == ERROR_FILE_NOT_FOUND) {
        SetLastError(static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::NotFound, {}};
    }
    if (status != ERROR_SUCCESS || IsLink(parent.get()) || !ValidateSecurity(parent.get(), true)) {
        SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR
                                             : static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::Untrusted, {}};
    }
    std::array<wchar_t, 37> name{};
    std::wmemcpy(name.data(), capsule_id.data(), capsule_id.size());
    Key key;
    status = RegOpenKeyExW(parent.get(), name.data(), REG_OPTION_OPEN_LINK,
        KEY_READ | READ_CONTROL | KEY_WOW64_64KEY, key.put());
    if (status == ERROR_FILE_NOT_FOUND) {
        SetLastError(static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::NotFound, {}};
    }
    if (status != ERROR_SUCCESS || IsLink(key.get()) || !ValidateSecurity(key.get(), true)) {
        SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR
                                             : static_cast<DWORD>(status));
        return {CapsuleRegistryReadStatus::Untrusted, {}};
    }
    std::vector<CapsuleValue> values;
    if (!ReadValues(key.get(), values))
        return {CapsuleRegistryReadStatus::Malformed, {}};
    auto parsed = ParseCapsule(values, capsule_id, transaction_id, operation, action);
    switch (parsed.status) {
        case CapsuleParseStatus::Success:
            return {CapsuleRegistryReadStatus::Success, std::move(parsed.capsule)};
        case CapsuleParseStatus::Incomplete:
            SetLastError(ERROR_INVALID_DATA);
            return {CapsuleRegistryReadStatus::Incomplete, {}};
        case CapsuleParseStatus::BindingMismatch:
            SetLastError(ERROR_INVALID_DATA);
            return {CapsuleRegistryReadStatus::BindingMismatch, {}};
        case CapsuleParseStatus::Malformed:
            SetLastError(ERROR_INVALID_DATA);
            return {CapsuleRegistryReadStatus::Malformed, {}};
    }
    return {CapsuleRegistryReadStatus::Error, {}};
}

}  // namespace wincur::helper
