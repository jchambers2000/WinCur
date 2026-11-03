#include "wincur/helper/windows_inspection.hpp"

#include <Windows.h>
#include <netfw.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace wincur::helper {
namespace {

constexpr wchar_t kAutoRunPath[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
constexpr wchar_t kPowerShellScriptBlockPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
constexpr wchar_t kPowerShellModulePath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging";
constexpr wchar_t kPowerShellModuleNamesPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames";
constexpr DWORD kMaximumInspectionValueBytes = 4096;

class UniqueRegistryKey final {
public:
    UniqueRegistryKey() noexcept = default;
    UniqueRegistryKey(const UniqueRegistryKey&) = delete;
    UniqueRegistryKey& operator=(const UniqueRegistryKey&) = delete;
    ~UniqueRegistryKey() noexcept {
        if (key_ != nullptr) {
            RegCloseKey(key_);
        }
    }
    [[nodiscard]] HKEY* put() noexcept { return &key_; }
    [[nodiscard]] HKEY get() const noexcept { return key_; }

private:
    HKEY key_{nullptr};
};

class ComApartment final {
public:
    ComApartment() noexcept {
        const HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (result == S_OK || result == S_FALSE) {
            usable_ = true;
            uninitialize_ = true;
        } else if (result == RPC_E_CHANGED_MODE) {
            usable_ = true;
        } else {
            error_ = result;
        }
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;
    ~ComApartment() noexcept {
        if (uninitialize_) {
            CoUninitialize();
        }
    }
    [[nodiscard]] bool usable() const noexcept { return usable_; }
    [[nodiscard]] HRESULT error() const noexcept { return error_; }

private:
    bool usable_{false};
    bool uninitialize_{false};
    HRESULT error_{E_FAIL};
};

template <typename T>
class ComPointer final {
public:
    ComPointer() noexcept = default;
    ComPointer(const ComPointer&) = delete;
    ComPointer& operator=(const ComPointer&) = delete;
    ~ComPointer() noexcept {
        if (pointer_ != nullptr) {
            pointer_->Release();
        }
    }
    [[nodiscard]] T** put() noexcept { return &pointer_; }
    [[nodiscard]] T* operator->() const noexcept { return pointer_; }

private:
    T* pointer_{nullptr};
};

[[nodiscard]] EvidenceState RegistryErrorState(const LSTATUS status) noexcept {
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return EvidenceState::Missing;
    }
    if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) {
        return EvidenceState::Inaccessible;
    }
    if (status == ERROR_CALL_NOT_IMPLEMENTED || status == ERROR_NOT_SUPPORTED) {
        return EvidenceState::Unsupported;
    }
    return EvidenceState::Error;
}

[[nodiscard]] bool IsRegistryLinkOrAmbiguous(const HKEY key) noexcept {
    DWORD type = 0;
    DWORD size = 0;
    return RegQueryValueExW(
               key,
               L"SymbolicLinkValue",
               nullptr,
               &type,
               nullptr,
               &size
           ) != ERROR_FILE_NOT_FOUND;
}

[[nodiscard]] ValueEvidence ReadFixedRegistryValue(
    const wchar_t* const path,
    const wchar_t* const name
) noexcept {
    UniqueRegistryKey key;
    const LSTATUS open_status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        path,
        REG_OPTION_OPEN_LINK,
        KEY_QUERY_VALUE | kInspectionRegistryView,
        key.put()
    );
    if (open_status != ERROR_SUCCESS) {
        return {RegistryErrorState(open_status), EvidenceType::None, 0, {}};
    }
    if (IsRegistryLinkOrAmbiguous(key.get())) {
        return {EvidenceState::Error, EvidenceType::None, 0, {}};
    }

    DWORD type = 0;
    DWORD size = 0;
    LSTATUS status = RegQueryValueExW(
        key.get(),
        name,
        nullptr,
        &type,
        nullptr,
        &size
    );
    if (status != ERROR_SUCCESS) {
        return {RegistryErrorState(status), EvidenceType::None, 0, {}};
    }
    if (size > kMaximumInspectionValueBytes) {
        return {EvidenceState::Present, EvidenceType::Other, 0, {}};
    }

    if (type == REG_DWORD) {
        if (size != sizeof(DWORD)) {
            return {EvidenceState::Present, EvidenceType::Other, 0, {}};
        }
        DWORD value = 0;
        DWORD read_size = sizeof(value);
        status = RegQueryValueExW(
            key.get(),
            name,
            nullptr,
            &type,
            reinterpret_cast<BYTE*>(&value),
            &read_size
        );
        if (status != ERROR_SUCCESS) {
            return {RegistryErrorState(status), EvidenceType::None, 0, {}};
        }
        if (type != REG_DWORD || read_size != sizeof(value)) {
            return {EvidenceState::Present, EvidenceType::Other, 0, {}};
        }
        return {EvidenceState::Present, EvidenceType::Dword, value, {}};
    }

    if (type == REG_SZ) {
        if (size < sizeof(wchar_t) || size % sizeof(wchar_t) != 0) {
            return {EvidenceState::Present, EvidenceType::Other, 0, {}};
        }
        try {
            std::vector<wchar_t> value(size / sizeof(wchar_t));
            DWORD read_size = size;
            status = RegQueryValueExW(
                key.get(),
                name,
                nullptr,
                &type,
                reinterpret_cast<BYTE*>(value.data()),
                &read_size
            );
            if (status != ERROR_SUCCESS) {
                return {RegistryErrorState(status), EvidenceType::None, 0, {}};
            }
            if (type != REG_SZ || read_size != size || value.back() != L'\0' ||
                std::find(value.begin(), value.end() - 1, L'\0') !=
                    value.end() - 1) {
                return {EvidenceState::Present, EvidenceType::Other, 0, {}};
            }
            return {
                EvidenceState::Present,
                EvidenceType::String,
                0,
                std::wstring(value.data(), value.size() - 1),
            };
        } catch (...) {
            return {EvidenceState::Error, EvidenceType::None, 0, {}};
        }
    }

    return {EvidenceState::Present, EvidenceType::Other, 0, {}};
}

[[nodiscard]] RegistryInspectionEvidence CollectAutoRun() noexcept {
    RegistryInspectionEvidence evidence{};
    evidence.value_count = 2;
    evidence.values[0] =
        ReadFixedRegistryValue(kAutoRunPath, L"NoDriveTypeAutoRun");
    evidence.values[1] = ReadFixedRegistryValue(kAutoRunPath, L"NoAutorun");
    return evidence;
}

[[nodiscard]] RegistryInspectionEvidence CollectPowerShellLogging() noexcept {
    RegistryInspectionEvidence evidence{};
    evidence.value_count = 3;
    evidence.values[0] = ReadFixedRegistryValue(
        kPowerShellScriptBlockPath,
        L"EnableScriptBlockLogging"
    );
    evidence.values[1] = ReadFixedRegistryValue(
        kPowerShellModulePath,
        L"EnableModuleLogging"
    );
    evidence.values[2] =
        ReadFixedRegistryValue(kPowerShellModuleNamesPath, L"*");
    return evidence;
}

[[nodiscard]] PolicyAuthority FirewallAuthorityFromResult(
    const HRESULT result,
    const NET_FW_MODIFY_STATE state
) noexcept {
    if (FAILED(result)) {
        if (result == E_ACCESSDENIED) {
            return PolicyAuthority::Inaccessible;
        }
        if (result == E_NOINTERFACE || result == REGDB_E_CLASSNOTREG ||
            result == E_NOTIMPL) {
            return PolicyAuthority::Unsupported;
        }
        return PolicyAuthority::Ambiguous;
    }
    switch (state) {
        case NET_FW_MODIFY_STATE_GP_OVERRIDE:
            return PolicyAuthority::Managed;
        case NET_FW_MODIFY_STATE_OK:
            return PolicyAuthority::NoReliableManagedOverrideEvidence;
        case NET_FW_MODIFY_STATE_INBOUND_BLOCKED:
            return PolicyAuthority::Ambiguous;
    }
    return PolicyAuthority::Ambiguous;
}

[[nodiscard]] FirewallProfileState FirewallProfileFromResult(
    const HRESULT result,
    const VARIANT_BOOL enabled
) noexcept {
    if (SUCCEEDED(result)) {
        if (enabled == VARIANT_FALSE) {
            return FirewallProfileState::Disabled;
        }
        if (enabled == VARIANT_TRUE) {
            return FirewallProfileState::Enabled;
        }
        return FirewallProfileState::Error;
    }
    if (result == E_ACCESSDENIED) {
        return FirewallProfileState::Inaccessible;
    }
    if (result == E_NOINTERFACE || result == REGDB_E_CLASSNOTREG ||
        result == E_NOTIMPL) {
        return FirewallProfileState::Unsupported;
    }
    return FirewallProfileState::Error;
}

[[nodiscard]] FirewallInspectionEvidence CollectFirewall() noexcept {
    FirewallInspectionEvidence evidence{};
    const ComApartment apartment;
    if (!apartment.usable()) {
        const FirewallProfileState state = FirewallProfileFromResult(
            apartment.error(),
            VARIANT_FALSE
        );
        evidence.profiles.fill(state);
        evidence.authority = apartment.error() == E_ACCESSDENIED
                                 ? PolicyAuthority::Inaccessible
                                 : PolicyAuthority::Unsupported;
        return evidence;
    }

    ComPointer<INetFwPolicy2> policy;
    const HRESULT create_result = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(policy.put())
    );
    if (FAILED(create_result)) {
        const FirewallProfileState state =
            FirewallProfileFromResult(create_result, VARIANT_FALSE);
        evidence.profiles.fill(state);
        evidence.authority = FirewallAuthorityFromResult(
            create_result,
            NET_FW_MODIFY_STATE_OK
        );
        return evidence;
    }

    constexpr std::array<NET_FW_PROFILE_TYPE2, 3> profiles{
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    };
    for (std::size_t index = 0; index < profiles.size(); ++index) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        const HRESULT result =
            policy->get_FirewallEnabled(profiles[index], &enabled);
        evidence.profiles[index] = FirewallProfileFromResult(result, enabled);
    }
    NET_FW_MODIFY_STATE modify_state = NET_FW_MODIFY_STATE_OK;
    const HRESULT authority_result =
        policy->get_LocalPolicyModifyState(&modify_state);
    evidence.authority =
        FirewallAuthorityFromResult(authority_result, modify_state);
    return evidence;
}

}  // namespace

InspectionResult InspectWindowsAction(const ActionId action) noexcept {
    try {
        switch (action) {
            case ActionId::DisableAutoRun:
                return EvaluateAutoRunInspection(CollectAutoRun());
            case ActionId::EnablePowerShellLogging:
                return EvaluatePowerShellLoggingInspection(
                    CollectPowerShellLogging()
                );
            case ActionId::EnableFirewallProfiles:
                return EvaluateFirewallInspection(CollectFirewall());
        }
    } catch (...) {
    }
    return {
        InspectionStatus::Ambiguous,
        L"InspectionInternalError",
        L"The selected configuration could not be inspected reliably.",
        L"No configuration state is assumed after an unexpected inspection failure.",
    };
}

}  // namespace wincur::helper
