#include "wincur/helper/windows_capsule_capture.hpp"

#include "wincur/helper/windows_inspection.hpp"

#include <Windows.h>
#include <netfw.h>

#include <array>
#include <vector>

namespace wincur::helper {
namespace {

constexpr wchar_t kAutoRunPath[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
constexpr wchar_t kScriptBlockPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
constexpr wchar_t kModulePath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging";
constexpr wchar_t kModuleNamesPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames";

class Key final {
public:
    ~Key() noexcept { if (value_) RegCloseKey(value_); }
    [[nodiscard]] HKEY* put() noexcept { return &value_; }
    [[nodiscard]] HKEY get() const noexcept { return value_; }
private:
    HKEY value_{nullptr};
};

[[nodiscard]] bool IsLink(HKEY key) noexcept {
    DWORD type = 0, size = 0;
    return RegQueryValueExW(key, L"SymbolicLinkValue", nullptr, &type, nullptr, &size)
           != ERROR_FILE_NOT_FOUND;
}

[[nodiscard]] bool ReadExact(
    const wchar_t* path, const wchar_t* name,
    RegistryValueState& output, PolicyAuthority& authority
) noexcept {
    Key key;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, REG_OPTION_OPEN_LINK,
        KEY_QUERY_VALUE | kInspectionRegistryView, key.put());
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        output = {false, false, 0, {}};
        return true;
    }
    if (status != ERROR_SUCCESS || IsLink(key.get())) {
        SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_REPARSE_DATA
                                             : static_cast<DWORD>(status));
        authority = status == ERROR_ACCESS_DENIED
                        ? PolicyAuthority::Inaccessible
                        : PolicyAuthority::Ambiguous;
        return false;
    }
    output.key_exists = true;
    DWORD type = 0, size = 0;
    status = RegQueryValueExW(key.get(), name, nullptr, &type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) {
        output.value_exists = false;
        return true;
    }
    if (status != ERROR_SUCCESS || size > kMaximumCapsuleValueBytes) {
        SetLastError(status == ERROR_SUCCESS ? ERROR_BUFFER_OVERFLOW
                                             : static_cast<DWORD>(status));
        authority = status == ERROR_ACCESS_DENIED
                        ? PolicyAuthority::Inaccessible
                        : PolicyAuthority::Ambiguous;
        return false;
    }
    try {
        output.data.resize(size);
        DWORD actual_type = type, actual_size = size;
        status = RegQueryValueExW(key.get(), name, nullptr, &actual_type,
            output.data.data(), &actual_size);
        if (status != ERROR_SUCCESS || actual_type != type || actual_size != size) {
            SetLastError(status == ERROR_SUCCESS ? ERROR_INVALID_DATA
                                                 : static_cast<DWORD>(status));
            authority = PolicyAuthority::Ambiguous;
            return false;
        }
        output.value_exists = true;
        output.type = type;
        return true;
    } catch (...) {
        SetLastError(ERROR_OUTOFMEMORY);
        authority = PolicyAuthority::Ambiguous;
        return false;
    }
}

class Apartment final {
public:
    Apartment() noexcept {
        const HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        usable_ = result == S_OK || result == S_FALSE || result == RPC_E_CHANGED_MODE;
        uninitialize_ = result == S_OK || result == S_FALSE;
    }
    ~Apartment() noexcept { if (uninitialize_) CoUninitialize(); }
    [[nodiscard]] bool usable() const noexcept { return usable_; }
private:
    bool usable_{false};
    bool uninitialize_{false};
};

template <typename T> class ComPtr final {
public:
    ~ComPtr() noexcept { if (value_) value_->Release(); }
    [[nodiscard]] T** put() noexcept { return &value_; }
    [[nodiscard]] T* operator->() const noexcept { return value_; }
private:
    T* value_{nullptr};
};

[[nodiscard]] bool CaptureFirewall(PreChangeCapsule& capsule) noexcept {
    Apartment apartment;
    if (!apartment.usable()) return false;
    ComPtr<INetFwPolicy2> policy;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(policy.put())))) return false;
    NET_FW_MODIFY_STATE modify = NET_FW_MODIFY_STATE_OK;
    const HRESULT authority = policy->get_LocalPolicyModifyState(&modify);
    if (FAILED(authority)) {
        capsule.authority = authority == E_ACCESSDENIED
                                ? PolicyAuthority::Inaccessible
                                : PolicyAuthority::Ambiguous;
    } else if (modify == NET_FW_MODIFY_STATE_GP_OVERRIDE) {
        capsule.authority = PolicyAuthority::Managed;
    } else if (modify == NET_FW_MODIFY_STATE_OK) {
        capsule.authority = PolicyAuthority::NoReliableManagedOverrideEvidence;
    } else {
        capsule.authority = PolicyAuthority::Ambiguous;
    }
    constexpr std::array<NET_FW_PROFILE_TYPE2, 3> profiles{
        NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    for (std::size_t i = 0; i < profiles.size(); ++i) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        const HRESULT result = policy->get_FirewallEnabled(profiles[i], &enabled);
        if (FAILED(result) || (enabled != VARIANT_TRUE && enabled != VARIANT_FALSE))
            capsule.firewall_profiles[i].effective = ObservedState::Unavailable;
        else
            capsule.firewall_profiles[i].effective = enabled == VARIANT_TRUE
                ? ObservedState::Enabled : ObservedState::Disabled;
        // INetFwPolicy2 exposes effective state and the overall modify authority,
        // but not an unambiguous per-profile local value suitable for rollback.
        capsule.firewall_profiles[i].local = ObservedState::NotEstablished;
    }
    return true;
}

}  // namespace

std::optional<PreChangeCapsule> CaptureWindowsPreChangeState(
    ActionId action, std::wstring capsule_id, std::wstring transaction_id,
    std::wstring created_utc
) noexcept {
    try {
        PreChangeCapsule result{};
        result.capsule_id = std::move(capsule_id);
        result.transaction_id = std::move(transaction_id);
        result.action = action;
        result.helper_version = std::wstring(kHelperVersion);
        result.build_identity = std::wstring(kCapsuleBuildIdentity);
        result.created_utc = std::move(created_utc);
        // These fixed policy paths can be populated by local policy, domain
        // policy, MDM, or an administrator. A registry read does not establish
        // ownership, so capture preserves the bytes but does not authorize a
        // future write.
        result.authority = PolicyAuthority::Ambiguous;
        if (action == ActionId::EnableFirewallProfiles) {
            result.kind = ExactStateKind::Firewall;
            result.target_count = 3;
            if (!CaptureFirewall(result)) return std::nullopt;
            return result;
        }
        result.kind = ExactStateKind::Registry;
        if (action == ActionId::DisableAutoRun) {
            result.target_count = 2;
            if (!ReadExact(kAutoRunPath, L"NoDriveTypeAutoRun",
                    result.registry_values[0], result.authority) ||
                !ReadExact(kAutoRunPath, L"NoAutorun",
                    result.registry_values[1], result.authority)) return std::nullopt;
        } else {
            result.target_count = 3;
            if (!ReadExact(kScriptBlockPath, L"EnableScriptBlockLogging",
                    result.registry_values[0], result.authority) ||
                !ReadExact(kModulePath, L"EnableModuleLogging",
                    result.registry_values[1], result.authority) ||
                !ReadExact(kModuleNamesPath, L"*",
                    result.registry_values[2], result.authority)) return std::nullopt;
        }
        return result;
    } catch (...) { return std::nullopt; }
}

}  // namespace wincur::helper
