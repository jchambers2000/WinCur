#include "wincur/helper/windows_management_posture.hpp"

#include <Windows.h>
#include <CommCtrl.h>
#include <initguid.h>
#include <gpedit.h>
#include <lm.h>
#include <mdmregistration.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

namespace wincur::helper {
namespace {

constexpr std::size_t kMaximumRsopObjects = 4096;
constexpr std::size_t kMaximumRegistryPathCharacters = 512;
constexpr std::size_t kMaximumValueNameCharacters = 128;
constexpr std::size_t kMaximumAttributionCharacters = 1024;

struct FixedTarget final {
    const wchar_t* key;
    const wchar_t* value;
};

struct LocalGroupPolicyCollection final {
    ProviderEvidence provider{};
    ProviderDiagnostics diagnostics{};
    std::array<bool, kFixedPolicyTargetCount> matches{};
};

constexpr std::array<FixedTarget, kFixedPolicyTargetCount> kFixedTargets{{
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
     L"NoDriveTypeAutoRun"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
     L"NoAutorun"},
    {L"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
     L"EnableScriptBlockLogging"},
    {L"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
     L"EnableModuleLogging"},
    {L"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames",
     L"*"},
}};

template <typename T> class ComPointer final {
public:
    ComPointer() = default;
    ComPointer(const ComPointer&) = delete;
    ComPointer& operator=(const ComPointer&) = delete;
    ~ComPointer() noexcept {
        if (value_ != nullptr) {
            value_->Release();
        }
    }
    [[nodiscard]] T* get() const noexcept { return value_; }
    [[nodiscard]] T** put() noexcept { return &value_; }
    [[nodiscard]] T* operator->() const noexcept { return value_; }

private:
    T* value_{nullptr};
};

class ComApartment final {
public:
    explicit ComApartment(
        const DWORD model = COINIT_MULTITHREADED
    ) noexcept : result_(CoInitializeEx(nullptr, model)) {
        owns_ = result_ == S_OK || result_ == S_FALSE;
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;
    ~ComApartment() noexcept {
        if (owns_) {
            CoUninitialize();
        }
    }
    [[nodiscard]] bool usable() const noexcept {
        return SUCCEEDED(result_);
    }
    [[nodiscard]] HRESULT result() const noexcept { return result_; }

private:
    HRESULT result_{E_FAIL};
    bool owns_{false};
};

class Bstr final {
public:
    explicit Bstr(const wchar_t* const value) noexcept
        : value_(SysAllocString(value)) {}
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    ~Bstr() noexcept { SysFreeString(value_); }
    [[nodiscard]] BSTR get() const noexcept { return value_; }
    [[nodiscard]] bool valid() const noexcept { return value_ != nullptr; }

private:
    BSTR value_{nullptr};
};

class Variant final {
public:
    Variant() noexcept { VariantInit(&value_); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;
    ~Variant() noexcept { VariantClear(&value_); }
    [[nodiscard]] VARIANT* put() noexcept { return &value_; }
    [[nodiscard]] const VARIANT& get() const noexcept { return value_; }

private:
    VARIANT value_{};
};

[[nodiscard]] std::uint32_t ErrorCode(const HRESULT value) noexcept {
    return static_cast<std::uint32_t>(value);
}

[[nodiscard]] ProviderHealth HealthFromHresult(const HRESULT value) noexcept {
    if (value == E_ACCESSDENIED || value == WBEM_E_ACCESS_DENIED) {
        return ProviderHealth::AccessDenied;
    }
    if (value == E_NOTIMPL || value == E_NOINTERFACE ||
        value == REGDB_E_CLASSNOTREG || value == WBEM_E_INVALID_NAMESPACE ||
        value == WBEM_E_INVALID_CLASS || value == WBEM_E_NOT_SUPPORTED) {
        return ProviderHealth::Unsupported;
    }
    return ProviderHealth::Failed;
}

[[nodiscard]] ProviderEvidence FailedProvider(const HRESULT value) noexcept {
    return {
        HealthFromHresult(value),
        EvidenceFreshness::NotApplicable,
        ErrorCode(value),
        false,
    };
}

[[nodiscard]] ProviderEvidence FailedProviderStatus(const LSTATUS value) noexcept {
    const ProviderHealth health = value == ERROR_ACCESS_DENIED
                                      ? ProviderHealth::AccessDenied
                                      : ProviderHealth::Failed;
    return {
        health,
        EvidenceFreshness::NotApplicable,
        static_cast<std::uint32_t>(value),
        false,
    };
}

[[nodiscard]] bool EqualsInsensitive(
    const std::wstring_view left,
    const std::wstring_view right
) noexcept {
    if (left.size() != right.size() ||
        left.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    return CompareStringOrdinal(
               left.data(),
               static_cast<int>(left.size()),
               right.data(),
               static_cast<int>(right.size()),
               TRUE
           ) == CSTR_EQUAL;
}

[[nodiscard]] std::wstring_view NormalizeMachineRegistryPath(
    std::wstring_view path
) noexcept {
    constexpr std::array prefixes{
        std::wstring_view{L"HKEY_LOCAL_MACHINE\\"},
        std::wstring_view{L"HKLM\\"},
        std::wstring_view{L"MACHINE\\"},
    };
    for (const std::wstring_view prefix : prefixes) {
        if (path.size() >= prefix.size() &&
            EqualsInsensitive(path.substr(0, prefix.size()), prefix)) {
            path.remove_prefix(prefix.size());
            break;
        }
    }
    return path;
}

[[nodiscard]] bool FindTarget(
    const std::wstring_view registry_path,
    const std::wstring_view value_name,
    std::size_t* const index
) noexcept {
    const std::wstring_view normalized =
        NormalizeMachineRegistryPath(registry_path);
    for (std::size_t candidate = 0; candidate < kFixedTargets.size();
         ++candidate) {
        if (EqualsInsensitive(normalized, kFixedTargets[candidate].key) &&
            EqualsInsensitive(value_name, kFixedTargets[candidate].value)) {
            *index = candidate;
            return true;
        }
    }
    return false;
}

[[nodiscard]] ProviderEvidence CollectDomainMembership(
    DomainMembership* const membership
) noexcept {
    LPWSTR joined_name = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    const NET_API_STATUS result =
        NetGetJoinInformation(nullptr, &joined_name, &status);
    if (joined_name != nullptr) {
        NetApiBufferFree(joined_name);
    }
    if (result != NERR_Success) {
        *membership = DomainMembership::Unknown;
        return {
            ProviderHealth::Failed,
            EvidenceFreshness::NotApplicable,
            static_cast<std::uint32_t>(result),
            false,
        };
    }
    switch (status) {
        case NetSetupUnjoined:
            *membership = DomainMembership::Unjoined;
            break;
        case NetSetupWorkgroupName:
            *membership = DomainMembership::Workgroup;
            break;
        case NetSetupDomainName:
            *membership = DomainMembership::Domain;
            break;
        case NetSetupUnknownStatus:
        default:
            *membership = DomainMembership::Unknown;
            return {
                ProviderHealth::Failed,
                EvidenceFreshness::NotApplicable,
                ERROR_INVALID_DATA,
                false,
            };
    }
    return {
        ProviderHealth::Healthy,
        EvidenceFreshness::NotApplicable,
        ERROR_SUCCESS,
        true,
    };
}

[[nodiscard]] ProviderEvidence CollectMdmRegistration(
    MdmRegistration* const registration
) noexcept {
    BOOL registered = FALSE;
    const HRESULT result =
        IsDeviceRegisteredWithManagement(&registered, 0, nullptr);
    if (FAILED(result)) {
        *registration = MdmRegistration::Unknown;
        return FailedProvider(result);
    }
    *registration = registered == FALSE ? MdmRegistration::NotRegistered
                                        : MdmRegistration::Registered;
    return {
        ProviderHealth::Healthy,
        EvidenceFreshness::NotApplicable,
        ERROR_SUCCESS,
        true,
    };
}

[[nodiscard]] ProviderEvidence CollectLocalGroupPolicy(
    std::array<bool, kFixedPolicyTargetCount>* const matches,
    ProviderDiagnostics* const diagnostics,
    const DWORD apartment_model = COINIT_MULTITHREADED
) noexcept {
    matches->fill(false);
    *diagnostics = {};
    const ComApartment apartment(apartment_model);
    if (!apartment.usable()) {
        diagnostics->stage = ProviderFailureStage::ComInitialization;
        diagnostics->raw_result = ErrorCode(apartment.result());
        const auto provider = FailedProvider(apartment.result());
        diagnostics->structurally_consistent =
            IsLocalGroupPolicyDiagnosticConsistent(provider, *diagnostics);
        return provider;
    }
    ComPointer<IGroupPolicyObject> policy;
    HRESULT result = CoCreateInstance(
        CLSID_GroupPolicyObject,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IGroupPolicyObject,
        reinterpret_cast<void**>(policy.put())
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::ComActivation;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsLocalGroupPolicyDiagnosticConsistent(provider, *diagnostics);
        return provider;
    }
    result = policy->OpenLocalMachineGPO(
        GPO_OPEN_LOAD_REGISTRY | GPO_OPEN_READ_ONLY
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::OpenLocalMachineGpo;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsLocalGroupPolicyDiagnosticConsistent(provider, *diagnostics);
        return provider;
    }
    HKEY root = nullptr;
    result = policy->GetRegistryKey(GPO_SECTION_MACHINE, &root);
    if (FAILED(result) || root == nullptr) {
        if (root != nullptr) {
            RegCloseKey(root);
        }
        const HRESULT failure = FAILED(result) ? result : E_UNEXPECTED;
        diagnostics->stage = ProviderFailureStage::GetRegistryKey;
        diagnostics->raw_result = ErrorCode(failure);
        const auto provider = FailedProvider(failure);
        diagnostics->structurally_consistent =
            IsLocalGroupPolicyDiagnosticConsistent(provider, *diagnostics);
        return provider;
    }
    for (std::size_t index = 0; index < kFixedTargets.size(); ++index) {
        HKEY key = nullptr;
        LSTATUS status = RegOpenKeyExW(
            root,
            kFixedTargets[index].key,
            0,
            KEY_QUERY_VALUE,
            &key
        );
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
            continue;
        }
        if (status != ERROR_SUCCESS) {
            RegCloseKey(root);
            diagnostics->stage = ProviderFailureStage::RegistryQuery;
            diagnostics->raw_result = static_cast<std::uint32_t>(status);
            const auto provider = FailedProviderStatus(status);
            diagnostics->structurally_consistent =
                IsLocalGroupPolicyDiagnosticConsistent(
                    provider, *diagnostics);
            return provider;
        }
        DWORD type = 0;
        DWORD size = 0;
        status = RegQueryValueExW(
            key,
            kFixedTargets[index].value,
            nullptr,
            &type,
            nullptr,
            &size
        );
        RegCloseKey(key);
        if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA) {
            (*matches)[index] = true;
        } else if (status != ERROR_FILE_NOT_FOUND) {
            RegCloseKey(root);
            diagnostics->stage = ProviderFailureStage::RegistryQuery;
            diagnostics->raw_result = static_cast<std::uint32_t>(status);
            const auto provider = FailedProviderStatus(status);
            diagnostics->structurally_consistent =
                IsLocalGroupPolicyDiagnosticConsistent(
                    provider, *diagnostics);
            return provider;
        }
    }
    RegCloseKey(root);
    const ProviderEvidence provider{
        ProviderHealth::Healthy,
        EvidenceFreshness::NotApplicable,
        ERROR_SUCCESS,
        true,
    };
    diagnostics->stage = ProviderFailureStage::Completed;
    diagnostics->normal_termination = true;
    diagnostics->structurally_consistent =
        IsLocalGroupPolicyDiagnosticConsistent(provider, *diagnostics);
    return provider;
}

[[nodiscard]] LocalGroupPolicyCollection
CollectLocalGroupPolicyOnDedicatedSta() noexcept {
    LocalGroupPolicyCollection result{};
    try {
        std::thread collection_thread([&result]() noexcept {
            result.provider = CollectLocalGroupPolicy(
                &result.matches,
                &result.diagnostics,
                COINIT_APARTMENTTHREADED
            );
        });
        collection_thread.join();
    } catch (...) {
        result.provider = FailedProvider(E_UNEXPECTED);
        result.diagnostics.stage =
            ProviderFailureStage::ComInitialization;
        result.diagnostics.raw_result = ErrorCode(E_UNEXPECTED);
        result.diagnostics.structurally_consistent =
            IsLocalGroupPolicyDiagnosticConsistent(
                result.provider, result.diagnostics);
    }
    return result;
}

[[nodiscard]] bool ReadBoundedBstr(
    IWbemClassObject* const object,
    const wchar_t* const property,
    const std::size_t maximum,
    std::wstring* const output
) noexcept {
    Variant value;
    if (FAILED(object->Get(property, 0, value.put(), nullptr, nullptr)) ||
        value.get().vt != VT_BSTR || value.get().bstrVal == nullptr) {
        return false;
    }
    const UINT length = SysStringLen(value.get().bstrVal);
    if (length == 0 || static_cast<std::size_t>(length) > maximum) {
        return false;
    }
    const std::wstring_view view(value.get().bstrVal, length);
    if (std::find(view.begin(), view.end(), L'\0') != view.end()) {
        return false;
    }
    output->assign(view);
    return true;
}

[[nodiscard]] bool ValidAttributionRecord(
    IWbemClassObject* const object
) noexcept {
    std::wstring gpo_id;
    std::wstring scope_id;
    std::wstring creation_time;
    if (!ReadBoundedBstr(
            object, L"GPOID", kMaximumAttributionCharacters, &gpo_id) ||
        !ReadBoundedBstr(
            object, L"SOMID", kMaximumAttributionCharacters, &scope_id) ||
        !ReadBoundedBstr(object, L"creationTime", 64, &creation_time)) {
        return false;
    }
    Variant precedence;
    if (FAILED(object->Get(
            L"precedence", 0, precedence.put(), nullptr, nullptr))) {
        return false;
    }
    const VARTYPE type = precedence.get().vt;
    return type == VT_UI4 ||
           (type == VT_I4 && precedence.get().lVal >= 0);
}

[[nodiscard]] ProviderEvidence CollectRsop(
    std::array<bool, kFixedPolicyTargetCount>* const matches,
    ProviderDiagnostics* const diagnostics
) noexcept {
    matches->fill(false);
    *diagnostics = {};
    const ComApartment apartment;
    if (!apartment.usable()) {
        diagnostics->stage = ProviderFailureStage::ComInitialization;
        diagnostics->raw_result = ErrorCode(apartment.result());
        const auto provider = FailedProvider(apartment.result());
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    const HRESULT security = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );
    if (FAILED(security) && security != RPC_E_TOO_LATE) {
        diagnostics->stage = ProviderFailureStage::ProxySecurity;
        diagnostics->raw_result = ErrorCode(security);
        const auto provider = FailedProvider(security);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    ComPointer<IWbemLocator> locator;
    HRESULT result = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(locator.put())
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::ComActivation;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    Bstr namespace_name(L"ROOT\\RSOP\\Computer");
    if (!namespace_name.valid()) {
        diagnostics->stage = ProviderFailureStage::WmiConnection;
        diagnostics->raw_result = ErrorCode(E_OUTOFMEMORY);
        const auto provider = FailedProvider(E_OUTOFMEMORY);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    ComPointer<IWbemServices> services;
    result = locator->ConnectServer(
        namespace_name.get(),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        services.put()
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::WmiConnection;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    result = CoSetProxyBlanket(
        services.get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::ProxySecurity;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    Bstr language(L"WQL");
    Bstr query(
        L"SELECT registryKey,valueName,GPOID,SOMID,precedence,creationTime "
        L"FROM RSOP_RegistryPolicySetting"
    );
    if (!language.valid() || !query.valid()) {
        diagnostics->stage = ProviderFailureStage::ExecQuery;
        diagnostics->raw_result = ErrorCode(E_OUTOFMEMORY);
        const auto provider = FailedProvider(E_OUTOFMEMORY);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }
    ComPointer<IEnumWbemClassObject> enumerator;
    result = services->ExecQuery(
        language.get(),
        query.get(),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        enumerator.put()
    );
    if (FAILED(result)) {
        diagnostics->stage = ProviderFailureStage::ExecQuery;
        diagnostics->raw_result = ErrorCode(result);
        const auto provider = FailedProvider(result);
        diagnostics->structurally_consistent =
            IsProviderEvidenceConsistent(provider, true);
        return provider;
    }

    std::size_t object_count = 0;
    for (;;) {
        ComPointer<IWbemClassObject> object;
        ULONG returned = 0;
        result = enumerator->Next(5000, 1, object.put(), &returned);
        diagnostics->stage = ProviderFailureStage::Enumeration;
        diagnostics->raw_result = ErrorCode(result);
        diagnostics->returned_object_count = returned;
        const auto disposition = ClassifyWmiEnumerationResult(
            ErrorCode(result), returned, object.get() != nullptr);
        if (disposition == WmiEnumerationDisposition::NormalEnd) {
            diagnostics->normal_termination = true;
            break;
        }
        if (disposition != WmiEnumerationDisposition::Object) {
            const HRESULT failure =
                disposition == WmiEnumerationDisposition::Timeout
                    ? HRESULT_FROM_WIN32(WAIT_TIMEOUT)
                    : disposition == WmiEnumerationDisposition::Malformed
                          ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA)
                          : result;
            const auto provider = FailedProvider(failure);
            diagnostics->structurally_consistent =
                disposition != WmiEnumerationDisposition::Malformed &&
                IsProviderEvidenceConsistent(provider, true);
            return provider;
        }
        if (object_count >= kMaximumRsopObjects) {
            const HRESULT failure = HRESULT_FROM_WIN32(ERROR_MORE_DATA);
            diagnostics->raw_result = ErrorCode(failure);
            const auto provider = FailedProvider(failure);
            diagnostics->structurally_consistent =
                IsProviderEvidenceConsistent(provider, true);
            return provider;
        }
        ++object_count;

        std::wstring registry_path;
        std::wstring value_name;
        if (!ReadBoundedBstr(
                object.get(),
                L"registryKey",
                kMaximumRegistryPathCharacters,
                &registry_path
            ) ||
            !ReadBoundedBstr(
                object.get(),
                L"valueName",
                kMaximumValueNameCharacters,
                &value_name
            )) {
            const HRESULT failure = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            diagnostics->raw_result = ErrorCode(failure);
            const auto provider = FailedProvider(failure);
            diagnostics->structurally_consistent =
                IsProviderEvidenceConsistent(provider, true);
            return provider;
        }
        std::size_t target_index = 0;
        if (FindTarget(registry_path, value_name, &target_index)) {
            if (!ValidAttributionRecord(object.get())) {
                const HRESULT failure =
                    HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                diagnostics->raw_result = ErrorCode(failure);
                const auto provider = FailedProvider(failure);
                diagnostics->structurally_consistent =
                    IsProviderEvidenceConsistent(provider, true);
                return provider;
            }
            (*matches)[target_index] = true;
        }
    }
    const ProviderEvidence provider{
        ProviderHealth::Healthy,
        // RSOP_RegistryPolicySetting exposes creationTime, but Microsoft does
        // not define it as a freshness guarantee for absence of a target.
        EvidenceFreshness::Unknown,
        ERROR_SUCCESS,
        true,
    };
    diagnostics->stage = ProviderFailureStage::Completed;
    diagnostics->structurally_consistent =
        IsProviderEvidenceConsistent(provider, true);
    return provider;
}

}  // namespace

WmiEnumerationDisposition ClassifyWmiEnumerationResult(
    const std::uint32_t raw_result,
    const std::uint32_t returned_object_count,
    const bool object_present
) noexcept {
    const HRESULT result = static_cast<HRESULT>(raw_result);
    if (result == WBEM_S_TIMEDOUT) {
        return WmiEnumerationDisposition::Timeout;
    }
    if (FAILED(result)) {
        return WmiEnumerationDisposition::Failure;
    }
    if (result == WBEM_S_FALSE && returned_object_count == 0 &&
        !object_present) {
        return WmiEnumerationDisposition::NormalEnd;
    }
    if (result == WBEM_S_NO_ERROR && returned_object_count == 1 &&
        object_present) {
        return WmiEnumerationDisposition::Object;
    }
    return WmiEnumerationDisposition::Malformed;
}

LocalGroupPolicyApartmentDiagnostic
InspectLocalGroupPolicyApartmentsForDiagnostics() noexcept {
    LocalGroupPolicyApartmentDiagnostic result{};
    std::array<bool, kFixedPolicyTargetCount> ignored_matches{};
    result.mta_provider = CollectLocalGroupPolicy(
        &ignored_matches,
        &result.mta_diagnostics,
        COINIT_MULTITHREADED
    );
    try {
        std::thread sta_thread([&result]() noexcept {
            std::array<bool, kFixedPolicyTargetCount> thread_matches{};
            result.sta_provider = CollectLocalGroupPolicy(
                &thread_matches,
                &result.sta_diagnostics,
                COINIT_APARTMENTTHREADED
            );
        });
        sta_thread.join();
    } catch (...) {
        result.sta_provider = FailedProvider(E_UNEXPECTED);
        result.sta_diagnostics.stage =
            ProviderFailureStage::ComInitialization;
        result.sta_diagnostics.raw_result = ErrorCode(E_UNEXPECTED);
        result.sta_diagnostics.structurally_consistent = true;
    }
    return result;
}

ManagementPostureResult InspectWindowsManagementPosture() noexcept {
    try {
        ManagementPostureInput input{};
        input.domain_provider =
            CollectDomainMembership(&input.domain_membership);
        input.mdm_provider = CollectMdmRegistration(&input.mdm_registration);
        const LocalGroupPolicyCollection local_group_policy =
            CollectLocalGroupPolicyOnDedicatedSta();
        input.local_group_policy_provider = local_group_policy.provider;
        input.local_group_policy_diagnostics =
            local_group_policy.diagnostics;
        input.local_group_policy_matches = local_group_policy.matches;
        input.rsop_provider = CollectRsop(
            &input.rsop_matches, &input.rsop_diagnostics);
        return EvaluateManagementPosture(input);
    } catch (...) {
        ManagementPostureInput failed{};
        failed.domain_provider = FailedProvider(E_UNEXPECTED);
        failed.mdm_provider = FailedProvider(E_UNEXPECTED);
        failed.local_group_policy_provider = FailedProvider(E_UNEXPECTED);
        failed.rsop_provider = FailedProvider(E_UNEXPECTED);
        return EvaluateManagementPosture(failed);
    }
}

}  // namespace wincur::helper
