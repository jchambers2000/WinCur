#include "wincur/helper/registry_security.hpp"
#include "wincur/helper/transaction.hpp"
#include "wincur/helper/windows_transaction_store.hpp"

#include <Sddl.h>
#include <Windows.h>

#include <array>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <string_view>

namespace {

constexpr wchar_t kOptInVariable[] =
    L"WINCUR_RUN_PRODUCTION_PATH_ACCEPTANCE";
constexpr wchar_t kOptInValue[] =
    L"DISPOSABLE_WINDOWS_11_VM_ONLY_I_ACCEPT_PRODUCTION_PATH_HKLM_WRITES";
constexpr wchar_t kTransaction[] =
    L"fb1e2b15-58eb-41c7-b252-26f98ee22e58";

[[nodiscard]] bool HasExplicitOptIn() {
    wchar_t value[128]{};
    const DWORD length = GetEnvironmentVariableW(
        kOptInVariable,
        value,
        static_cast<DWORD>(std::size(value))
    );
    return length == std::wcslen(kOptInValue) &&
           std::wstring_view(value, length) == kOptInValue;
}

[[nodiscard]] bool IsAdministrator() {
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> storage{};
    DWORD size = static_cast<DWORD>(storage.size());
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            nullptr,
            storage.data(),
            &size
        )) {
        return false;
    }
    BOOL member = FALSE;
    return CheckTokenMembership(nullptr, storage.data(), &member) && member != FALSE;
}

[[nodiscard]] bool RootIsAbsent(const REGSAM view) {
    HKEY key = nullptr;
    const LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        wincur::helper::kWinCurRegistryPath,
        REG_OPTION_OPEN_LINK,
        KEY_READ | view,
        &key
    );
    if (key != nullptr) {
        RegCloseKey(key);
    }
    return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

[[nodiscard]] bool ExclusivelyCreateProtectedProductionRoot() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wincur::helper::kPublicRegistrySecurityDescriptor,
            SDDL_REVISION_1,
            &descriptor,
            nullptr
        )) {
        return false;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;

    HKEY software = nullptr;
    HKEY root = nullptr;
    DWORD disposition = 0;
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE",
        REG_OPTION_OPEN_LINK,
        KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        &software
    );
    if (status == ERROR_SUCCESS) {
        status = RegCreateKeyExW(
            software,
            wincur::helper::kWinCurRegistryRootName,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE | REG_OPTION_OPEN_LINK,
            KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
            &attributes,
            &root,
            &disposition
        );
    }
    if (root != nullptr) {
        RegCloseKey(root);
    }
    if (software != nullptr) {
        RegCloseKey(software);
    }
    LocalFree(descriptor);
    return status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
}

}  // namespace

int wmain() {
    static_assert(
        std::wstring_view(wincur::helper::kWinCurRegistryPath) ==
            L"SOFTWARE\\WinCur",
        "Production-path acceptance must use the production registry root."
    );
    if (!HasExplicitOptIn() || !IsAdministrator()) {
        std::wcerr << L"Production-path acceptance requires its exact opt-in and "
                      L"an elevated disposable-VM console.\n";
        return 77;
    }
    if (!RootIsAbsent(KEY_WOW64_64KEY) || !RootIsAbsent(KEY_WOW64_32KEY)) {
        std::wcerr << L"Refusing to touch preexisting WinCur data in either view.\n";
        return 77;
    }
    if (!ExclusivelyCreateProtectedProductionRoot()) {
        std::wcerr << L"Could not exclusively create the protected production root.\n";
        return EXIT_FAILURE;
    }

    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Preview;
    request.transaction_id = kTransaction;
    request.action = wincur::helper::ActionId::DisableAutoRun;
    const auto record = wincur::helper::MakeNotImplementedResult(
        request,
        wincur::helper::CurrentUtcTimestamp()
    );
    wincur::helper::WindowsTransactionStorage storage;
    if (wincur::helper::PersistTransactionResult(storage, record) !=
        wincur::helper::PersistStatus::Success) {
        std::wcerr << L"Production-path protected write failed.\n";
        return EXIT_FAILURE;
    }
    const auto read =
        wincur::helper::ReadTransactionResultFromRegistry(kTransaction);
    if (read.status != wincur::helper::RegistryReadStatus::Success ||
        !read.result.has_value() || read.result->message_code != L"NotImplemented") {
        std::wcerr << L"Production-path readback failed.\n";
        return EXIT_FAILURE;
    }

    std::wcout << L"Minimal production-path protected write/read passed. The record "
                   L"was intentionally retained; revert the VM snapshot.\n";
    return EXIT_SUCCESS;
}
