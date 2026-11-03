#include "wincur/helper/transaction.hpp"
#include "wincur/helper/registry_security.hpp"
#include "wincur/helper/windows_transaction_store.hpp"

#include <Sddl.h>
#include <Windows.h>

#include <array>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

namespace {

constexpr wchar_t kOptInVariable[] =
    L"WINCUR_RUN_NATIVE_REGISTRY_INTEGRATION";
constexpr wchar_t kOptInValue[] =
    L"DISPOSABLE_WINDOWS_11_VM_ONLY_I_ACCEPT_HKLM_WRITES";
constexpr wchar_t kTransaction[] =
    L"2b20152f-7266-4fa0-bf5e-8c6cc87979f1";
constexpr wchar_t kUntrustedProbeTransaction[] =
    L"38e3ab04-acb5-40a4-8dda-1c9ab085233a";
constexpr wchar_t kInterruptedTransaction[] =
    L"70e7a2d4-8453-47c7-b06d-ddc6c22ff8f0";
constexpr wchar_t kMalformedTransaction[] =
    L"dfe22314-f043-4ef4-94d4-f83ec3ce0703";

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
    BOOL is_member = FALSE;
    return CheckTokenMembership(nullptr, storage.data(), &is_member) &&
           is_member != FALSE;
}

[[nodiscard]] LSTATUS ProbeRoot(const REGSAM view) {
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
    return status;
}

[[nodiscard]] bool IsAbsent(const LSTATUS status) {
    return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

[[nodiscard]] bool DeleteKnownKey(
    const std::wstring& path,
    const REGSAM view
) {
    const LSTATUS status = RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        path.c_str(),
        view,
        0
    );
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND ||
           status == ERROR_PATH_NOT_FOUND;
}

// Deletes only names that this process can create after proving the dedicated
// test roots absent. It deliberately never performs recursive deletion.
class TestNamespaceCleanup final {
public:
    TestNamespaceCleanup() = default;
    TestNamespaceCleanup(const TestNamespaceCleanup&) = delete;
    TestNamespaceCleanup& operator=(const TestNamespaceCleanup&) = delete;
    ~TestNamespaceCleanup() noexcept {
        if (owns_64_bit_ || owns_32_bit_) {
            static_cast<void>(Cleanup());
        }
    }

    void Arm(const REGSAM view) noexcept {
        if (view == KEY_WOW64_64KEY) {
            owns_64_bit_ = true;
        } else if (view == KEY_WOW64_32KEY) {
            owns_32_bit_ = true;
        }
    }

    [[nodiscard]] bool Cleanup() noexcept {
        const std::wstring root(wincur::helper::kWinCurRegistryPath);
        const std::wstring transactions =
            root + L"\\" + wincur::helper::kTransactionsSubkey;
        bool clean = true;
        if (owns_64_bit_) {
            for (const wchar_t* id : {
                     kTransaction,
                     kUntrustedProbeTransaction,
                     kInterruptedTransaction,
                     kMalformedTransaction,
                 }) {
                clean =
                    DeleteKnownKey(transactions + L"\\" + id, KEY_WOW64_64KEY) &&
                    clean;
            }
            clean = DeleteKnownKey(transactions, KEY_WOW64_64KEY) && clean;
            clean = DeleteKnownKey(root, KEY_WOW64_64KEY) && clean;
        }
        if (owns_32_bit_) {
            clean = DeleteKnownKey(root, KEY_WOW64_32KEY) && clean;
        }
        const bool absent_64 =
            !owns_64_bit_ || IsAbsent(ProbeRoot(KEY_WOW64_64KEY));
        const bool absent_32 =
            !owns_32_bit_ || IsAbsent(ProbeRoot(KEY_WOW64_32KEY));
        if (clean && absent_64 && absent_32) {
            owns_64_bit_ = false;
            owns_32_bit_ = false;
            return true;
        }
        return false;
    }

private:
    bool owns_64_bit_{false};
    bool owns_32_bit_{false};
};

[[nodiscard]] bool CreateWeakRoot(const REGSAM view) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LSTATUS status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        wincur::helper::kWinCurRegistryPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS | view,
        nullptr,
        &key,
        &disposition
    );
    if (key != nullptr) {
        RegCloseKey(key);
    }
    return status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
}

[[nodiscard]] bool CreateProtectedRoot(const REGSAM view) {
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

    HKEY key = nullptr;
    DWORD disposition = 0;
    const LSTATUS status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        wincur::helper::kWinCurRegistryPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE | REG_OPTION_OPEN_LINK,
        KEY_ALL_ACCESS | view,
        &attributes,
        &key,
        &disposition
    );
    if (key != nullptr) {
        RegCloseKey(key);
    }
    LocalFree(descriptor);
    return status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
}

}  // namespace

int wmain() {
    static_assert(
        std::wstring_view(wincur::helper::kWinCurRegistryPath) ==
            L"SOFTWARE\\WinCurNativeHelperTests",
        "The broad integration harness must never target the production root."
    );

    if (!HasExplicitOptIn()) {
        std::wcerr
            << L"Refusing HKLM integration test. Run only in a disposable "
               L"Windows 11 VM with the exact opt-in environment value.\n";
        return 77;
    }
    if (!IsAdministrator()) {
        std::wcerr << L"The opt-in integration test requires an elevated VM console.\n";
        return 77;
    }

    if (!IsAbsent(ProbeRoot(KEY_WOW64_64KEY)) ||
        !IsAbsent(ProbeRoot(KEY_WOW64_32KEY))) {
        std::wcerr << L"Refusing to alter a preexisting native-helper test root "
                      L"in either registry view.\n";
        return 77;
    }
    TestNamespaceCleanup cleanup;

    if (!CreateWeakRoot(KEY_WOW64_64KEY)) {
        std::wcerr << L"Could not create the intentionally untrusted test root.\n";
        return EXIT_FAILURE;
    }
    cleanup.Arm(KEY_WOW64_64KEY);
    wincur::helper::WindowsTransactionStorage untrusted_storage;
    if (untrusted_storage.Begin(kUntrustedProbeTransaction) !=
        wincur::helper::StorageCreateStatus::Untrusted) {
        std::wcerr << L"An inherited, untrusted preexisting root was not blocked.\n";
        return EXIT_FAILURE;
    }
    if (!cleanup.Cleanup()) {
        std::wcerr << L"Could not remove the harness-owned weak test root safely.\n";
        return EXIT_FAILURE;
    }

    // The 32-bit shadow is created before the protected 64-bit namespace. The
    // production storage must ignore it and continue to use only the 64-bit view.
    TestNamespaceCleanup protected_cleanup;
    if (!CreateWeakRoot(KEY_WOW64_32KEY)) {
        std::wcerr << L"Could not create the 32-bit shadow test root.\n";
        return EXIT_FAILURE;
    }
    protected_cleanup.Arm(KEY_WOW64_32KEY);
    if (!CreateProtectedRoot(KEY_WOW64_64KEY)) {
        std::wcerr << L"Could not exclusively create the protected test root.\n";
        return EXIT_FAILURE;
    }
    protected_cleanup.Arm(KEY_WOW64_64KEY);

    wincur::helper::Request request{};
    request.operation = wincur::helper::Operation::Preview;
    request.transaction_id = kTransaction;
    request.action = wincur::helper::ActionId::DisableAutoRun;
    const wincur::helper::TransactionResult record =
        wincur::helper::MakeNotImplementedResult(
            request,
            wincur::helper::CurrentUtcTimestamp()
        );

    wincur::helper::WindowsTransactionStorage storage;
    if (wincur::helper::PersistTransactionResult(storage, record) !=
        wincur::helper::PersistStatus::Success) {
        std::wcerr << L"Protected transaction write failed.\n";
        return EXIT_FAILURE;
    }
    const auto read =
        wincur::helper::ReadTransactionResultFromRegistry(kTransaction);
    if (read.status != wincur::helper::RegistryReadStatus::Success ||
        !read.result.has_value() ||
        read.result->message_code != L"NotImplemented") {
        std::wcerr << L"Protected transaction readback failed.\n";
        return EXIT_FAILURE;
    }
    if (IsAbsent(ProbeRoot(KEY_WOW64_32KEY))) {
        std::wcerr << L"The 64-bit store unexpectedly altered the 32-bit shadow root.\n";
        return EXIT_FAILURE;
    }

    wincur::helper::WindowsTransactionStorage replay_storage;
    if (wincur::helper::PersistTransactionResult(replay_storage, record) !=
        wincur::helper::PersistStatus::Duplicate) {
        std::wcerr << L"Duplicate transaction UUID was not rejected.\n";
        return EXIT_FAILURE;
    }

    {
        wincur::helper::WindowsTransactionStorage interrupted;
        if (interrupted.Begin(kInterruptedTransaction) !=
            wincur::helper::StorageCreateStatus::Created ||
            !interrupted.Write({
                L"SchemaVersion",
                wincur::helper::TransactionValueType::Dword,
                wincur::helper::kTransactionSchemaVersion,
                {},
            })) {
            std::wcerr << L"Could not create interrupted transaction fixture.\n";
            return EXIT_FAILURE;
        }
    }
    if (wincur::helper::ReadTransactionResultFromRegistry(kInterruptedTransaction)
            .status != wincur::helper::RegistryReadStatus::Incomplete) {
        std::wcerr << L"Interrupted transaction was not classified incomplete.\n";
        return EXIT_FAILURE;
    }

    {
        wincur::helper::WindowsTransactionStorage malformed;
        if (malformed.Begin(kMalformedTransaction) !=
            wincur::helper::StorageCreateStatus::Created ||
            !malformed.Write({
                L"Complete",
                wincur::helper::TransactionValueType::Dword,
                1,
                {},
            })) {
            std::wcerr << L"Could not create malformed transaction fixture.\n";
            return EXIT_FAILURE;
        }
    }
    if (wincur::helper::ReadTransactionResultFromRegistry(kMalformedTransaction)
            .status != wincur::helper::RegistryReadStatus::Malformed) {
        std::wcerr << L"Malformed completed transaction was not rejected.\n";
        return EXIT_FAILURE;
    }

    if (!protected_cleanup.Cleanup()) {
        std::wcerr << L"Exact non-recursive test-namespace cleanup failed.\n";
        return EXIT_FAILURE;
    }

    std::wcout
        << L"Dedicated-namespace ACL, replay, registry-view isolation, "
           L"interrupted-write, malformed-record, and safe cleanup tests passed.\n";
    return EXIT_SUCCESS;
}
