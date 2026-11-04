#include "wincur/helper/windows_capsule_capture.hpp"
#include "wincur/helper/windows_capsule_store.hpp"
#include "wincur/helper/windows_transaction_store.hpp"
#include "wincur/helper/windows_uuid.hpp"

#include <Windows.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

namespace {
using namespace wincur::helper;

[[nodiscard]] int Fail(
    const int code,
    const wchar_t* operation,
    const long detail,
    const DWORD windows_error = ERROR_SUCCESS
) {
    std::wcerr << L"FAIL [exit " << code << L"] operation=" << operation
               << L" detail=" << detail << L" windows_error=" << windows_error
               << L" (0x" << std::hex << windows_error << std::dec << L")\n";
    return code;
}

[[nodiscard]] bool TestRootAbsent(LSTATUS& observed_status) {
    HKEY key = nullptr;
    observed_status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWinCurRegistryPath,
        REG_OPTION_OPEN_LINK, KEY_READ | KEY_WOW64_64KEY, &key);
    if (key) RegCloseKey(key);
    return observed_status == ERROR_FILE_NOT_FOUND ||
           observed_status == ERROR_PATH_NOT_FOUND;
}

[[nodiscard]] bool Cleanup(const std::wstring& id) {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWinCurRegistryPath, 0,
            KEY_WRITE | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS) return false;
    HKEY rollback = nullptr;
    if (RegOpenKeyExW(root, kRollbackCapsulesSubkey, 0,
            KEY_WRITE | KEY_WOW64_64KEY, &rollback) != ERROR_SUCCESS) {
        RegCloseKey(root); return false;
    }
    const LSTATUS child = RegDeleteKeyExW(rollback, id.c_str(), KEY_WOW64_64KEY, 0);
    RegCloseKey(rollback);
    const LSTATUS parent = RegDeleteKeyExW(root, kRollbackCapsulesSubkey,
                                            KEY_WOW64_64KEY, 0);
    RegCloseKey(root);
    const LSTATUS top = RegDeleteKeyExW(HKEY_LOCAL_MACHINE,
        kWinCurRegistryPath, KEY_WOW64_64KEY, 0);
    if (child != ERROR_SUCCESS || parent != ERROR_SUCCESS ||
        top != ERROR_SUCCESS) {
        std::wcerr << L"Cleanup failure: child=" << child
                   << L" parent=" << parent << L" root=" << top << L"\n";
    }
    return child == ERROR_SUCCESS && parent == ERROR_SUCCESS && top == ERROR_SUCCESS;
}

class CleanupGuard final {
public:
    explicit CleanupGuard(const std::wstring& id) noexcept : id_(id) {}
    ~CleanupGuard() noexcept {
        if (active_ && !Cleanup(id_)) {
            std::wcerr << L"WARNING: exact test-namespace cleanup failed; restore snapshot.\n";
        }
    }
    void Activate() noexcept { active_ = true; }
    void Release() noexcept { active_ = false; }
private:
    const std::wstring& id_;
    bool active_{false};
};
}  // namespace

int wmain() {
    wchar_t opt_in[128]{};
    if (GetEnvironmentVariableW(L"WINCUR_RUN_CAPSULE_REGISTRY_TESTS", opt_in,
            static_cast<DWORD>(std::size(opt_in))) == 0 ||
        std::wstring_view(opt_in) != L"I_UNDERSTAND_DISPOSABLE_VM_ONLY") {
        std::wcerr << L"Refusing: set the disposable-VM opt-in variable.\n";
        return 2;
    }
    LSTATUS root_status = ERROR_SUCCESS;
    if (!TestRootAbsent(root_status)) {
        std::wcerr << L"Refusing: dedicated test namespace is present or could not "
                      L"be inspected.\n";
        return Fail(3, L"precondition.test-root-absent", root_status, root_status);
    }
    const auto generated = GenerateCanonicalTransactionUuid();
    if (generated.status != UuidGenerationStatus::Success ||
        !IsCanonicalTransactionUuid(generated.value)) {
        std::wcerr << L"UUID diagnostic: status="
                   << static_cast<unsigned int>(generated.status)
                   << L" hresult=0x" << std::hex
                   << static_cast<unsigned long>(generated.hresult) << std::dec
                   << L" formatted_characters=" << generated.formatted_characters
                   << L" value_length=" << generated.value.size() << L"\n";
        return Fail(4, L"transaction-id.generate-and-canonicalize",
                    static_cast<long>(generated.status));
    }
    const std::wstring& id = generated.value;
    const auto observed = CaptureWindowsPreChangeState(
        ActionId::DisableAutoRun, id, id, L"2026-11-03T00:00:00Z");
    if (!observed)
        return Fail(5, L"capture.autorun-pre-change", 0, GetLastError());
    CleanupGuard cleanup(id);
    cleanup.Activate();
    {
        WindowsCapsuleStorage storage;
        const CapsulePersistStatus persisted = PersistCapsule(storage, *observed);
        if (persisted != CapsulePersistStatus::Success)
            return Fail(6, L"capsule.persist", static_cast<long>(persisted),
                        GetLastError());
    }
    const auto read = ReadCapsuleFromRegistry(
        id, id, Operation::Apply, ActionId::DisableAutoRun);
    if (read.status != CapsuleRegistryReadStatus::Success || !read.capsule)
        return Fail(7, L"capsule.read-validate", static_cast<long>(read.status),
                    GetLastError());
    const auto intended = MakeIntendedPostChange(*read.capsule);
    if (!intended)
        return Fail(8, L"reconciliation.make-intended", -1);
    const ReconciliationClassification reconciliation =
        ReconcileState(*read.capsule, *read.capsule, *intended);
    if (reconciliation !=
        ReconciliationClassification::ManagedOrPolicyControlled)
        return Fail(8, L"reconciliation.fail-closed-policy-authority",
                    static_cast<long>(reconciliation));
    if (!Cleanup(id))
        return Fail(9, L"cleanup.exact-test-namespace", 0, GetLastError());
    cleanup.Release();
    std::wcout << L"Protected capsule storage and read-only reconciliation passed.\n";
    return 0;
}
